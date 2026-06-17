#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <stddef.h>

#define DEBUG
#include "log.h"
#include "trace_binder.h"

// Calibration program: derive binder struct offsets at runtime with no BTF.
// For every live binder_transaction we ship a window of the struct plus a
// window at each slot that looks like a kernel pointer (one deref level).
// We also ship the transaction's debug_id *value* (read from the structured
// tracepoint), so userspace can locate the debug_id field by searching the
// struct window for that exact value instead of guessing from monotonicity.
// Part of the binder offset-finder tool.

// 256 covers binder_transaction comfortably (it is well under this on 5.10/6.x).
#define FINDER_STRUCT_WIN 256
// 128 covers the front of binder_thread where transaction_stack lives.
#define FINDER_DEREF_WIN 128

#define FINDER_KIND_TXN 0
#define FINDER_KIND_DEREF 1

// arm64 ioctl syscall numbers (native + compat). The tool is arm64-only, so we
// reset the per-tid pairing slot at each ioctl boundary rather than tracking
// every syscall.
#define FINDER_NR_IOCTL 29
#define FINDER_NR_IOCTL_COMPAT 54

// Heuristic: on arm64 with 48-bit VA (Android 5.10/6.x), kernel addresses
// have the top 16 bits set (>= 0xffff000000000000). A 52-bit-VA kernel would
// need a different mask; out of scope.
#define IS_KERNEL_PTR(v) (((v) >> 48) == 0xffff)

// Count of records dropped because finder_events was full. Read by userspace
// after calibration so "too few samples" can be told apart from "ring overran".
__u64 g_ringbuf_drops = 0;

struct finder_txn {
    __u32 kind;
    __u32 reply;
    __u64 txn_ptr;
    __u32 debug_id;
    __u8 window[FINDER_STRUCT_WIN];
};

struct finder_deref {
    __u32 kind;
    __u32 src_off;
    __u64 txn_ptr;
    __u8 window[FINDER_DEREF_WIN];
};

// Per-tid pairing slot. The raw tracepoint supplies txn_ptr + the struct window;
// the structured tracepoint supplies the debug_id value. They fire on the same
// thread for the same event, in either order, so we stash each half here keyed
// by tid and emit once both are present.
struct finder_inflight {
    __u64 txn_ptr;
    __u32 reply;
    __u32 debug_id;
    __u8 have_transaction;
    __u8 have_debug_id;
    __u8 window[FINDER_STRUCT_WIN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16M
} finder_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct finder_txn);
} finder_txn_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct finder_deref);
} finder_deref_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct finder_inflight);
} finder_inflight_map SEC(".maps");

// zeroed template used to insert a fresh finder_inflight without a big stack init
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct finder_inflight);
} finder_inflight_template SEC(".maps");

static __always_inline struct finder_inflight *inflight_get(__u32 tid) {
    struct finder_inflight *st = bpf_map_lookup_elem(&finder_inflight_map, &tid);
    if (st) {
        return st;
    }
    __u32 z = 0;
    struct finder_inflight *tmpl = bpf_map_lookup_elem(&finder_inflight_template, &z);
    if (!tmpl) {
        return NULL;
    }
    bpf_map_update_elem(&finder_inflight_map, &tid, tmpl, BPF_NOEXIST);
    return bpf_map_lookup_elem(&finder_inflight_map, &tid);
}

// Ship one txn sample (struct window + debug_id value) plus a deref window for
// each kernel-pointer slot in the window. Inlined so it takes no pointer arg as
// a global subprog — the pre-5.13 verifier rejects those (see binder.bpf.c).
static __always_inline void finder_emit(struct finder_inflight *st) {
    __u32 key = 0;
    struct finder_txn *txn = bpf_map_lookup_elem(&finder_txn_scratch, &key);
    if (!txn) {
        return;
    }
    txn->kind = FINDER_KIND_TXN;
    txn->reply = st->reply;
    txn->txn_ptr = st->txn_ptr;
    txn->debug_id = st->debug_id;
    __builtin_memcpy(txn->window, st->window, FINDER_STRUCT_WIN);
    if (bpf_ringbuf_output(&finder_events, txn, sizeof(*txn), 0)) {
        __sync_fetch_and_add(&g_ringbuf_drops, 1);
    }

    struct finder_deref *de = bpf_map_lookup_elem(&finder_deref_scratch, &key);
    if (!de) {
        return;
    }
    // Constant trip count -> the compiler unrolls this, so every window read below
    // is at a constant offset (keeps the verifier happy, no variable map indexing).
#pragma unroll
    for (size_t off = 0; off + 8 <= FINDER_STRUCT_WIN; off += 8) {
        __u64 val = 0;
        __builtin_memcpy(&val, st->window + off, 8);
        if (!IS_KERNEL_PTR(val)) {
            continue;
        }
        de->kind = FINDER_KIND_DEREF;
        de->src_off = off;
        de->txn_ptr = st->txn_ptr;
        if (bpf_probe_read_kernel(de->window, FINDER_DEREF_WIN, (const void *)val)) {
            continue; // bad guess, skip
        }
        if (bpf_ringbuf_output(&finder_events, de, sizeof(*de), 0)) {
            __sync_fetch_and_add(&g_ringbuf_drops, 1);
        }
    }
}

// Reset the pairing slot at each ioctl boundary so a half-filled pair from a
// prior ioctl can't mis-pair with the next transaction.
SEC("raw_tp/sys_enter")
int finder_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    long id = (long)ctx->args[1];
    if (id != FINDER_NR_IOCTL && id != FINDER_NR_IOCTL_COMPAT) {
        return 0;
    }
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct finder_inflight *st = bpf_map_lookup_elem(&finder_inflight_map, &tid);
    if (st) {
        st->have_transaction = 0;
        st->have_debug_id = 0;
    }
    return 0;
}

SEC("raw_tp/binder_transaction")
int finder_raw_txn(struct bpf_raw_tracepoint_args *ctx) {
    __u64 txn = (__u64)ctx->args[1];
    if (!txn) {
        return 0;
    }
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct finder_inflight *st = inflight_get(tid);
    if (!st) {
        return 0;
    }
    if (bpf_probe_read_kernel(st->window, FINDER_STRUCT_WIN, (const void *)txn)) {
        LOG("finder: struct window read failed at %px", txn);
        return 0;
    }
    st->txn_ptr = txn;
    st->reply = (__u32)ctx->args[0];
    st->have_transaction = 1;
    if (st->have_debug_id) {
        finder_emit(st);
        st->have_transaction = 0;
        st->have_debug_id = 0;
    }
    return 0;
}

// Structured tracepoint: its ctx carries debug_id (the raw tp does not), read
// directly via the trace-event struct (same BTF-free pattern as binder.bpf.c).
SEC("tracepoint/binder/binder_transaction")
int finder_tp_txn(struct trace_event_raw_binder_transaction *ctx) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct finder_inflight *st = inflight_get(tid);
    if (!st) {
        return 0;
    }
    st->debug_id = ctx->debug_id;
    st->have_debug_id = 1;
    if (st->have_transaction) {
        finder_emit(st);
        st->have_transaction = 0;
        st->have_debug_id = 0;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
