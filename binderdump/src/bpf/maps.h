#pragma once
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <stdint.h>

#include "common_types.h"
#include "trace_binder.h"
#include "utils.h"

// Ring buffer for sending binder events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SZ_64M);
} binder_events_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, int);
} in_compat_syscall_map SEC(".maps");

// Map of tid to binder_process_state_t
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PID_MAX);
    __type(key, pid_t);
    __type(value, binder_process_state_t);
} binder_process_state SEC(".maps");

// Map of tid to ioctl context
struct ioctl_context {
    int fd;
    unsigned int cmd;
    unsigned long arg;
    int ret;
    int is_compat;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PID_MAX);
    __type(key, pid_t);
    __type(value, struct ioctl_context);
} ioctl_context_map SEC(".maps");

// Temporary buffer for reading/writing binder_write_read data
struct write_read_buffer {
    union {
        struct {
            struct binder_event event;
            struct binder_event_write_read bwr;
        };
        char _data[SZ_32K];
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct write_read_buffer);
} tmp_buffers SEC(".maps");

// Separate scratch buffer used by emit_ptr_payloads when we walk the offsets
// array and ship BINDER_TYPE_PTR scatter-gather payloads up to userspace.
// Aliasing tmp_buffers would corrupt the offsets bytes mid-walk.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct write_read_buffer);
} ptr_payload_buffers SEC(".maps");

// Per-cpu state for the offsets-array walker. Stashing args here keeps the
// emit_ptr_payloads / emit_one_ptr_payload subprog frames small enough to fit
// the BPF 512-byte combined-stack budget across the call chain.
struct ptr_walk_state {
    __u64 task_id;
    __u64 data_user_addr;
    __u32 offsets_size;
    // per-iteration scratch — populated by the walker, consumed by emit_one_ptr_payload
    __u32 cur_offset_index;
    __u64 cur_ptr_buffer_addr;
    __u64 cur_ptr_length;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ptr_walk_state);
} ptr_walk_state_map SEC(".maps");

// Per-cpu scratch for raw_sys_exit's struct my_pt_regs read. Keeping the
// ~280-byte regs blob off the BPF stack frees enough budget for the PTR-walk
// subprogs further down the call chain.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct my_pt_regs);
} pt_regs_scratch SEC(".maps");

// Map of tid to binder_write_read buffers
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PID_MAX);
    __type(key, pid_t);
    __type(value, struct binder_write_read);
} binder_write_read_buffers SEC(".maps");

// max number of BR_TRANSACTION, BR_REPLY or BR_TRANSACTION_SEC_CTX
// returns we expect to get in a single BINDER_WRITE_READ ioctls
#define MAX_TRANSACTIONS_PER_REPLY 64

// This is used for replies where we only trace from BINDER_TXN_RECEIVED / BINDER_RETURN
struct binder_reply_offsets {
    uint8_t count;
    struct binder_reply_offset {
        binder_size_t offset;
        uint32_t cmd;
    } offsets[MAX_TRANSACTIONS_PER_REPLY];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PID_MAX);
    __type(key, pid_t);
    __type(value, struct binder_reply_offsets);
} binder_reply_offsets_map SEC(".maps");

struct transaction_command {
    uint32_t cmd;
    struct binder_transaction_data txn;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct transaction_command);
} transaction_command_buffers SEC(".maps");
