#include <linux/types.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <linux/android/binder.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define DEBUG
#include "common_types.h"
#include "log.h"
#include "maps.h"
#include "process_state.h"
#include "trace_binder.h"
#include "utils.h"

// We send chunks of size 32KB, this lets us send up to 1MB transactions, which is the maximum size
// Android mmaps the binder driver and therefore the maximum size of a binder transaction.
// I never saw a transaction with offsets_size > 32KB (which makes sense, parcels don't tend to have
// so many nested fields), so we only handle data_size > 32KB.
#define MAX_TRANSACTION_CHUNKS 32

// Maximum number of objects in a transaction's offsets array we'll walk to look for
// BINDER_TYPE_PTR scatter-gather buffers. Most transactions have far fewer than this;
// the cap keeps the BPF verifier happy and prevents pathological loops.
#define MAX_PTR_OBJECTS 32
// Maximum bytes of a single BINDER_TYPE_PTR scatter-gather buffer we copy up per chunk.
// Anything larger gets truncated; the userspace `total_size` field still records the
// real length so the user knows.
#define MAX_PTR_PAYLOAD 16384

#ifndef SYS_compat_ioctl
#define SYS_compat_ioctl 54
#endif
#define compat_user_mode(pstate)                                                                   \
    (((pstate) & (PSR_MODE32_BIT | PSR_MODE_MASK)) == (PSR_MODE32_BIT | PSR_MODE_EL0t))

int32_t g_loader_pid = 0;

int check_is_compat(struct bpf_raw_tracepoint_args *ctx) {
    struct my_pt_regs *regs_ptr = (struct my_pt_regs *)ctx->args[0];
    __u64 pstate;
    uint32_t map_key = 0;
    pid_t tid = GET_TID();
    int *in_compat = bpf_map_lookup_elem(&in_compat_syscall_map, &map_key);

    if (!in_compat) {
        LOG("raw_sys_enter: failed to lookup in_compat");
        return 0;
    }

    if (tid == g_loader_pid) {
        return 0;
    }

    if (bpf_probe_read(&pstate, sizeof(pstate), &regs_ptr->user_regs.pstate)) {
        LOG("raw_sys_enter: failed to read regs");
        return 0;
    }

    if compat_user_mode (pstate) {
        *in_compat = 1;
    } else {
        *in_compat = 0;
    }
    return 0;
}

SEC("raw_tp/sys_enter")
int sys_enter_check_compat(struct bpf_raw_tracepoint_args *ctx) { return check_is_compat(ctx); }

// we need this also on sys_exit if we started tracing a process blocked in binder_read
SEC("raw_tp/sys_exit")
int sys_exit_check_compat(struct bpf_raw_tracepoint_args *ctx) { return check_is_compat(ctx); }

int get_is_compat() {
    uint32_t map_key = 0;
    int *in_compat = bpf_map_lookup_elem(&in_compat_syscall_map, &map_key);
    if (!in_compat) {
        LOG("get_is_compat: failed to lookup in_compat");
        return -1;
    }
    return *in_compat;
}

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx) {
    pid_t tid = GET_TID();
    int is_compat = get_is_compat();
    if (is_compat < 0) {
        return 0;
    }
    long ioctl_syscall = (is_compat) ? SYS_compat_ioctl : SYS_ioctl;
    if (ctx->id == ioctl_syscall && tid != g_loader_pid) {
        struct ioctl_context ioctl_ctx = {.fd = ctx->args[0], .is_compat = is_compat};
        if (bpf_map_update_elem(&ioctl_context_map, &tid, &ioctl_ctx, BPF_ANY)) {
            LOG("ioctl: invalid state for %d", tid);
        };
    }
    return 0;
}

#ifdef __aarch64__
int __noinline do_bc_br_transaction(pid_t pid, pid_t tid, char log_char,
                                    struct transaction_command *command);

int handle_binder_return_from_ioctl(pid_t tid, pid_t pid, struct binder_write_read *bwr,
                                    struct binder_reply_offsets *reply_offsets) {
    int ret = 1;
    uint32_t map_key = 0;

    if (!bwr || !reply_offsets) {
        LOG("br: invalid args");
        goto l_cleanup;
    }
    struct transaction_command *command =
        bpf_map_lookup_elem(&transaction_command_buffers, &map_key);
    if (!command) {
        LOG("br: failed to get transaction command buffer");
        goto l_cleanup;
    }
    // LOG("valid read_only ioctl, handling %d replies", reply_offsets->count);
    for (size_t i = 0; i < reply_offsets->count; i++) {
        if (i >= MAX_TRANSACTIONS_PER_REPLY) {
            // we already checked but make the verifier happy
            goto l_cleanup;
        }
        struct binder_reply_offset *reply = &reply_offsets->offsets[i];
        uint32_t cmd = reply->cmd;
        if (cmd == BR_TRANSACTION || cmd == BR_TRANSACTION_SEC_CTX || cmd == BR_REPLY) {
            if (bpf_probe_read_user(command, sizeof(*command),
                                    UNTAG(bwr->read_buffer + reply->offset))) {
                LOG("failed to read BC data %px (cmd: %d)", bwr->read_buffer + reply->offset, cmd);
                goto l_cleanup;
            }

            // LOG("b%c handling command from read_only ioctl: %x", log_char, command);
            if (do_bc_br_transaction(pid, tid, 'r', command) != 0) {
                LOG("br failed to handle transaction command");
                goto l_cleanup;
            }
        }
    }
    ret = 0;
l_cleanup:
    LOG_BWR_BUFFERS("handle_binder_return_from_ioctl: b%c delete element");
    bpf_map_delete_elem(&binder_write_read_buffers, &tid);
    return 0;
}

SEC("raw_tp/sys_exit")
int raw_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
    struct my_pt_regs *regs_ptr = (struct my_pt_regs *)ctx->args[0];
    __u32 regs_key = 0;
    // We use map here to take less stack space, as we are on the verge of exceeding our 512 byte
    // limit.
    struct my_pt_regs *regs = bpf_map_lookup_elem(&pt_regs_scratch, &regs_key);
    if (!regs) {
        return 0;
    }
    __u64 task_id = bpf_get_current_pid_tgid();
    pid_t pid = task_id >> 32;
    pid_t tid = task_id & 0xffffffff;
    if (tid == g_loader_pid) {
        return 0;
    }
    int is_compat = get_is_compat();
    if (is_compat < 0) {
        return 0;
    }
    __s32 ioctl_syscall = (is_compat) ? SYS_compat_ioctl : SYS_ioctl;

    if (bpf_probe_read(regs, sizeof(*regs), regs_ptr)) {
        LOG("raw_sys_exit: failed to read regs");
        return 0;
    }

    if (regs->syscallno == ioctl_syscall) {
        struct ioctl_context *ioctl_ctx = bpf_map_lookup_elem(&ioctl_context_map, &tid);
        if (!ioctl_ctx) {
            return 0;
        } else if (ioctl_ctx->fd == -2) {
            // we set fd to -2 to mark that we started processing this ioctl only from
            // binder_read we need to send the BINDER_IOCTL event for this ioctl

            ioctl_ctx->fd = regs->orig_x0;
            ioctl_ctx->cmd = (__u32)regs->user_regs.regs[1];
            ioctl_ctx->arg = regs->user_regs.regs[2];
            ioctl_ctx->is_compat = is_compat;

            struct binder_event *event = bpf_ringbuf_reserve(
                &binder_events_buffer,
                sizeof(struct binder_event) + sizeof(struct binder_event_ioctl), 0);
            if (!event) {
                LOG("binder_ioctl: failed to reserved event");
                send_invalidate(tid, pid);
                return 0;
            }
            event->type = BINDER_IOCTL;
            event->pid = pid;
            event->tid = tid;
            event->timestamp = bpf_ktime_get_boot_ns();

            struct binder_event_ioctl *ioctl_event = (struct binder_event_ioctl *)(event + 1);
            __u64 creds = bpf_get_current_uid_gid();

            ioctl_event->fd = ioctl_ctx->fd;
            bpf_get_current_comm(ioctl_event->comm, sizeof(ioctl_event->comm));
            ioctl_event->uid = creds & 0xffffffff;
            ioctl_event->gid = creds >> 32;
            ioctl_event->cmd = ioctl_ctx->cmd;
            ioctl_event->arg = ioctl_ctx->arg;
            ioctl_event->read_only = 1;
            ioctl_event->is_compat = ioctl_ctx->is_compat;
            // wait with sending the event until we do some sanity checks

            // now we need to send the BINDER_WRITE_READ event
            if (ioctl_ctx->cmd != BINDER_WRITE_READ) {
                // This shouldn't happen - we will only set fd to -2 for BINDER_WRITE_READ
                // ioctls inside
                LOG("read_only ioctl but cmd != BINDER_WRITE_READ");
                goto l_error;
            }
            struct binder_write_read bwr = {};
            if (bpf_probe_read_user(&bwr, sizeof(bwr), UNTAG(ioctl_ctx->arg))) {
                LOG("raw_sys_exit: failed to read BINDER_WRITE_READ arg from user addr: %px",
                    (const void *)ioctl_ctx->arg);
                goto l_error;
            }
            struct binder_reply_offsets *reply_offsets =
                bpf_map_lookup_elem(&binder_reply_offsets_map, &tid);
            if (!reply_offsets) {
                goto l_error;
            }
            // The ioctl is already done, so bwr contains the final read_consumed value
            size_t index = reply_offsets->count - 1;
            if (index >= MAX_TRANSACTIONS_PER_REPLY) {
                LOG("too many reply offsets: %d", reply_offsets->count);
                goto l_error;
            }
            struct binder_reply_offset *last_reply = &reply_offsets->offsets[index];
            size_t last_offset = last_reply->offset + sizeof(uint32_t) + _IOC_SIZE(last_reply->cmd);
            if (bwr.read_consumed != last_offset) {
                // we didn't read all the reply data yet
                LOG("read_consumed %llu != last reply offset %llu", bwr.read_consumed, last_offset);
                goto l_error;
            }

            // We checked that we are handling a BINDER_WRITE_READ ioctl, we were able to read
            // the bwr command from userspace, and we saw that read_consumed matches the last
            // reply offset, so we can now send the ioctl event.
            //
            // we force wakeup here so we can capture the process' cmdline and fds before it can
            // exit.
            bpf_ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);

            // now pass on the cmds we got from binder_return and binder_txn_received
            handle_binder_return_from_ioctl(tid, pid, &bwr, reply_offsets);

            return 0;
        l_error:
            bpf_map_delete_elem(&binder_write_read_buffers, &tid);
            LOG("discarding event");
            bpf_ringbuf_discard(event, 0);
        }
        // sys_exit tracepoint is running after us and will clear the ioctl context (in both
        // arm64 and x86)
    }
    return 0;
}
// TODO - x86
#endif

static __always_inline int do_binder_write_read(pid_t tid, pid_t pid,
                                                struct ioctl_context *ioctl_ctx, int is_done);

int is_binder_ioctl_cmd(unsigned int cmd) {
    switch (cmd) {
    case BINDER_WRITE_READ:
    case BINDER_SET_IDLE_TIMEOUT:
    case BINDER_SET_MAX_THREADS:
    case BINDER_SET_IDLE_PRIORITY:
    case BINDER_SET_CONTEXT_MGR:
    case BINDER_THREAD_EXIT:
    case BINDER_VERSION:
    case BINDER_GET_NODE_DEBUG_INFO:
    case BINDER_GET_NODE_INFO_FOR_REF:
    case BINDER_SET_CONTEXT_MGR_EXT:
    case BINDER_FREEZE:
    case BINDER_GET_FROZEN_INFO:
    case BINDER_ENABLE_ONEWAY_SPAM_DETECTION:
    case BINDER_GET_EXTENDED_ERROR:
        return 1;
    default:
        return 0;
    }
}

// NOTE - this must be defined after raw_sys_exit to keep the same ordering when loaded into the
// kernel
SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx) {
    // pid_t tid = GET_TID();
    __u64 task_id = bpf_get_current_pid_tgid();
    pid_t pid = task_id >> 32;
    pid_t tid = task_id & 0xffffffff;
    struct ioctl_context *ioctl_ctx = NULL;
    struct binder_event *event = NULL;
    binder_process_state_t *current_state = NULL;
    int is_compat = get_is_compat();
    if (is_compat < 0) {
        return 0;
    }
    long ioctl_syscall = (is_compat) ? SYS_compat_ioctl : SYS_ioctl;

    if (ctx->id != ioctl_syscall || tid == g_loader_pid) {
        return 0;
    }

    current_state = bpf_map_lookup_elem(&binder_process_state, &tid);
    if (!current_state) {
        return 0;
    }

    ioctl_ctx = bpf_map_lookup_elem(&ioctl_context_map, &tid);
    if (!ioctl_ctx || !is_binder_ioctl_cmd(ioctl_ctx->cmd)) {
        *current_state = BINDER_INVALID;
        return 0;
    }

    if (ioctl_ctx->cmd == BINDER_WRITE_READ && ioctl_ctx->fd >= 0) {
        if (do_binder_write_read(tid, pid, ioctl_ctx, 1)) {
            send_invalidate(tid, pid);
            return 0;
        }
    }

    event = bpf_ringbuf_reserve(
        &binder_events_buffer, sizeof(struct binder_event) + sizeof(struct binder_event_ioctl_done),
        0);
    if (!event) {
        LOG("binder_ioctl_done: failed to reserved event");
        return 0;
    }
    event->type = BINDER_IOCTL_DONE;
    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_boot_ns();
    struct binder_event_ioctl_done *ioctl_event = (struct binder_event_ioctl_done *)(event + 1);
    ioctl_event->ret = ioctl_ctx->ret;

    LOG_RINGBUF("submit %u %x", sizeof(*event) + sizeof(struct binder_event_ioctl_done),
                *(int *)event);
    bpf_ringbuf_submit(event, 0);

    LOG_TRANSITION("thread %d 9 -> 0", tid);
    *current_state = BINDER_INVALID;
    ioctl_ctx->fd = -1;
    ioctl_ctx->arg = 0;
    ioctl_ctx->cmd = 0;
    ioctl_ctx->ret = 0;

    return 0;
}

SEC("tp/sched/sched_process_exit")
int sched_process_exit(const struct trace_event_raw_sched_process_template *ctx) {
    pid_t tid = ctx->pid;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_map_lookup_elem(&binder_process_state, &tid)) {
        // LOG("binder task %d removed from map", tid);
        binder_process_state_t state = BINDER_INVALID;
        // bpf_map_delete_elem(&binder_process_state, &tid);
        bpf_map_update_elem(&binder_process_state, &tid, &state, BPF_ANY);
    }
    if (bpf_map_lookup_elem(&ioctl_context_map, &tid)) {
        // LOG("binder task %d removed from ioctl map", tid);
        struct ioctl_context ioctl_ctx = {.fd = -1};
        bpf_map_update_elem(&ioctl_context_map, &tid, &ioctl_ctx, BPF_ANY);
    }

    struct binder_event *event = bpf_ringbuf_reserve(&binder_events_buffer, sizeof(*event), 0);
    if (!event) {
        LOG("Failed to send process invalidate message");
        return 0;
    }
    event->type = BINDER_INVALIDATE_PROCESS;
    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_boot_ns();
    LOG_RINGBUF("submit %u %x", sizeof(*event), *(int *)event);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

int do_binder_write_read(pid_t tid, pid_t pid, struct ioctl_context *ioctl_ctx, int is_done) {
    struct write_read_buffer *buffer = NULL;
    __u32 key = 0;
    const void *addr = NULL;
    __u32 size = 0;
    __u32 original_size = 0;

    if (!ioctl_ctx) {
        return -1;
    }
    buffer = bpf_map_lookup_elem(&tmp_buffers, &key);
    if (!buffer) {
        LOG("bwr: no buffer");
        return -1;
    }

    if (bpf_probe_read_user(&buffer->bwr, sizeof(buffer->bwr), UNTAG(ioctl_ctx->arg))) {
        LOG("bwr: failed to read BINDER_WRITE_READ arg from user addr: %px (is_done %d)",
            (const void *)ioctl_ctx->arg, is_done);
        __builtin_memset(&buffer->bwr, 0, sizeof(buffer->bwr));
        return -1;
    }

    if (is_done) {
        size = (__u32)(*(volatile binder_size_t *)&buffer->bwr.bwr.read_consumed);
        addr = (const void *)buffer->bwr.bwr.read_buffer;
        buffer->event.type = BINDER_READ;
        LOG_BWR_BUFFERS("do_binder_write_read (is_done == 1) - delete elem");
        bpf_map_delete_elem(&binder_write_read_buffers, &tid);

    } else {
        size = (__u32)(*(volatile binder_size_t *)&buffer->bwr.bwr.write_size);
        addr = (const void *)buffer->bwr.bwr.write_buffer;
        buffer->event.type = BINDER_WRITE;

        LOG_BWR_BUFFERS("do_binder_write_read (is_done == 0) - update elem");
        if (bpf_map_update_elem(&binder_write_read_buffers, &tid, &buffer->bwr, BPF_NOEXIST)) {
            LOG("bwr: failed to save bwr buffer (is_done %d)", is_done);
            __builtin_memset(&buffer->bwr, 0, sizeof(buffer->bwr));
            return -1;
        }
    }

    original_size = size;
    // tell verifier size < sizeof(*buffer)
    size &= (sizeof(*buffer) - 1);
    if (size == 0) {
        if (original_size == 0) {
            goto l_send_event;
        }
        LOG("bwr: size: 0 original_size: %u (is_done %d)", original_size, is_done);
        return -1;
    }
    if (size > (__u32)(sizeof(*buffer) - offsetof(struct write_read_buffer, bwr.data))) {
        return -1;
    }

    // TODO - check addr != NULL?
    int _ret = bpf_probe_read_user(buffer->bwr.data, size, UNTAG(addr));
    if (_ret) {
        LOG("bwr: failed to read addr %px size: %u (is_done: %d)", addr, size, is_done);
        LOG("bwr: read error %d", _ret);
        return -1;
    }
l_send_event:
    buffer->event.pid = pid;
    buffer->event.tid = tid;
    buffer->event.timestamp = bpf_ktime_get_boot_ns();
    LOG_RINGBUF("output %u (%u + %u) %x",
                (__u32)offsetof(struct write_read_buffer, bwr.data) + size,
                (__u32)offsetof(struct write_read_buffer, bwr.data), size, *(int *)buffer);
    if (bpf_ringbuf_output(&binder_events_buffer, buffer,
                           (__u32)offsetof(struct write_read_buffer, bwr.data) + size, 0)) {
        LOG("bwr: failed to output write_read data (is_done: %d)", is_done);
        return -1;
    }
    return 0;
}

SEC("tp/binder/binder_ioctl")
int binder_ioctl(struct trace_event_raw_binder_ioctl *ctx) {
    __u64 task_id = bpf_get_current_pid_tgid();
    pid_t pid = task_id >> 32;
    pid_t tid = task_id & 0xffffffff;
    binder_process_state_t state = BINDER_IOCTL;
    struct ioctl_context *ioctl_ctx = NULL;

    LOG_TRANSITION("thread %d _ -> BINDER_IOCTL", tid);
    if (bpf_map_update_elem(&binder_process_state, &tid, &state, BPF_ANY)) {
        LOG("binder_ioctl: invalid binder state for task %d", tid);
        // TODO maybe remove from map?
        return 0;
    }

    ioctl_ctx = bpf_map_lookup_elem(&ioctl_context_map, &tid);
    if (!ioctl_ctx) {
        LOG("binder_ioctl: no fd?");
        return 0;
    }

    struct binder_event *event = bpf_ringbuf_reserve(
        &binder_events_buffer, sizeof(struct binder_event) + sizeof(struct binder_event_ioctl), 0);
    if (!event) {
        LOG("binder_ioctl: failed to reserved event");
        return 0;
    }
    event->type = BINDER_IOCTL;
    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_boot_ns();

    struct binder_event_ioctl *ioctl_event = (struct binder_event_ioctl *)(event + 1);
    __u64 creds = bpf_get_current_uid_gid();

    ioctl_event->fd = ioctl_ctx->fd;
    bpf_get_current_comm(ioctl_event->comm, sizeof(ioctl_event->comm));
    ioctl_event->uid = creds & 0xffffffff;
    ioctl_event->gid = creds >> 32;
    ioctl_event->cmd = ioctl_ctx->cmd = ctx->cmd;
    ioctl_event->arg = ioctl_ctx->arg = ctx->arg;
    ioctl_event->read_only = 0;
    ioctl_event->is_compat = ioctl_ctx->is_compat;
    // if this is the first event from that process, force wakeup so we can capture its cmdline
    // and fds before it can exit
    LOG_RINGBUF("submit %u %x", sizeof(struct binder_event) + sizeof(struct binder_event_ioctl),
                *(int *)event);
    bpf_ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);

    if (ctx->cmd != BINDER_WRITE_READ) {
        return 0;
    }

    if (do_binder_write_read(tid, pid, ioctl_ctx, 0)) {
        send_invalidate(tid, pid);
    }

    return 0;
}

int __noinline handle_transaction_chunk(__u64 chunk_size, __u64 addr,
                                        struct write_read_buffer *buffer, size_t chunk_index) {

    if (!buffer) {
        return -1;
    }
    if (chunk_size > (__u32)(sizeof(*buffer) - offsetof(struct write_read_buffer, bwr.data))) {
        return -1;
    }
    if (bpf_probe_read_user(buffer->bwr.data, chunk_size, (const void *)addr)) {
        LOG("failed to read txn data %u", chunk_size);
        return -1;
    }
    buffer->bwr.bwr.write_consumed = chunk_size;
    buffer->bwr.bwr.write_buffer = chunk_index + 1;

    LOG_RINGBUF("output: %u %x", (__u32)offsetof(struct write_read_buffer, bwr.data) + chunk_size,
                *(int *)buffer);
    if (bpf_ringbuf_output(&binder_events_buffer, buffer,
                           (__u32)offsetof(struct write_read_buffer, bwr.data) + chunk_size, 0)) {
        LOG("failed to output txn data");
        return -1;
    }
    return 0;
}

// Walk the transaction's offsets array (already copied into `offsets_buffer`),
// and for every BINDER_TYPE_PTR object, read its scatter-gather payload from
// the sender's address space and emit a BINDER_TXN_PTR_DATA event.
//
// `data_user` is the sender's VA of the transaction `data` buffer. `offsets_buffer`
// is a kernel-side copy of the offsets array (binder_size_t entries — u64 on 64-bit
// builds, u32 in 32-bit compat). We can't reuse the same scratch buffer the
// caller used for the offsets ringbuf event, so the caller passes us a separate
// scratch buffer for our own ringbuf submissions.
// Walker + emitter share state via a per-cpu map (`ptr_walk_state_map`) so
// neither subprog needs more than one or two args. Keeps both frames small
// enough to fit inside the 512-byte combined-stack budget.

static int __always_inline emit_one_ptr_payload(void) {
    __u32 key = 0;
    struct ptr_walk_state *st = bpf_map_lookup_elem(&ptr_walk_state_map, &key);
    struct write_read_buffer *out_buffer = bpf_map_lookup_elem(&ptr_payload_buffers, &key);
    if (!st || !out_buffer) {
        return -1;
    }
    __u32 to_read =
        st->cur_ptr_length > MAX_PTR_PAYLOAD ? MAX_PTR_PAYLOAD : (__u32)st->cur_ptr_length;
    if (to_read == 0) {
        return 0;
    }
    struct binder_event *ev_hdr = (struct binder_event *)out_buffer->_data;
    ev_hdr->type = BINDER_TXN_PTR_DATA;
    ev_hdr->pid = (pid_t)(st->task_id >> 32);
    ev_hdr->tid = (pid_t)(st->task_id & 0xffffffff);
    ev_hdr->timestamp = bpf_ktime_get_boot_ns();
    struct binder_event_txn_ptr_data *meta =
        (struct binder_event_txn_ptr_data *)(out_buffer->_data + sizeof(struct binder_event));
    meta->offset_index = st->cur_offset_index;
    meta->chunk_index = 0;
    meta->buffer_addr = st->cur_ptr_buffer_addr;
    meta->total_size = st->cur_ptr_length;
    meta->chunk_size = to_read;
    if (bpf_probe_read_user(meta->data, to_read, UNTAG(st->cur_ptr_buffer_addr))) {
        return -1;
    }
    bpf_ringbuf_output(
        &binder_events_buffer, out_buffer,
        sizeof(struct binder_event) + sizeof(struct binder_event_txn_ptr_data) + to_read, 0);
    return 0;
}

static int __always_inline emit_ptr_payloads(struct write_read_buffer *offsets_buf) {
    __u32 key = 0;
    struct ptr_walk_state *st = bpf_map_lookup_elem(&ptr_walk_state_map, &key);
    if (!offsets_buf || !st || st->offsets_size == 0) {
        return 0;
    }
    __u32 ptr_size = st->is_compat ? 4 : 8;
    __u32 entry_count = st->offsets_size / ptr_size;
    if (entry_count > MAX_PTR_OBJECTS) {
        entry_count = MAX_PTR_OBJECTS;
    }

    for (__u32 i = 0; i < MAX_PTR_OBJECTS; i++) {
        if (i >= entry_count) {
            break;
        }
        __u64 entry = 0;
        if (bpf_probe_read_kernel(&entry, ptr_size,
                                  (const __u8 *)offsets_buf->bwr.data + i * ptr_size)) {
            continue;
        }
        __u32 type_ = 0;
        if (bpf_probe_read_user(&type_, sizeof(type_),
                                (const void *)(uintptr_t)(st->data_user_addr + entry))) {
            continue;
        }
        if (type_ != BINDER_TYPE_PTR) {
            continue;
        }
        st->cur_ptr_buffer_addr = 0;
        st->cur_ptr_length = 0;
        if (bpf_probe_read_user(&st->cur_ptr_buffer_addr, ptr_size,
                                (const void *)(uintptr_t)(st->data_user_addr + entry + 8))) {
            continue;
        }
        if (bpf_probe_read_user(
                &st->cur_ptr_length, ptr_size,
                (const void *)(uintptr_t)(st->data_user_addr + entry + 8 + ptr_size))) {
            continue;
        }
        st->cur_offset_index = i;
        emit_one_ptr_payload();
    }
    return 0;
}

int __noinline do_bc_br_transaction(pid_t pid, pid_t tid, char log_char,
                                    struct transaction_command *command) {
    struct write_read_buffer *buffer = NULL;
    __u32 key = 0;
    __u64 data_size = 0;
    __u32 offsets_size = 0;
    if (!command) {
        return -1;
    }
    const void *addr = UNTAG(command->txn.data.ptr.buffer);

    buffer = bpf_map_lookup_elem(&tmp_buffers, &key);
    if (!buffer) {
        LOG("b%c: no buffer", log_char);
        goto l_error;
    }

    // we will abuse the same `write_read_buffer` struct to construct our event
    buffer->event.type = BINDER_TXN_DATA;
    buffer->event.pid = pid;
    buffer->event.tid = tid;
    buffer->event.timestamp = bpf_ktime_get_boot_ns();

    data_size = command->txn.data_size;
    offsets_size = command->txn.offsets_size;

    buffer->bwr.bwr = (struct binder_write_read){.write_size = data_size,
                                                 .write_consumed = 0,
                                                 .write_buffer = 0,
                                                 .read_size = offsets_size,
                                                 .read_consumed = 0,
                                                 .read_buffer = 0};

    for (size_t i = 0; i < MAX_TRANSACTION_CHUNKS && data_size > 0; i++) {
        __u64 chunk_size = data_size;
        if (chunk_size > (__u32)(sizeof(*buffer) - offsetof(struct write_read_buffer, bwr.data))) {
            chunk_size = (__u32)(sizeof(*buffer) - offsetof(struct write_read_buffer, bwr.data));
        }
        if (handle_transaction_chunk(chunk_size, (__u64)addr, buffer, i) != 0) {
            goto l_error;
        }
        data_size -= chunk_size;
        addr += chunk_size;
    }

    if (data_size > 0) {
        LOG("b%c: failed to send all txn data, left %llu", log_char, data_size);
    }

    // if (data_size > (__u32)(sizeof(*buffer) - offsetof(struct write_read_buffer, bwr.data))) {
    //     LOG("b%c data too big: %u + %llu > %llu", log_char, data_size,
    //         offsetof(struct write_read_buffer, bwr.data), sizeof(*buffer));
    //     data_size = (__u32)(sizeof(*buffer) - offsetof(struct write_read_buffer, bwr.data));
    //     // goto l_error;
    // }

    // if (bpf_probe_read_user(buffer->bwr.data, data_size, addr)) {
    //     LOG("failed to read txn data %u, %lx", data_size, command->txn.data.ptr.buffer);
    //     goto l_error;
    // }

    // buffer->bwr.bwr.write_consumed = data_size;
    // buffer->bwr.bwr.write_buffer = 1;

    // LOG_RINGBUF("output: %u %x", (__u32)offsetof(struct write_read_buffer, bwr.data) + data_size,
    //             *(int *)buffer);
    // if (bpf_ringbuf_output(&binder_events_buffer, buffer,
    //                        (__u32)offsetof(struct write_read_buffer, bwr.data) + data_size, 0)) {
    //     LOG("failed to output txn data");
    //     goto l_error;
    // }
    // LOG("txn data: %llu/%llu", buffer->bwr.bwr.write_consumed, buffer->bwr.bwr.write_size);

    if (offsets_size == 0) {
        return 0;
    }

    if (offsets_size >
        (__u32)sizeof(*buffer) - (__u32)offsetof(struct write_read_buffer, bwr.data)) {
        LOG("offsets too big: %u + %llu > %llu", offsets_size,
            offsetof(struct write_read_buffer, bwr.data), sizeof(*buffer));
        goto l_error;
    }

    if (bpf_probe_read_user(buffer->bwr.data, offsets_size, UNTAG(command->txn.data.ptr.offsets))) {
        LOG("failed to read txn offsets %u, %llx", offsets_size, command->txn.data.ptr.offsets);
        goto l_error;
    }

    buffer->bwr.bwr.write_buffer = 0;
    buffer->bwr.bwr.read_buffer = 1;
    buffer->bwr.bwr.read_consumed = offsets_size;

    LOG_RINGBUF("output: %u %x", offsetof(struct write_read_buffer, bwr.data) + offsets_size,
                *(int *)buffer);
    if (bpf_ringbuf_output(&binder_events_buffer, buffer,
                           offsetof(struct write_read_buffer, bwr.data) + offsets_size, 0)) {
        LOG("failed to output txn offsets");
        goto l_error;
    }

    {
        struct ptr_walk_state *st = bpf_map_lookup_elem(&ptr_walk_state_map, &key);
        if (st) {
            st->task_id = ((__u64)pid << 32) | (__u32)tid;
            st->data_user_addr = (__u64)command->txn.data.ptr.buffer & 0xffffffffffffULL;
            st->offsets_size = offsets_size;
            struct ioctl_context *ic = bpf_map_lookup_elem(&ioctl_context_map, &tid);
            st->is_compat = ic ? ic->is_compat : 0;
            emit_ptr_payloads(buffer);
        }
    }

    return 0;
l_error:
    return -1;
}

int __always_inline do_bc_br(uint32_t cmd, const bool is_return) {
    __u64 task_id = bpf_get_current_pid_tgid();
    pid_t pid = task_id >> 32;
    pid_t tid = task_id & 0xffffffff;
    struct binder_write_read *bwr = NULL;
    struct binder_write_read empty_bwr;
    char log_char = is_return ? 'r' : 'c';
    size_t bytes_processed = sizeof(uint32_t) + _IOC_SIZE(cmd);
    uint32_t map_key = 0;
    __builtin_memset(&empty_bwr, 0, sizeof(empty_bwr));

    struct transaction_command *command =
        bpf_map_lookup_elem(&transaction_command_buffers, &map_key);
    if (!command) {
        LOG("b%c: failed to get transaction command buffer", log_char);
        goto l_error;
    }

    if (is_return) {
        if (do_transition(pid, tid, BINDER_RETURN)) {
            LOG("bad transition");
            goto l_error;
        }
    } else {
        if (do_transition(pid, tid, BINDER_COMMAND)) {
            LOG("bad transition");
            goto l_error;
        }
    }

    LOG_BWR_BUFFERS("do_bc_br: b%c lookup element", log_char);
    bwr = bpf_map_lookup_elem(&binder_write_read_buffers, &tid);
    if (!bwr) {
        if (is_return) {
            // We are starting to parse a BINDER_WRITE_READ call from the read side.
            // We will initialize an empty bwr and just record the offsets
            bwr = &empty_bwr;
            struct ioctl_context ioctl_ctx = {.fd = -2};
            if (bpf_map_update_elem(&ioctl_context_map, &tid, &ioctl_ctx, BPF_ANY)) {
                LOG("b%c: failed to mark ioctl read only context", log_char);
                return 0;
            }
        } else {
            return 0;
        }
    }
    if (is_return) {
        // account for BR_NOOP that is always added but never traced
        if (bwr->read_consumed == 0) {
            bwr->read_consumed += sizeof(uint32_t);
        }
        // BR_SPAWN_LOOPER actualy overwrites the first BR_NOOP.
        // If it exists it will be traced as the LAST return (see `binder_thread_read`),
        // so we can safely ignore it
        if (cmd == BR_SPAWN_LOOPER) {
            return 0;
        }

        if (!bwr->read_buffer) {
            struct binder_reply_offsets *reply_offsets =
                bpf_map_lookup_elem(&binder_reply_offsets_map, &tid);
            if (!reply_offsets) {
                reply_offsets = bpf_map_lookup_elem(&tmp_buffers, &map_key);
                if (!reply_offsets) {
                    LOG("b%c: failed to get empty reply offsets", log_char);
                    goto l_error;
                }
                reply_offsets->count = 0;
            }
            if (reply_offsets->count >= (uint8_t)MAX_TRANSACTIONS_PER_REPLY) {
                LOG("too many reply offsets: %u", reply_offsets->count);
                bpf_map_delete_elem(&binder_reply_offsets_map, &tid);
                goto l_error;
            }
            reply_offsets->offsets[reply_offsets->count].offset = bwr->read_consumed;
            reply_offsets->offsets[reply_offsets->count].cmd = cmd;
            reply_offsets->count++;
            bpf_map_update_elem(&binder_reply_offsets_map, &tid, reply_offsets, BPF_ANY);
            goto cleanup;
        }

        // TODO - support secctx?
        if (cmd == BR_TRANSACTION || cmd == BR_REPLY || cmd == BR_TRANSACTION_SEC_CTX) {

            if (bwr->read_buffer) {
                if (bpf_probe_read_user(command, sizeof(*command),
                                        UNTAG(bwr->read_buffer + bwr->read_consumed))) {
                    LOG("failed to read BR data %px (cmd: %d)",
                        bwr->read_buffer + bwr->read_consumed, cmd);
                    goto l_error;
                }
            }
        } else {
            goto cleanup;
        }
    } else if (cmd == BC_TRANSACTION || cmd == BC_REPLY || cmd == BC_TRANSACTION_SG ||
               cmd == BC_REPLY_SG) {
        // we don't care about the extra `buffers_size` field in `binder_transaction_data_sg`
        if (bpf_probe_read_user(command, sizeof(*command),
                                UNTAG(bwr->write_buffer + bwr->write_consumed))) {
            LOG("failed to read BC data %px", bwr->write_buffer + bwr->write_consumed);
            goto l_error;
        }
    } else {
        goto cleanup;
    }

    if (cmd != command->cmd) {
        LOG("b%c command mismatch: expected %u got %u", log_char, cmd, command->cmd);
        goto l_error;
    }

    if (do_bc_br_transaction(pid, tid, log_char, command) != 0) {
        LOG("b%c failed to handle transaction command", log_char);
        goto l_error;
    }
    // LOG("txn offsets: %llu/%llu", buffer->bwr.bwr.read_consumed, buffer->bwr.bwr.read_size);

cleanup:

    if (is_return) {
        bwr->read_consumed += bytes_processed;
    } else {
        bwr->write_consumed += bytes_processed;
    }
    LOG_BWR_BUFFERS("do_bc_br: b%c update element", log_char);
    bpf_map_update_elem(&binder_write_read_buffers, &tid, bwr, BPF_ANY);

    return 0;

l_error:
    LOG_BWR_BUFFERS("do_bc_br: b%c delete element", log_char);
    bpf_map_delete_elem(&binder_write_read_buffers, &tid);
    LOG("b%c error", log_char);
    return 0;
}

SEC("tp/binder/binder_command")
int binder_command(struct trace_event_raw_binder_command *ctx) { return do_bc_br(ctx->cmd, 0); }

SEC("tp/binder/binder_return")
int binder_return(struct trace_event_raw_binder_return *ctx) { return do_bc_br(ctx->cmd, 1); }

// CO-RE-relocatable stubs for the three fields we touch. libbpf rewrites
// each access to the target kernel's offset at load time using BTF;
// other fields are intentionally omitted (libbpf matches by name).
struct binder_thread___local {
    struct binder_transaction___local *transaction_stack;
} __attribute__((preserve_access_index));

struct binder_transaction___local {
    int debug_id;
    struct binder_thread___local *to_thread;
} __attribute__((preserve_access_index));

// Manual-offset values (set from userspace via --reply-offsets). When the
// manual program autoloads, these get patched into rodata before load.
// All three must be supplied together; zero is a valid debug_id offset
// so userspace, not BPF, enforces that.
// (Reachable only via raw_binder_transaction_manual, which userspace only
// autoloads after populating these via --reply-offsets.)
const volatile __u32 cfg_off_to_thread = 0;
const volatile __u32 cfg_off_transaction_stack = 0;
const volatile __u32 cfg_off_debug_id = 0;

// Shared submit path — debug_ids come from either branch. Inlined to
// avoid an extra BPF helper call on a hot path.
static __always_inline void submit_txn_stack(int request_debug_id, int reply_debug_id) {
    // debug_id is monotonic from 1 in the kernel; treat 0 as a failed read.
    if (request_debug_id == 0 || reply_debug_id == 0) {
        return;
    }

    __u64 task_id = bpf_get_current_pid_tgid();
    pid_t pid = task_id >> 32;
    pid_t tid = task_id & 0xffffffff;
    struct binder_event *event = NULL;
    struct binder_event_transaction_stack *txn_event = NULL;

    event = bpf_ringbuf_reserve(&binder_events_buffer, sizeof(*event) + sizeof(*txn_event), 0);
    if (!event) {
        LOG("Failed to reserved txn stack event");
        return;
    }
    event->type = BINDER_TXN_STACK;
    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_boot_ns();

    txn_event = (struct binder_event_transaction_stack *)(event + 1);
    txn_event->reply_debug_id = reply_debug_id;
    txn_event->request_debug_id = request_debug_id;

    LOG_RINGBUF("submit %u %x", sizeof(*event) + sizeof(*txn_event), *(int *)event);
    bpf_ringbuf_submit(event, 0);
}

// KEEP these two before binder_transaction tracepoint so they are executed first.
// At most one of these is autoloaded per capture session (userspace picks).
SEC("raw_tp/binder_transaction")
int raw_binder_transaction_core(struct bpf_raw_tracepoint_args *ctx) {
    if (!(int)ctx->args[0]) {
        return 0;
    }
    struct binder_transaction___local *transaction =
        (struct binder_transaction___local *)ctx->args[1];

    struct binder_thread___local *to_thread = BPF_CORE_READ(transaction, to_thread);
    if (!to_thread) {
        return 0;
    }
    struct binder_transaction___local *stack = BPF_CORE_READ(to_thread, transaction_stack);
    if (!stack) {
        return 0;
    }

    int request_debug_id = BPF_CORE_READ(stack, debug_id);
    int reply_debug_id = BPF_CORE_READ(transaction, debug_id);
    submit_txn_stack(request_debug_id, reply_debug_id);
    return 0;
}

SEC("raw_tp/binder_transaction")
int raw_binder_transaction_manual(struct bpf_raw_tracepoint_args *ctx) {
    if (!(int)ctx->args[0]) {
        return 0;
    }
    void *transaction_raw = (void *)ctx->args[1];

    void *to_thread_raw = NULL;
    void *stack_raw = NULL;
    int request_debug_id = 0;
    int reply_debug_id = 0;

    if (bpf_probe_read_kernel(&to_thread_raw, sizeof(to_thread_raw),
                              transaction_raw + cfg_off_to_thread)) {
        LOG("raw_binder_transaction: manual read of to_thread failed");
        return 0;
    }
    if (!to_thread_raw) {
        return 0;
    }
    if (bpf_probe_read_kernel(&stack_raw, sizeof(stack_raw),
                              to_thread_raw + cfg_off_transaction_stack)) {
        LOG("raw_binder_transaction: manual read of transaction_stack failed");
        return 0;
    }
    if (!stack_raw) {
        return 0;
    }
    if (bpf_probe_read_kernel(&request_debug_id, sizeof(request_debug_id),
                              stack_raw + cfg_off_debug_id)) {
        LOG("raw_binder_transaction: manual read of request debug_id failed");
        return 0;
    }
    if (bpf_probe_read_kernel(&reply_debug_id, sizeof(reply_debug_id),
                              transaction_raw + cfg_off_debug_id)) {
        LOG("raw_binder_transaction: manual read of reply debug_id failed");
        return 0;
    }
    submit_txn_stack(request_debug_id, reply_debug_id);
    return 0;
}

SEC("tp/binder/binder_transaction")
int binder_transaction(struct trace_event_raw_binder_transaction *ctx) {
    __u64 task_id = bpf_get_current_pid_tgid();
    pid_t pid = task_id >> 32;
    pid_t tid = task_id & 0xffffffff;
    struct binder_event *event = NULL;
    struct binder_event_transaction *txn_event = NULL;
    if (do_transition(pid, tid, BINDER_TXN)) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&binder_events_buffer,
                                sizeof(*event) + sizeof(struct binder_event_transaction), 0);
    if (!event) {
        LOG("Failed to reserved txn event");
        return 0;
    }
    event->type = BINDER_TXN;
    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_boot_ns();

    txn_event = (struct binder_event_transaction *)(event + 1);
    txn_event->debug_id = ctx->debug_id;
    txn_event->target_node = ctx->target_node;
    txn_event->to_proc = ctx->to_proc;
    txn_event->to_thread = ctx->to_thread;
    txn_event->reply = ctx->reply;
    txn_event->code = ctx->code;
    txn_event->flags = ctx->flags;

    LOG_RINGBUF("submit %u %x", sizeof(*event) + sizeof(struct binder_event_transaction),
                *(int *)event);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tp/binder/binder_transaction_received")
int binder_transaction_received(struct trace_event_raw_binder_transaction_received *ctx) {

    __u64 task_id = bpf_get_current_pid_tgid();
    pid_t pid = task_id >> 32;
    pid_t tid = task_id & 0xffffffff;
    struct binder_event *event = NULL;
    struct binder_event_transaction_received *txn_event = NULL;
    if (do_transition(pid, tid, BINDER_TXN_RECEIVED)) {
        return 0;
    }

    event =
        bpf_ringbuf_reserve(&binder_events_buffer,
                            sizeof(*event) + sizeof(struct binder_event_transaction_received), 0);
    if (!event) {
        LOG("Failed to reserved txn event");
        return 0;
    }
    event->type = BINDER_TXN_RECEIVED;
    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_boot_ns();

    txn_event = (struct binder_event_transaction_received *)(event + 1);
    txn_event->debug_id = ctx->debug_id;

    LOG_RINGBUF("submit %u %x", sizeof(*event) + sizeof(struct binder_event_transaction_received),
                *(int *)event);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tp/binder/binder_write_done")
int binder_write_done(void *ctx) {
    pid_t tid = GET_TID();
    pid_t pid = GET_PID();
    do_transition(pid, tid, BINDER_WRITE_DONE);
    return 0;
}

SEC("tp/binder/binder_wait_for_work")
int binder_wait_for_work(void *ctx) {
    pid_t tid = GET_TID();
    pid_t pid = GET_PID();
    do_transition(pid, tid, BINDER_WAIT_FOR_WORK);
    return 0;
}

SEC("tp/binder/binder_read_done")
int binder_read_done(void *ctx) {
    pid_t tid = GET_TID();
    pid_t pid = GET_PID();
    do_transition(pid, tid, BINDER_READ_DONE);
    return 0;
}

SEC("tp/binder/binder_ioctl_done")
int binder_ioctl_done(struct trace_event_raw_binder_ioctl_done *ctx) {
    pid_t tid = GET_TID();
    pid_t pid = GET_PID();
    struct ioctl_context *ioctl_ctx = NULL;

    if (do_transition(pid, tid, BINDER_IOCTL_DONE)) {
        return 0;
    }

    ioctl_ctx = bpf_map_lookup_elem(&ioctl_context_map, &tid);
    if (!ioctl_ctx) {
        LOG("binder_ioctl_done: no fd?");
        return 0;
    }
    ioctl_ctx->ret = ctx->ret;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
