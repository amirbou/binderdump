#include "common_types.h"
#include "trace_binder.h"
#include <bpf/bpf_helpers.h>
#include <linux/android/binder.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

char LICENSE[] SEC("license") = "GPL";
#define DEBUG
#ifdef DEBUG
#define LOG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#define GET_TID() (bpf_get_current_pid_tgid() & 0xffffffff)

// Default value in Android
#define PID_MAX 32768

// https://github.com/iovisor/bcc/issues/2519#issuecomment-534359316
#define SZ_16K 0x00004000
#define SZ_32K 0x00008000
#define SZ_64M 0x04000000

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PID_MAX);
    __type(key, pid_t);
    __type(value, binder_process_state_t);
} binder_process_state SEC(".maps");

struct ioctl_context {
    int fd;
    unsigned int cmd;
    unsigned long arg;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PID_MAX);
    __type(key, pid_t);
    __type(value, struct ioctl_context);
} ioctl_context_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SZ_64M);
} binder_events_buffer SEC(".maps");

struct write_read_buffer {
    union {
        struct {
            struct binder_event event;
            struct binder_event_write_read bwr;
            char data[];
        };
        char _reserved[SZ_32K];
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct write_read_buffer);
} binder_write_read_buffers SEC(".maps");

static const binder_process_state_t g_valid_transitions[BINDER_STATE_MAX][BINDER_STATE_MAX] = {
    // starting state
    [BINDER_IOCTL] = {BINDER_INVALID},

    // binder commands are processed in a loop, that starts after IOCTL with
    // write_size > 0
    // so its possible for
    // BINDER_IOCTL -> BINDER_COMMAND // single command that isn't a
    // transaction
    // BINDER_IOCTL -> BINDER_COMMAND -> BINDER_COMMAND // two commands that
    // are not transactions
    // BINDER_IOCTL -> BINDER_COMMAND -> BINDER_TXN -> BINDER_COMMAND // two
    // commands, the first is a TXN
    [BINDER_COMMAND] = {BINDER_IOCTL, BINDER_COMMAND, BINDER_TXN},

    // a transaction is a special kind of command
    [BINDER_TXN] = {BINDER_COMMAND},

    // after the BINDER_COMMAND loop ends we get the BINDER_WRITE_DONE
    // event, so we might get
    // BINDER_COMMAND -> BINDER_WRITE_DONE
    // BINDER_COMMAND -> BINDER_TXN -> BINDER_WRITE_DONE
    [BINDER_WRITE_DONE] = {BINDER_TXN, BINDER_COMMAND},

    // binder wait_for_work is called at the start of binder_thread_read, so
    // we might get:
    // BINDER_IOCTL -> BINDER_WAIT_FOR_WORK // if write_size == 0 and
    // read_size > 0
    // BINDER_IOCTL -> ... -> BINDER_WRITE_DONE -> BINDER_WAIT_FOR_WORK //
    // if write_size > 0 and read_size > 0
    [BINDER_WAIT_FOR_WORK] = {BINDER_IOCTL, BINDER_WRITE_DONE},

    // binder_transaction_recieved is traced when the read loop encounters a
    // BR_TRANSACTION, so we might get:
    // BINDER_WAIT_FOR_WORK -> BINDER_TXN_RECEIVED
    // BINDER_WAIT_FOR_WORK -> BINDER_TXN_RECEIVED -> BINDER_RETURN ->
    // BINDER_TXN_RECEIVED
    // BINDER_WAIT_FOR_WORK -> BINDER_RETURN -> BINDER_TXN_RECEIVED
    [BINDER_TXN_RECEIVED] = {BINDER_WAIT_FOR_WORK, BINDER_RETURN},

    // binder_return is traced after the read loop handles a BR command, so
    // we might get:
    // BINDER_WAIT_FOR_WORK -> BINDER_RETURN
    // BINDER_WAIT_FOR_WORK -> BINDER_TXN_RECEIVED -> BINDER_RETURN
    // BINDER_WAIT_FOR_WORK -> BINDER_RETURN -> BINDER_RETURN
    [BINDER_RETURN] = {BINDER_WAIT_FOR_WORK, BINDER_TXN_RECEIVED, BINDER_RETURN},

    // binder_read_done is traced after `binder_thread_read` returns, so we
    // might get:
    // BINDER_WAIT_FOR_WORK -> BINDER_READ_DONE
    // BINDER_WAIT_FOR_WORK -> BINDER_RETURN -> BINDER_READ_DONE
    // BINDER_WAIT_FOR_WORK -> BINDER_TXN_RECEIVED -> BINDER_RETURN ->
    // BINDER_READ_DONE
    [BINDER_READ_DONE] = {BINDER_WAIT_FOR_WORK, BINDER_RETURN},

    // ioctl_done is traced at the end of `binder_ioctl`, so we might get:
    // BINDER_IOCTL -> BINDER_IOCTL_DONE
    // BINDER_IOCTL -> ... -> BINDER_WRITE_DONE -> BINDER_IOCTL_DONE
    // BINDER_IOCTL -> ... -> BINDER_READ_DONE -> BINDER_IOCTL_DONE
    [BINDER_IOCTL_DONE] = {BINDER_IOCTL, BINDER_WRITE_DONE, BINDER_READ_DONE}};

static __always_inline bool is_valid_transition(binder_process_state_t from,
                                                binder_process_state_t to) {
    // >= 5.3 supports loops
    // #pragma unroll
    for (size_t i = 0; i < BINDER_STATE_MAX; i++) {
        binder_process_state_t state = g_valid_transitions[to][i];
        if (state == from) {
            return true;
        }
        // we check the invalid state only once
        if (state == BINDER_INVALID) {
            break;
        }
    }
    return false;
}

static __always_inline int do_transition(pid_t tid, binder_process_state_t to) {
    struct binder_event *event = NULL;
    binder_process_state_t *from = bpf_map_lookup_elem(&binder_process_state, &tid);
    if (!from) {
        LOG("failed transition of thread %d to state %d: no such process\n", tid, to);
        // no need to send BINDER_INVALID message to userspace
        return -1;
    }
    if (!is_valid_transition(*from, to)) {
        LOG("transition of thread %d from state %d to %d is invalid\n", tid, *from, to);
        goto l_error;
    }
    if (bpf_map_update_elem(&binder_process_state, &tid, &to, BPF_ANY)) {
        LOG("failed to update state of thread %d %d -> %d\n", tid, *from, to);
        goto l_error;
    }
    // LOG("thread %d %d -> %d\n", tid, *from, to);
    return 0;

l_error:
    event = bpf_ringbuf_reserve(&binder_events_buffer, sizeof(struct binder_event), 0);
    if (!event) {
        LOG("do_transition: failed to reserved event\n");
        return -1;
    }
    event->type = BINDER_INVALID;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_boot_ns();

    bpf_ringbuf_submit(event, 0);
    return -1;
}

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx) {
    pid_t tid = GET_TID();
    if (ctx->id == SYS_ioctl) {
        struct ioctl_context ioctl_ctx = {.fd = ctx->args[0]};
        if (bpf_map_update_elem(&ioctl_context_map, &tid, &ioctl_ctx, BPF_ANY)) {
            LOG("ioctl: invalid state for %d", tid);
        };
    }
    return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx) {
    pid_t tid = GET_TID();
    if (ctx->id == SYS_ioctl) {
        struct ioctl_context ioctl_ctx = {.fd = -1};
        bpf_map_update_elem(&ioctl_context_map, &tid, &ioctl_ctx, BPF_ANY);
    }
    return 0;
}

SEC("tp/sched/sched_process_exit")
int sched_process_exit(const struct trace_event_raw_sched_process_template *ctx) {
    pid_t tid = ctx->pid;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_map_lookup_elem(&binder_process_state, &tid)) {
        LOG("binder task %d removed from map\n", tid);
        binder_process_state_t state = BINDER_INVALID;
        // bpf_map_delete_elem(&binder_process_state, &tid);
        bpf_map_update_elem(&binder_process_state, &tid, &state, BPF_ANY);
    }
    if (bpf_map_lookup_elem(&ioctl_context_map, &tid)) {
        LOG("binder task %d removed from ioctl map\n", tid);
        struct ioctl_context ioctl_ctx = {.fd = -1};
        bpf_map_update_elem(&ioctl_context_map, &tid, &ioctl_ctx, BPF_ANY);
    }

    struct binder_event *event = bpf_ringbuf_reserve(&binder_events_buffer, sizeof(*event), 0);
    if (!event) {
        LOG("Failed to send process invalidate message\n");
        return 0;
    }
    event->type = BINDER_INVALIDATE_PROCESS;
    event->pid = pid;
    event->tid = tid;
    event->timestamp = 0;
    bpf_ringbuf_submit(event, 0);

    return 0;
}

static __always_inline void send_invalidate(pid_t tid, pid_t pid) {
    struct binder_event invalidate = {};
    invalidate.type = BINDER_INVALID;
    invalidate.pid = pid;
    invalidate.tid = tid;

    if (bpf_ringbuf_output(&binder_events_buffer, &invalidate, sizeof(invalidate), 0)) {
        LOG("failed to invalidate ioctl\n");
    }
}

static __always_inline int do_binder_write_read(pid_t tid, pid_t pid,
                                                struct ioctl_context *ioctl_ctx, int is_done) {
    struct write_read_buffer *buffer = NULL;
    __u32 key = 0;
    const void *addr = NULL;
    __u32 size = 0;
    __u32 original_size = 0;

    buffer = bpf_map_lookup_elem(&binder_write_read_buffers, &key);
    if (!buffer) {
        LOG("bwr: no buffer\n");
        return -1;
    }

    if (bpf_probe_read_user(&buffer->bwr, sizeof(buffer->bwr), (const void *)ioctl_ctx->arg)) {
        LOG("bwr: failed to read BINDER_WRITE_READ arg from user addr: %p (is_done %d)\n",
            (const void *)ioctl_ctx->arg),
            is_done;
        __builtin_memset(&buffer->bwr, 0, sizeof(buffer->bwr));
        return -1;
    }

    if (is_done) {
        size = (__u32)(*(volatile binder_size_t *)&buffer->bwr.bwr.read_consumed);
        addr = (const void *)buffer->bwr.bwr.read_buffer;
        buffer->event.type = BINDER_READ;
    } else {
        size = (__u32)(*(volatile binder_size_t *)&buffer->bwr.bwr.write_size);
        addr = (const void *)buffer->bwr.bwr.write_buffer;
        buffer->event.type = BINDER_WRITE;
    }

    original_size = size;
    // tell verifier size < sizeof(*buffer)
    size &= (sizeof(*buffer) - 1);
    if (size == 0) {
        if (original_size == 0) {
            goto l_send_event;
        }
        LOG("bwr: size: 0 original_size: %u (is_done %d)\n", original_size, is_done);
        return -1;
    }
    if (size + offsetof(struct write_read_buffer, data) > sizeof(*buffer)) {
        return -1;
    }

    if (bpf_probe_read_user(buffer->data, size, addr)) {
        LOG("bwr: failed to read addr %p (is_done: %d)\n", addr, is_done);
        return -1;
    }
l_send_event:
    buffer->event.pid = pid;
    buffer->event.tid = tid;
    buffer->event.timestamp = bpf_ktime_get_boot_ns();
    if (bpf_ringbuf_output(&binder_events_buffer, buffer,
                           offsetof(struct write_read_buffer, data) + size, 0)) {
        LOG("bwr: failed to output write_read data (is_done: %d)\n", is_done);
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

    if (bpf_map_update_elem(&binder_process_state, &tid, &state, BPF_ANY)) {
        LOG("binder_ioctl: invalid binder state for task %d\n", tid);
        // TODO maybe remove from map?
        return 0;
    }

    ioctl_ctx = bpf_map_lookup_elem(&ioctl_context_map, &tid);
    if (!ioctl_ctx) {
        LOG("binder_ioctl: no fd?\n");
        return 0;
    }

    struct binder_event *event = bpf_ringbuf_reserve(
        &binder_events_buffer, sizeof(struct binder_event) + sizeof(struct binder_event_ioctl), 0);
    if (!event) {
        LOG("binder_ioctl: failed to reserved event\n");
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
    // if this is the first event from that process, force wakeup so we can capture its cmdline
    // and fds before it can exit
    bpf_ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);

    if (ctx->cmd != BINDER_WRITE_READ) {
        return 0;
    }

    if (do_binder_write_read(tid, pid, ioctl_ctx, 0)) {
        send_invalidate(tid, pid);
    }

    return 0;
}

SEC("tp/binder/binder_command")
int binder_command(struct trace_event_raw_binder_command *ctx) {
    pid_t tid = GET_TID();
    do_transition(tid, BINDER_COMMAND);
    return 0;
}

SEC("tp/binder/binder_transaction")
int binder_transaction(struct trace_event_raw_binder_transaction *ctx) {
    pid_t tid = GET_TID();
    do_transition(tid, BINDER_TXN);
    return 0;
}

SEC("tp/binder/binder_transaction_received")
int binder_transaction_received(struct trace_event_raw_binder_transaction_received *ctx) {
    pid_t tid = GET_TID();
    do_transition(tid, BINDER_TXN_RECEIVED);
    return 0;
}

SEC("tp/binder/binder_write_done")
int binder_write_done(struct trace_event_raw_binder_write_done *ctx) {
    pid_t tid = GET_TID();
    do_transition(tid, BINDER_WRITE_DONE);
    return 0;
}

SEC("tp/binder/binder_wait_for_work")
int binder_wait_for_work(void *ctx) {
    pid_t tid = GET_TID();
    do_transition(tid, BINDER_WAIT_FOR_WORK);
    return 0;
}

SEC("tp/binder/binder_read_done")
int binder_read_done(struct trace_event_raw_binder_read_done *ctx) {
    pid_t tid = GET_TID();
    do_transition(tid, BINDER_READ_DONE);
    return 0;
}

SEC("tp/binder/binder_return")
int binder_return(void *ctx) {
    pid_t tid = GET_TID();
    do_transition(tid, BINDER_RETURN);
    return 0;
}

SEC("tp/binder/binder_ioctl_done")
int binder_ioctl_done(struct trace_event_raw_binder_ioctl_done *ctx) {
    __u64 task_id = bpf_get_current_pid_tgid();
    pid_t pid = task_id >> 32;
    pid_t tid = task_id & 0xffffffff;
    struct ioctl_context *ioctl_ctx = NULL;
    struct binder_event *event = NULL;

    if (do_transition(tid, BINDER_IOCTL_DONE)) {
        return 0;
    }

    // LOG("removing %d\n", tid);
    binder_process_state_t state = BINDER_INVALID;
    bpf_map_update_elem(&binder_process_state, &tid, &state, BPF_ANY);

    ioctl_ctx = bpf_map_lookup_elem(&ioctl_context_map, &tid);
    if (!ioctl_ctx) {
        LOG("binder_ioctl_done: no fd?\n");
        return 0;
    }

    if (ioctl_ctx->cmd == BINDER_WRITE_READ) {
        if (do_binder_write_read(tid, pid, ioctl_ctx, 1)) {
            send_invalidate(tid, pid);
            return 0;
        }
    }

    event = bpf_ringbuf_reserve(
        &binder_events_buffer, sizeof(struct binder_event) + sizeof(struct binder_event_ioctl_done),
        0);
    if (!event) {
        LOG("binder_ioctl_done: failed to reserved event\n");
        return 0;
    }
    event->type = BINDER_IOCTL_DONE;
    event->pid = pid;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_boot_ns();
    struct binder_event_ioctl_done *ioctl_event = (struct binder_event_ioctl_done *)(event + 1);
    ioctl_event->ret = ctx->ret;

    bpf_ringbuf_submit(event, 0);
    return 0;
}
