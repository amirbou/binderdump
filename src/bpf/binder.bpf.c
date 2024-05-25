#include "common_types.h"
#include "trace_binder.h"
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 0x2000);
    __type(key, pid_t);
    __type(value, binder_process_state_t);
} binder_process_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 0x2000);
    __type(key, pid_t);
    __type(value, int);
} ioctl_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 0x100 * 0x1000 /* 1MB */);
} binder_events_buffer SEC(".maps");

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

static __always_inline int do_transition(pid_t pid, binder_process_state_t to) {
    binder_process_state_t *from = bpf_map_lookup_elem(&binder_process_state, &pid);
    if (!from) {
        bpf_printk("failed transition of proc %d to state %d: no such process\n", pid, to);
        return -1;
    }
    if (!is_valid_transition(*from, to)) {
        bpf_printk("transition of proc %d from state %d to %d is invalid\n", pid, *from, to);
        return -1;
    }
    if (bpf_map_update_elem(&binder_process_state, &pid, &to, BPF_EXIST)) {
        bpf_printk("failed to update state of proc %d %d -> %d\n", pid, *from, to);
        return -1;
    }
    bpf_printk("proc %d %d -> %d\n", pid, *from, to);
    return 0;
}

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (ctx->id == SYS_ioctl) {
        int fd = ctx->args[0];
        if (bpf_map_update_elem(&ioctl_fd, &pid, &fd, BPF_NOEXIST)) {
            bpf_printk("ioctl: invalid state for %d", pid);
        };
    }
    return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (ctx->id == SYS_ioctl) {
        bpf_map_delete_elem(&ioctl_fd, &pid);
    }
    return 0;
}

SEC("tp/sched/sched_process_exit")
int sched_process_exit(const struct trace_event_raw_sched_process_template *ctx) {
    pid_t pid = ctx->pid;
    if (bpf_map_lookup_elem(&binder_process_state, &pid)) {
        bpf_printk("binder task %d removed from map\n", pid);
        bpf_map_delete_elem(&binder_process_state, &pid);
    }
    if (bpf_map_lookup_elem(&ioctl_fd, &pid)) {
        bpf_printk("binder task %d removed from ioctl map\n", pid);
        bpf_map_delete_elem(&ioctl_fd, &pid);
    }

    return 0;
}

SEC("tp/binder/binder_ioctl")
int binder_ioctl(struct trace_event_raw_binder_ioctl *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    binder_process_state_t state = BINDER_IOCTL;
    int *fd = NULL;

    if (bpf_map_update_elem(&binder_process_state, &pid, &state, BPF_NOEXIST)) {
        bpf_printk("binder_ioctl: invalid binder state for task %d\n", pid);
        // TODO maybe remove from map?
        return 0;
    }

    fd = bpf_map_lookup_elem(&ioctl_fd, &pid);
    if (!fd) {
        bpf_printk("binder_ioctl: no fd?\n");
        return 0;
    }

    struct binder_event *event = bpf_ringbuf_reserve(
        &binder_events_buffer, sizeof(struct binder_event) + sizeof(struct binder_event_ioctl), 0);
    if (!event) {
        bpf_printk("binder_ioctl: failed to reserved event\n");
        return 0;
    }
    event->type = BINDER_IOCTL;
    event->tid = pid;
    event->timestamp = bpf_ktime_get_boot_ns();

    struct binder_event_ioctl *ioctl_event = (struct binder_event_ioctl *)event->data;
    ioctl_event->fd = *fd;
    ioctl_event->cmd = ctx->cmd;
    ioctl_event->arg = ctx->arg;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tp/binder/binder_command")
int binder_command(struct trace_event_raw_binder_command *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    do_transition(pid, BINDER_COMMAND);
    return 0;
}

SEC("tp/binder/binder_transaction")
int binder_transaction(struct trace_event_raw_binder_transaction *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    do_transition(pid, BINDER_TXN);
    return 0;
}

SEC("tp/binder/binder_transaction_received")
int binder_transaction_received(struct trace_event_raw_binder_transaction_received *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    do_transition(pid, BINDER_TXN_RECEIVED);
    return 0;
}

SEC("tp/binder/binder_write_done")
int binder_write_done(struct trace_event_raw_binder_write_done *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    do_transition(pid, BINDER_WRITE_DONE);
    return 0;
}

SEC("tp/binder/binder_wait_for_work")
int binder_wait_for_work(void *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    do_transition(pid, BINDER_WAIT_FOR_WORK);
    return 0;
}

SEC("tp/binder/binder_read_done")
int binder_read_done(struct trace_event_raw_binder_read_done *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    do_transition(pid, BINDER_READ_DONE);
    return 0;
}

SEC("tp/binder/binder_return")
int binder_return(void *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    do_transition(pid, BINDER_RETURN);
    return 0;
}

SEC("tp/binder/binder_ioctl_done")
int binder_ioctl_done(void *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (!do_transition(pid, BINDER_IOCTL_DONE)) {
        bpf_printk("removing %d\n", pid);
        bpf_map_delete_elem(&binder_process_state, &pid);
    }
    return 0;
}
