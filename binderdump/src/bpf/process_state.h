#pragma once
#include "common_types.h"
#include "log.h"
#include "maps.h"

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
    __u64 index = to; // verifier workaround
    if (index >= (__u64)BINDER_STATE_MAX) {
        return false;
    }
    if (from == BINDER_INVALID) {
        if (to == BINDER_RETURN || to == BINDER_TXN_RECEIVED) {
            LOG_TRANSITION("starting to parse read only ioctl: %d", to);
        }
        return to == BINDER_IOCTL || to == BINDER_RETURN || to == BINDER_TXN_RECEIVED;
    }
    // >= 5.3 supports loops
    // #pragma unroll
    for (size_t i = 0; i < BINDER_STATE_MAX; i++) {
        binder_process_state_t state = g_valid_transitions[index][i];
        // we check the invalid state only once
        if (state == BINDER_INVALID /* && to != BINDER_IOCTL && to != */) {
            break;
        }
        if (state == from) {
            return true;
        }
    }
    return false;
}

static __always_inline binder_process_state_t *get_process_state(pid_t tid) {
    return (binder_process_state_t *)bpf_map_lookup_elem(&binder_process_state, &tid);
}

int __noinline do_transition(pid_t tid, binder_process_state_t to) {
    struct binder_event *event = NULL;
    binder_process_state_t *from = get_process_state(tid);
    if (!from) {
        LOG("failed transition of thread %d to state %d: no such process", tid, to);
        // no need to send BINDER_INVALID message to userspace
        return -1;
    }
    binder_process_state_t old_from = *from;
    if (!is_valid_transition(*from, to)) {
        // LOG("transition of thread %d from state %d to %d is invalid", tid, *from, to);
        goto l_error;
    }
    // if (bpf_map_update_elem(&binder_process_state, &tid, &to, BPF_ANY)) {
    //     LOG("failed to update state of thread %d %d -> %d", tid, *from, to);
    //     goto l_error;
    // }
    *from = to;
    LOG_TRANSITION("thread %d %d -> %d", tid, old_from, to);
    return 0;

l_error:
    event = (struct binder_event *)bpf_ringbuf_reserve(&binder_events_buffer,
                                                       sizeof(struct binder_event), 0);
    if (!event) {
        LOG("do_transition: failed to reserved event");
        return -1;
    }
    event->type = BINDER_INVALID;
    event->tid = tid;
    event->timestamp = bpf_ktime_get_boot_ns();

    LOG_RINGBUF("submit %u %x", sizeof(struct binder_event), *(int *)event);
    bpf_ringbuf_submit(event, 0);
    return -1;
}

__noinline int send_invalidate(pid_t tid, pid_t pid) {
    struct binder_event invalidate = {};
    invalidate.type = BINDER_INVALID;
    invalidate.pid = pid;
    invalidate.tid = tid;

    LOG_RINGBUF("output: %u %x", sizeof(invalidate), *(int *)&invalidate);
    if (bpf_ringbuf_output(&binder_events_buffer, &invalidate, sizeof(invalidate), 0)) {
        LOG("failed to invalidate ioctl");
    }
    return 0;
}
