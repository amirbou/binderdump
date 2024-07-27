// common structures for userspace and ebpf

#include <sys/types.h>
// make clang-format not reorder
#include <linux/android/binder.h>
#include <linux/types.h>

typedef enum {
    BINDER_INVALID = 0,
    BINDER_IOCTL,
    BINDER_COMMAND,
    BINDER_TXN,
    BINDER_WRITE_DONE,
    BINDER_WAIT_FOR_WORK,
    BINDER_RETURN,
    BINDER_READ_DONE,
    BINDER_TXN_RECEIVED,
    BINDER_IOCTL_DONE,

    BINDER_STATE_MAX,
    // psuedo state sent from sched_process_exit to invalidate the ProcessCache entry
    BINDER_INVALIDATE_PROCESS = BINDER_STATE_MAX,
    BINDER_WRITE,    // gets sent after BINDER_IOCTL message, iff cmd was BINDER_WRITE_READ
    BINDER_READ,     // gets sent before BINDER_IOCTL_DONE message, iff cmd was BINDER_WRITE_READ
    BINDER_TXN_DATA, // gets sent when BC_TRANSACTION, BC_TRANSACTION_SG, BC_REPLY or BC_REPLY_SG
                     // is sent, or when BR_TRANSACTION, BR_TRANSACTION_SECCTX or BR_REPLY is
                     // received
} binder_process_state_t;

// header before every message
struct binder_event {
    binder_process_state_t type;
    pid_t pid;
    pid_t tid;
    // CLOCK_BOOTTIME at time of event capture
    // this requires kernel >=5.8, but so does ring buffer
    __u64 timestamp;
};

// BINDER_IOCTL message
struct binder_event_ioctl {
    // this is the first message to userspace about this ioctl,
    // so we send all metadata here, once.
    int fd;
    char comm[16];
    uid_t uid;
    uid_t gid;
    unsigned int cmd;
    unsigned long arg;
};

// BINDER_IOCTL_DONE message
struct binder_event_ioctl_done {
    int ret;
};

// BINDER_WRITE or BINDER_READ message
struct binder_event_write_read {
    struct binder_write_read bwr;
    char data[];
};

struct binder_event_transaction {
    int debug_id;
    int target_node;
    int to_proc;
    int to_thread;
    int reply;
    unsigned int code;
    unsigned int flags;
};

struct binder_event_transaction_received {
    int debug_id;
};
