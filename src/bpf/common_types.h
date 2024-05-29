// common structures for userspace and ebpf
#include <linux/types.h>
#include <sys/types.h>

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
    BINDER_IOCTL_WRITE_READ,
} binder_process_state_t;

struct binder_event {
    binder_process_state_t type;
    pid_t pid;
    pid_t tid;
    // CLOCK_BOOTTIME at time of event capture
    // this requires kernel >=5.8, but so does ring buffer
    __u64 timestamp;
};

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
