// common structures for userspace and ebpf
#include <sys/types.h>
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

    BINDER_STATE_MAX
} binder_process_state_t;

struct binder_event {
    binder_process_state_t type;
    pid_t tid;
    // CLOCK_BOOTTIME at time of event capture
    // this requires kernel >=5.8, but so does ring buffer
    __u64 timestamp;
    char data[];
};

struct binder_event_ioctl {
    int fd;
    unsigned int cmd;
    unsigned long arg;
};
