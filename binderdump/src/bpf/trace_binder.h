#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
    char __data[0];
};

struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    long id;
    long ret;
    char __data[0];
};

struct trace_event_raw_sched_process_template {
    struct trace_entry ent;
    char comm[16];
    pid_t pid;
    int prio;
    char __data[0];
};

struct trace_event_raw_binder_ioctl {
    struct trace_entry ent;
    unsigned int cmd;
    unsigned long arg;
    char __data[0];
};

struct trace_event_raw_binder_ioctl_done {
    struct trace_entry ent;
    int ret;
    char __data[0];
};

struct trace_event_raw_binder_lock_class {
    struct trace_entry ent;
    const char *tag;
    char __data[0];
};

struct trace_event_raw_binder_function_return_class {
    struct trace_entry ent;
    int ret;
    char __data[0];
};

struct trace_event_raw_binder_wait_for_work {
    struct trace_entry ent;
    bool proc_work;
    bool transaction_stack;
    bool thread_todo;
    char __data[0];
};

struct trace_event_raw_binder_transaction {
    struct trace_entry ent;
    int debug_id;
    int target_node;
    int to_proc;
    int to_thread;
    int reply;
    unsigned int code;
    unsigned int flags;
    char __data[0];
};

struct trace_event_raw_binder_transaction_received {
    struct trace_entry ent;
    int debug_id;
    char __data[0];
};

struct trace_event_raw_binder_command {
    struct trace_entry ent;
    uint32_t cmd;
    char __data[0];
};

struct trace_event_raw_binder_return {
    struct trace_entry ent;
    uint32_t cmd;
    char __data[0];
};

/*
struct trace_event_raw_binder_transaction_node_to_ref {
        struct trace_entry ent;
        int debug_id;
        int node_debug_id;
        binder_uintptr_t node_ptr;
        int ref_debug_id;
        uint32_t ref_desc;
        char __data[0];
};

struct trace_event_raw_binder_transaction_ref_to_node {
        struct trace_entry ent;
        int debug_id;
        int ref_debug_id;
        uint32_t ref_desc;
        int node_debug_id;
        binder_uintptr_t node_ptr;
        char __data[0];
};

struct trace_event_raw_binder_transaction_ref_to_ref {
        struct trace_entry ent;
        int debug_id;
        int node_debug_id;
        int src_ref_debug_id;
        uint32_t src_ref_desc;
        int dest_ref_debug_id;
        uint32_t dest_ref_desc;
        char __data[0];
};

struct trace_event_raw_binder_transaction_fd_send {
        struct trace_entry ent;
        int debug_id;
        int fd;
        size_t offset;
        char __data[0];
};

struct trace_event_raw_binder_transaction_fd_recv {
        struct trace_entry ent;
        int debug_id;
        int fd;
        size_t offset;
        char __data[0];
};
*/
