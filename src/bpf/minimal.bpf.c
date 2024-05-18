#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <unistd.h>
#include <sys/syscall.h>

char LICENSE[] SEC("license") = "GPL";

const volatile int my_pid = 0;

struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct sys_enter_context {
    struct trace_entry ent;
    long id;
    long unsigned args[6];
    char __data[0]
};

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_context *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;
    int tid = bpf_get_current_pid_tgid() & 0xffffffff;

    bpf_printk("BPF triggered from PID %d (%d) TID: %d syscall: %d (mypid: %d).\n", pid, tid, ctx->id, my_pid);

    if (pid != my_pid) {
        return 0;
    }

    return 0;
}