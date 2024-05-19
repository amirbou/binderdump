#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <unistd.h>
#include <sys/syscall.h>

char LICENSE[] SEC("license") = "GPL";

const volatile int my_pid = 0;
const volatile unsigned long long my_dev = 0;
const volatile unsigned long long my_ino = 0;
const volatile int check_ns = 0;

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
    struct bpf_pidns_info nsdata = {};
    int pid = bpf_get_current_pid_tgid() >> 32;
    int tid = bpf_get_current_pid_tgid() & 0xffffffff;

    if (check_ns && 0 != bpf_get_ns_current_pid_tgid(my_dev, my_ino, &nsdata, sizeof(nsdata))) {
        return 0;
    } else {
        nsdata.tgid = pid;
    }
    if (nsdata.tgid != my_pid) {
        return 0;
    }
    bpf_printk("BPF triggered from PID %d (global PID %d) syscall: %d.\n", my_pid, pid, ctx->id);
    return 0;
}