#pragma once
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <inttypes.h>

#define GET_TID() (bpf_get_current_pid_tgid() & 0xffffffff)
#define GET_PID() (bpf_get_current_pid_tgid() >> 32)

#define UNTAG(addr) (const void *)((__u64)(addr) & 0xffffffffffff)

// Default value in Android
#define PID_MAX 32768

// https://github.com/iovisor/bcc/issues/2519#issuecomment-534359316
#define SZ_16K 0x00004000
#define SZ_32K 0x00008000
#define SZ_64M 0x04000000

#ifdef __aarch64__
struct my_pt_regs {
    struct user_pt_regs user_regs;
    __u64 orig_x0;
    __s32 syscallno;
};
#endif
