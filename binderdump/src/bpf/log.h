#pragma once
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#ifdef DEBUG
#define LOG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define LOG(...)
#endif

#ifdef DEBUG_TRANSITION
#define LOG_TRANSITION(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define LOG_TRANSITION(...)
#endif

// #define DEBUG_RINGBUF
#ifdef DEBUG_RINGBUF
#define LOG_RINGBUF(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define LOG_RINGBUF(...)
#endif

// #define DEBUG_BWR_BUFFERS
#ifdef DEBUG_BWR_BUFFERS
#define LOG_BWR_BUFFERS(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define LOG_BWR_BUFFERS(...)
#endif
