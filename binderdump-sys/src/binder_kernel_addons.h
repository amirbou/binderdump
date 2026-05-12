// Constants added to the kernel binder ABI after the NDK sysroot snapshot
// shipped with our toolchain. Defined here so bindgen picks them up; values
// are taken verbatim from linux/include/uapi/linux/android/binder.h on
// torvalds master.

#pragma once
#include <linux/android/binder.h>

// BR constants: added to enum binder_driver_return_protocol (kernel 6.x).
// _IO('r', N) packs as ((0x72) << 8) | (N & 0xff).
#define BR_TRANSACTION_PENDING_FROZEN 0x7214
#define BR_FROZEN_BINDER 0x7215
#define BR_CLEAR_FREEZE_NOTIFICATION_DONE 0x7216

// BC constants: added to enum binder_driver_command_protocol (kernel 6.x).
// _IOW('c', N, struct binder_handle_cookie) with sizeof(binder_handle_cookie) = 12.
// Computed as _IOC(_IOC_WRITE, 'c', nr, 12) = (1 << 30) | (12 << 16) | ('c' << 8) | nr.
#define BC_FREEZE_NOTIFICATION_DONE 1074553618
#define BC_REQUEST_FREEZE_NOTIFICATION 1074553619
#define BC_CLEAR_FREEZE_NOTIFICATION 1074553620
