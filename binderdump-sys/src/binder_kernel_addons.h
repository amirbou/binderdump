// Constants added to the kernel binder ABI after the NDK sysroot snapshot
// shipped with our toolchain. Defined here so bindgen picks them up; values
// are taken verbatim from linux/include/uapi/linux/android/binder.h on
// torvalds master.

#pragma once
#include <linux/android/binder.h>

// BR constants: added to enum binder_driver_return_protocol (kernel 6.x).
//   _IO('r', N)     = (0x72 << 8) | N.
//   _IOR('r', N, T) = (2 << 30) | (sizeof(T) << 16) | (0x72 << 8) | N.
#define BR_TRANSACTION_PENDING_FROZEN 0x7214 // _IO('r', 20)
// _IOR('r', 21, struct binder_frozen_state_info); sizeof == 16 (u64 cookie + 2x u32).
#define BR_FROZEN_BINDER 0x80107215
#define BR_CLEAR_FREEZE_NOTIFICATION_DONE 0x7216 // _IO('r', 22)

// BC constants: added to enum binder_driver_command_protocol (kernel 6.x).
// _IOW('c', nr, struct binder_handle_cookie); sizeof(binder_handle_cookie) == 12
// (u32 handle + binder_uintptr_t cookie, __packed).
//   _IOC(_IOC_WRITE, 'c', nr, 12) = (1 << 30) | (12 << 16) | ('c' << 8) | nr.
#define BC_REQUEST_FREEZE_NOTIFICATION 1074553619 // nr 19
#define BC_CLEAR_FREEZE_NOTIFICATION 1074553620   // nr 20
#define BC_FREEZE_NOTIFICATION_DONE 1074553621    // nr 21
