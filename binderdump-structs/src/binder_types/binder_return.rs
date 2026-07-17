use super::{bwr_trait::Bwr, transaction::Transaction};
use anyhow::Error;
use binderdump_derive::{ConstOffsets, EpanProtocol, EpanProtocolEnum};
use binderdump_sys;
use num_derive;
use num_derive::FromPrimitive;
use plain::{Error as PlainError, Plain};
use std::mem::size_of;

#[derive(Debug, FromPrimitive, EpanProtocolEnum)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum binder_return {
    BR_ERROR = binderdump_sys::binder_driver_return_protocol_BR_ERROR,
    BR_OK = binderdump_sys::binder_driver_return_protocol_BR_OK,
    BR_TRANSACTION_SEC_CTX = binderdump_sys::binder_driver_return_protocol_BR_TRANSACTION_SEC_CTX,
    BR_TRANSACTION = binderdump_sys::binder_driver_return_protocol_BR_TRANSACTION,
    BR_REPLY = binderdump_sys::binder_driver_return_protocol_BR_REPLY,
    BR_ACQUIRE_RESULT = binderdump_sys::binder_driver_return_protocol_BR_ACQUIRE_RESULT,
    BR_DEAD_REPLY = binderdump_sys::binder_driver_return_protocol_BR_DEAD_REPLY,
    BR_TRANSACTION_COMPLETE = binderdump_sys::binder_driver_return_protocol_BR_TRANSACTION_COMPLETE,
    BR_INCREFS = binderdump_sys::binder_driver_return_protocol_BR_INCREFS,
    BR_ACQUIRE = binderdump_sys::binder_driver_return_protocol_BR_ACQUIRE,
    BR_RELEASE = binderdump_sys::binder_driver_return_protocol_BR_RELEASE,
    BR_DECREFS = binderdump_sys::binder_driver_return_protocol_BR_DECREFS,
    BR_ATTEMPT_ACQUIRE = binderdump_sys::binder_driver_return_protocol_BR_ATTEMPT_ACQUIRE,
    BR_NOOP = binderdump_sys::binder_driver_return_protocol_BR_NOOP,
    BR_SPAWN_LOOPER = binderdump_sys::binder_driver_return_protocol_BR_SPAWN_LOOPER,
    BR_FINISHED = binderdump_sys::binder_driver_return_protocol_BR_FINISHED,
    BR_DEAD_BINDER = binderdump_sys::binder_driver_return_protocol_BR_DEAD_BINDER,
    BR_CLEAR_DEATH_NOTIFICATION_DONE =
        binderdump_sys::binder_driver_return_protocol_BR_CLEAR_DEATH_NOTIFICATION_DONE,
    BR_FAILED_REPLY = binderdump_sys::binder_driver_return_protocol_BR_FAILED_REPLY,
    BR_FROZEN_REPLY = binderdump_sys::binder_driver_return_protocol_BR_FROZEN_REPLY,
    BR_ONEWAY_SPAM_SUSPECT = binderdump_sys::binder_driver_return_protocol_BR_ONEWAY_SPAM_SUSPECT,
    BR_TRANSACTION_PENDING_FROZEN = binderdump_sys::BR_TRANSACTION_PENDING_FROZEN,
    BR_FROZEN_BINDER = binderdump_sys::BR_FROZEN_BINDER,
    BR_CLEAR_FREEZE_NOTIFICATION_DONE = binderdump_sys::BR_CLEAR_FREEZE_NOTIFICATION_DONE,
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct ErrorReturn {
    code: i32,
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct TransactionSecCtx {
    transaction_data: Transaction,
    #[epan(display = Hex)]
    secctx: u64,
}

impl TransactionSecCtx {
    pub fn transaction(&self) -> &Transaction {
        &self.transaction_data
    }
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct RefReturn {
    #[epan(display = Hex)]
    ptr: u64,
    #[epan(display = Hex)]
    cookie: u64,
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct DeadBinder {
    #[epan(display = Hex)]
    cookie: u64,
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct ClearDeathNotificationDone {
    #[epan(display = Hex)]
    cookie: u64,
}

// Payload of BR_FROZEN_BINDER: `struct binder_frozen_state_info` (16 bytes) from
// <linux/android/binder.h>. bindgen doesn't emit the struct (it's only named by
// the BR_FROZEN_BINDER _IOR macro), so mirror it here.
#[allow(unused)]
#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct FrozenStateInfo {
    #[epan(display = Hex)]
    cookie: u64,
    is_frozen: u32,
    reserved: u32,
}

// Payload of BR_CLEAR_FREEZE_NOTIFICATION_DONE: a binder_uintptr_t (8 bytes) — the
// cookie of the freeze notification whose clear was acknowledged.
#[allow(unused)]
#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct FreezeNotificationDone {
    #[epan(display = Hex)]
    cookie: u64,
}

unsafe impl Plain for ErrorReturn {}
unsafe impl Plain for TransactionSecCtx {}
unsafe impl Plain for RefReturn {}
unsafe impl Plain for DeadBinder {}
unsafe impl Plain for ClearDeathNotificationDone {}
unsafe impl Plain for FrozenStateInfo {}
unsafe impl Plain for FreezeNotificationDone {}

#[derive(Debug)]
pub enum BinderReturn {
    Error(ErrorReturn),
    Ok,
    TransactionSecCtx(TransactionSecCtx),
    Transaction(Transaction),
    Reply(Transaction),
    DeadReply,
    TransactionComplete,
    IncRefs(RefReturn),
    Acquire(RefReturn),
    Release(RefReturn),
    DecRefs(RefReturn),
    Noop,
    SpawnLooper,
    DeadBinder(DeadBinder),
    ClearDeathNotificationDone(ClearDeathNotificationDone),
    FailedReply,
    FrozenReply,
    OnewaySpamSuspect,
    TransactionPendingFrozen,
    FrozenBinder(FrozenStateInfo),
    ClearFreezeNotificationDone(FreezeNotificationDone),
    // currently not supported
    // AcquireResult(),
    // AttemptCookie(),
    // Finished(),
}

impl Bwr for BinderReturn {
    type HeaderType = binder_return;

    fn size(&self) -> usize {
        let inner_size = match self {
            BinderReturn::Error(_) => size_of::<ErrorReturn>(),
            BinderReturn::TransactionSecCtx(_) => size_of::<TransactionSecCtx>(),
            BinderReturn::Transaction(_) | BinderReturn::Reply(_) => size_of::<Transaction>(),
            BinderReturn::IncRefs(_)
            | BinderReturn::Acquire(_)
            | BinderReturn::Release(_)
            | BinderReturn::DecRefs(_) => size_of::<RefReturn>(),
            BinderReturn::DeadBinder(_) => size_of::<DeadBinder>(),
            BinderReturn::ClearDeathNotificationDone(_) => size_of::<ClearDeathNotificationDone>(),
            BinderReturn::FrozenBinder(_) => size_of::<FrozenStateInfo>(),
            BinderReturn::ClearFreezeNotificationDone(_) => size_of::<FreezeNotificationDone>(),
            BinderReturn::Ok
            | BinderReturn::DeadReply
            | BinderReturn::Noop
            | BinderReturn::SpawnLooper
            | BinderReturn::TransactionComplete
            | BinderReturn::FailedReply
            | BinderReturn::FrozenReply
            | BinderReturn::OnewaySpamSuspect
            | BinderReturn::TransactionPendingFrozen => 0,
        };
        4 + inner_size
    }

    fn parse_with_header(br: &binder_return, data: &[u8]) -> Result<Self, PlainError> {
        let result = match br {
            binder_return::BR_ERROR => {
                let mut ret = ErrorReturn::default();
                ret.copy_from_bytes(data)?;
                Self::Error(ret)
            }
            binder_return::BR_OK => Self::Ok,
            binder_return::BR_TRANSACTION_SEC_CTX => {
                let mut ret = TransactionSecCtx::default();
                ret.copy_from_bytes(data)?;
                Self::TransactionSecCtx(ret)
            }
            binder_return::BR_TRANSACTION | binder_return::BR_REPLY => {
                let mut ret = Transaction::default();
                ret.copy_from_bytes(data)?;
                match br {
                    binder_return::BR_TRANSACTION => Self::Transaction(ret),
                    binder_return::BR_REPLY => Self::Reply(ret),
                    _ => unreachable!(),
                }
            }
            binder_return::BR_ACQUIRE_RESULT => todo!(),
            binder_return::BR_DEAD_REPLY => Self::DeadReply,
            binder_return::BR_TRANSACTION_COMPLETE => Self::TransactionComplete,
            binder_return::BR_INCREFS
            | binder_return::BR_ACQUIRE
            | binder_return::BR_RELEASE
            | binder_return::BR_DECREFS => {
                let mut ret = RefReturn::default();
                ret.copy_from_bytes(data)?;
                match br {
                    binder_return::BR_INCREFS => Self::IncRefs(ret),
                    binder_return::BR_ACQUIRE => Self::Acquire(ret),
                    binder_return::BR_RELEASE => Self::Release(ret),
                    binder_return::BR_DECREFS => Self::DecRefs(ret),
                    _ => unreachable!(),
                }
            }
            binder_return::BR_ATTEMPT_ACQUIRE => todo!(),
            binder_return::BR_NOOP => Self::Noop,
            binder_return::BR_SPAWN_LOOPER => Self::SpawnLooper,
            binder_return::BR_FINISHED => todo!(),
            binder_return::BR_DEAD_BINDER => {
                let mut ret = DeadBinder::default();
                ret.copy_from_bytes(data)?;
                Self::DeadBinder(ret)
            }
            binder_return::BR_CLEAR_DEATH_NOTIFICATION_DONE => {
                let mut ret = ClearDeathNotificationDone::default();
                ret.copy_from_bytes(data)?;
                Self::ClearDeathNotificationDone(ret)
            }
            binder_return::BR_FAILED_REPLY => Self::FailedReply,
            binder_return::BR_FROZEN_REPLY => Self::FrozenReply,
            binder_return::BR_ONEWAY_SPAM_SUSPECT => Self::OnewaySpamSuspect,
            binder_return::BR_TRANSACTION_PENDING_FROZEN => Self::TransactionPendingFrozen,
            binder_return::BR_FROZEN_BINDER => {
                let mut ret = FrozenStateInfo::default();
                ret.copy_from_bytes(data)?;
                Self::FrozenBinder(ret)
            }
            binder_return::BR_CLEAR_FREEZE_NOTIFICATION_DONE => {
                let mut ret = FreezeNotificationDone::default();
                ret.copy_from_bytes(data)?;
                Self::ClearFreezeNotificationDone(ret)
            }
        };
        Ok(result)
    }

    fn is_transaction(&self) -> bool {
        match self {
            BinderReturn::TransactionSecCtx(_)
            | BinderReturn::Transaction(_)
            | BinderReturn::Reply(_) => true,
            _ => false,
        }
    }

    fn get_header(&self) -> Self::HeaderType {
        match self {
            BinderReturn::Error(_) => binder_return::BR_ERROR,
            BinderReturn::Ok => binder_return::BR_OK,
            BinderReturn::TransactionSecCtx(_) => binder_return::BR_TRANSACTION_SEC_CTX,
            BinderReturn::Transaction(_) => binder_return::BR_TRANSACTION,
            BinderReturn::Reply(_) => binder_return::BR_REPLY,
            BinderReturn::DeadReply => binder_return::BR_DEAD_REPLY,
            BinderReturn::TransactionComplete => binder_return::BR_TRANSACTION_COMPLETE,
            BinderReturn::IncRefs(_) => binder_return::BR_INCREFS,
            BinderReturn::Acquire(_) => binder_return::BR_ACQUIRE,
            BinderReturn::Release(_) => binder_return::BR_RELEASE,
            BinderReturn::DecRefs(_) => binder_return::BR_DECREFS,
            BinderReturn::Noop => binder_return::BR_NOOP,
            BinderReturn::SpawnLooper => binder_return::BR_SPAWN_LOOPER,
            BinderReturn::DeadBinder(_) => binder_return::BR_DEAD_BINDER,
            BinderReturn::ClearDeathNotificationDone(_) => {
                binder_return::BR_CLEAR_DEATH_NOTIFICATION_DONE
            }
            BinderReturn::FailedReply => binder_return::BR_FAILED_REPLY,
            BinderReturn::FrozenReply => binder_return::BR_FROZEN_REPLY,
            BinderReturn::OnewaySpamSuspect => binder_return::BR_ONEWAY_SPAM_SUSPECT,
            BinderReturn::TransactionPendingFrozen => binder_return::BR_TRANSACTION_PENDING_FROZEN,
            BinderReturn::FrozenBinder(_) => binder_return::BR_FROZEN_BINDER,
            BinderReturn::ClearFreezeNotificationDone(_) => {
                binder_return::BR_CLEAR_FREEZE_NOTIFICATION_DONE
            }
        }
    }
}

impl TryFrom<&[u8]> for BinderReturn {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, <BinderReturn as TryFrom<&[u8]>>::Error> {
        Self::from_bytes(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_br_transaction_pending_frozen() {
        let buf = 29204u32.to_ne_bytes();
        let r = BinderReturn::from_bytes(&buf).expect("must parse new opcode");
        assert!(matches!(r, BinderReturn::TransactionPendingFrozen));
    }

    #[test]
    fn parses_br_frozen_binder() {
        // _IOR('r', 21, struct binder_frozen_state_info), sizeof == 16:
        // (2 << 30) | (16 << 16) | ('r' << 8) | 21. The 16-byte payload follows the
        // 4-byte header, so the whole command is 20 bytes.
        let mut buf = 0x8010_7215u32.to_ne_bytes().to_vec();
        buf.extend_from_slice(&0x7fdeadbeefu64.to_le_bytes()); // cookie
        buf.extend_from_slice(&1u32.to_le_bytes()); // is_frozen
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        let r = BinderReturn::from_bytes(&buf).expect("must parse new opcode");
        assert!(matches!(r, BinderReturn::FrozenBinder(_)));
        assert_eq!(r.size(), 4 + 16);
    }

    // BR_FROZEN_BINDER carries a 16-byte payload; a size() of 4 (ignoring it) would
    // misalign the next command in the stream and read its cookie as a bogus header
    // ("Failed to cast Header to enum"). Verify the trailing command still parses.
    #[test]
    fn br_frozen_binder_keeps_stream_aligned() {
        let mut buf = 0x8010_7215u32.to_ne_bytes().to_vec(); // BR_FROZEN_BINDER
        buf.extend_from_slice(&0x7fd457a0u64.to_le_bytes()); // cookie (a device pointer)
        buf.extend_from_slice(&1u32.to_le_bytes()); // is_frozen
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        let next_at = buf.len();
        buf.extend_from_slice(&29204u32.to_ne_bytes()); // BR_TRANSACTION_PENDING_FROZEN

        let first = BinderReturn::from_bytes(&buf).expect("frozen binder");
        assert_eq!(first.size(), next_at);
        let second = BinderReturn::from_bytes(&buf[first.size()..]).expect("cmd after frozen");
        assert!(matches!(second, BinderReturn::TransactionPendingFrozen));
    }

    #[test]
    fn parses_br_clear_freeze_notification_done() {
        // _IOR('r', 22, binder_uintptr_t) = 0x80087216, followed by the 8-byte cookie.
        let mut buf = 0x8008_7216u32.to_ne_bytes().to_vec();
        buf.extend_from_slice(&0x7fdeadbeefu64.to_le_bytes()); // cookie
        let r = BinderReturn::from_bytes(&buf).expect("must parse new opcode");
        assert!(matches!(r, BinderReturn::ClearFreezeNotificationDone(_)));
        assert_eq!(r.size(), 4 + 8);
    }
}
