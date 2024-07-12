use super::{
    bwr_trait::Bwr,
    transaction::{binder_transaction_data, Transaction},
};
use anyhow::Error;
use binderdump_sys;
use num_derive;
use num_derive::FromPrimitive;
use plain::{Error as PlainError, Plain};
use std::mem::size_of;

#[derive(Debug, FromPrimitive)]
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
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrorReturn {
    code: i32,
}

#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub struct TransactionSecCtx {
    transaction_data: binder_transaction_data,
    secctx: u64,
}

impl Default for TransactionSecCtx {
    fn default() -> Self {
        let transaction_data = unsafe { std::mem::zeroed::<binder_transaction_data>() };
        Self {
            transaction_data,
            secctx: 0,
        }
    }
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RefReturn {
    ptr: u64,
    cookie: u64,
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DeadBinder {
    cookie: u64,
}

#[allow(unused)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ClearDeathNotificationDone {
    cookie: u64,
}

unsafe impl Plain for ErrorReturn {}
unsafe impl Plain for TransactionSecCtx {}
unsafe impl Plain for RefReturn {}
unsafe impl Plain for DeadBinder {}
unsafe impl Plain for ClearDeathNotificationDone {}

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
            BinderReturn::Ok
            | BinderReturn::DeadReply
            | BinderReturn::Noop
            | BinderReturn::SpawnLooper
            | BinderReturn::TransactionComplete
            | BinderReturn::FailedReply
            | BinderReturn::FrozenReply
            | BinderReturn::OnewaySpamSuspect => 0,
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
}

impl TryFrom<&[u8]> for BinderReturn {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, <BinderReturn as TryFrom<&[u8]>>::Error> {
        Self::from_bytes(value)
    }
}
