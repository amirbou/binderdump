use super::{
    gen,
    transaction::{Transaction, TransactionSg},
};
use crate::errors::ToAnyhow;
use anyhow::Context;
use num::FromPrimitive;
use num_derive;
use num_derive::FromPrimitive;
use plain::{Error as PlainError, Plain};
use std::mem::size_of;

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum binder_command {
    BC_TRANSACTION = gen::binder_driver_command_protocol_BC_TRANSACTION,
    BC_REPLY = gen::binder_driver_command_protocol_BC_REPLY,
    BC_ACQUIRE_RESULT = gen::binder_driver_command_protocol_BC_ACQUIRE_RESULT,
    BC_FREE_BUFFER = gen::binder_driver_command_protocol_BC_FREE_BUFFER,
    BC_INCREFS = gen::binder_driver_command_protocol_BC_INCREFS,
    BC_ACQUIRE = gen::binder_driver_command_protocol_BC_ACQUIRE,
    BC_RELEASE = gen::binder_driver_command_protocol_BC_RELEASE,
    BC_DECREFS = gen::binder_driver_command_protocol_BC_DECREFS,
    BC_INCREFS_DONE = gen::binder_driver_command_protocol_BC_INCREFS_DONE,
    BC_ACQUIRE_DONE = gen::binder_driver_command_protocol_BC_ACQUIRE_DONE,
    BC_ATTEMPT_ACQUIRE = gen::binder_driver_command_protocol_BC_ATTEMPT_ACQUIRE,
    BC_REGISTER_LOOPER = gen::binder_driver_command_protocol_BC_REGISTER_LOOPER,
    BC_ENTER_LOOPER = gen::binder_driver_command_protocol_BC_ENTER_LOOPER,
    BC_EXIT_LOOPER = gen::binder_driver_command_protocol_BC_EXIT_LOOPER,
    BC_REQUEST_DEATH_NOTIFICATION =
        gen::binder_driver_command_protocol_BC_REQUEST_DEATH_NOTIFICATION,
    BC_CLEAR_DEATH_NOTIFICATION = gen::binder_driver_command_protocol_BC_CLEAR_DEATH_NOTIFICATION,
    BC_DEAD_BINDER_DONE = gen::binder_driver_command_protocol_BC_DEAD_BINDER_DONE,
    BC_TRANSACTION_SG = gen::binder_driver_command_protocol_BC_TRANSACTION_SG,
    BC_REPLY_SG = gen::binder_driver_command_protocol_BC_REPLY_SG,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RefCommand {
    // target == 0 && (IncRefs || Acquire) -> get handle to context manager (servicemanager)
    target: u32,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RefDoneCommand {
    node_ptr: u64,
    cookie: u64,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FreeBufferCommand {
    data_ptr: u64,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct DeathCommand {
    target: u32,
    cookie: u64,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct DeathDoneCommand {
    cookie: u64,
}

#[derive(Debug)]
pub enum BinderCommand {
    IncRefs(RefCommand),
    Acquire(RefCommand),
    Release(RefCommand),
    DecRefs(RefCommand),
    IncRefsDone(RefDoneCommand),
    AcquireDone(RefDoneCommand),
    FreeBuffer(FreeBufferCommand),
    TransactionSg(TransactionSg),
    ReplySg(TransactionSg),
    Transaction(Transaction),
    Reply(Transaction),
    RegisterLooper,
    EnterLooper,
    ExitLooper,
    RequestDeathNotification(DeathCommand),
    ClearDeathNotification(DeathCommand),
    DeadBinderDone(DeathDoneCommand),
}

unsafe impl Plain for RefCommand {}
unsafe impl Plain for RefDoneCommand {}
unsafe impl Plain for FreeBufferCommand {}
unsafe impl Plain for DeathCommand {}
unsafe impl Plain for DeathDoneCommand {}

impl BinderCommand {
    pub fn size(&self) -> usize {
        let inner_size = match self {
            BinderCommand::IncRefs(_)
            | BinderCommand::Acquire(_)
            | BinderCommand::Release(_)
            | BinderCommand::DecRefs(_) => size_of::<RefCommand>(),
            BinderCommand::IncRefsDone(_) | BinderCommand::AcquireDone(_) => {
                size_of::<RefDoneCommand>()
            }
            BinderCommand::FreeBuffer(_) => size_of::<FreeBufferCommand>(),
            BinderCommand::TransactionSg(_) | BinderCommand::ReplySg(_) => {
                size_of::<TransactionSg>()
            }
            BinderCommand::Transaction(_) | BinderCommand::Reply(_) => size_of::<Transaction>(),
            BinderCommand::RegisterLooper
            | BinderCommand::EnterLooper
            | BinderCommand::ExitLooper => 0,
            BinderCommand::RequestDeathNotification(_)
            | BinderCommand::ClearDeathNotification(_) => size_of::<DeathCommand>(),
            BinderCommand::DeadBinderDone(_) => size_of::<DeathDoneCommand>(),
        };
        4 + inner_size
    }

    pub fn is_transaction(&self) -> bool {
        match self {
            BinderCommand::TransactionSg(_)
            | BinderCommand::ReplySg(_)
            | BinderCommand::Transaction(_)
            | BinderCommand::Reply(_) => true,
            _ => false,
        }
    }
}

impl BinderCommand {
    fn parse_command(bc: &binder_command, data: &[u8]) -> Result<Self, PlainError> {
        let result = match bc {
            binder_command::BC_TRANSACTION | binder_command::BC_REPLY => {
                let mut command = Transaction::default();
                command.copy_from_bytes(data)?;
                match bc {
                    binder_command::BC_TRANSACTION => Self::Transaction(command),
                    binder_command::BC_REPLY => Self::Reply(command),
                    _ => unreachable!(),
                }
            }
            binder_command::BC_ACQUIRE_RESULT => todo!(),
            binder_command::BC_FREE_BUFFER => {
                let mut command = FreeBufferCommand::default();
                command.copy_from_bytes(data)?;
                Self::FreeBuffer(command)
            }
            binder_command::BC_INCREFS
            | binder_command::BC_ACQUIRE
            | binder_command::BC_RELEASE
            | binder_command::BC_DECREFS => {
                let mut command = RefCommand::default();
                command.copy_from_bytes(data)?;
                match bc {
                    binder_command::BC_INCREFS => Self::IncRefs(command),
                    binder_command::BC_ACQUIRE => Self::Acquire(command),
                    binder_command::BC_RELEASE => Self::Release(command),
                    binder_command::BC_DECREFS => Self::DecRefs(command),
                    _ => unreachable!(),
                }
            }
            binder_command::BC_INCREFS_DONE | binder_command::BC_ACQUIRE_DONE => {
                let mut command = RefDoneCommand::default();
                command.copy_from_bytes(data)?;
                match bc {
                    binder_command::BC_INCREFS_DONE => Self::IncRefsDone(command),
                    binder_command::BC_ACQUIRE_DONE => Self::AcquireDone(command),
                    _ => unreachable!(),
                }
            }
            binder_command::BC_ATTEMPT_ACQUIRE => todo!(),
            binder_command::BC_REGISTER_LOOPER => Self::RegisterLooper,
            binder_command::BC_ENTER_LOOPER => Self::EnterLooper,
            binder_command::BC_EXIT_LOOPER => Self::ExitLooper,
            binder_command::BC_REQUEST_DEATH_NOTIFICATION
            | binder_command::BC_CLEAR_DEATH_NOTIFICATION => {
                let mut command = DeathCommand::default();
                command.copy_from_bytes(data)?;
                match bc {
                    binder_command::BC_REQUEST_DEATH_NOTIFICATION => {
                        Self::RequestDeathNotification(command)
                    }
                    binder_command::BC_CLEAR_DEATH_NOTIFICATION => {
                        Self::ClearDeathNotification(command)
                    }
                    _ => unreachable!(),
                }
            }
            binder_command::BC_DEAD_BINDER_DONE => {
                let mut command = DeathDoneCommand::default();
                command.copy_from_bytes(data)?;
                Self::DeadBinderDone(command)
            }
            binder_command::BC_TRANSACTION_SG | binder_command::BC_REPLY_SG => {
                let mut command = TransactionSg::default();
                command.copy_from_bytes(data)?;
                match bc {
                    binder_command::BC_TRANSACTION_SG => Self::TransactionSg(command),
                    binder_command::BC_REPLY_SG => Self::ReplySg(command),
                    _ => unreachable!(),
                }
            }
        };
        Ok(result)
    }
}

impl TryFrom<&[u8]> for BinderCommand {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bc: &u32 =
            plain::from_bytes(value).map_err(|err| err.to_anyhow("Failed to read BC"))?;
        let bc = binder_command::from_u32(*bc).context("Failed to cast BC to enum")?;

        let data = &value[4..];
        Self::parse_command(&bc, data)
            .map_err(|err| err.to_anyhow(&format!("Failed to read {:?}", bc)))
    }
}
