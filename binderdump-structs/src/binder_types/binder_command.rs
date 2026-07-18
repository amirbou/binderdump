use super::{
    bwr_trait::Bwr,
    transaction::{Transaction, TransactionSg},
};
use binderdump_derive::{ConstOffsets, EpanProtocol, EpanProtocolEnum};
use binderdump_sys;
use num_derive;
use num_derive::FromPrimitive;
use plain::{Error as PlainError, Plain};
use std::mem::size_of;

#[derive(Debug, FromPrimitive, EpanProtocolEnum)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum binder_command {
    BC_TRANSACTION = binderdump_sys::binder_driver_command_protocol_BC_TRANSACTION,
    BC_REPLY = binderdump_sys::binder_driver_command_protocol_BC_REPLY,
    BC_ACQUIRE_RESULT = binderdump_sys::binder_driver_command_protocol_BC_ACQUIRE_RESULT,
    BC_FREE_BUFFER = binderdump_sys::binder_driver_command_protocol_BC_FREE_BUFFER,
    BC_INCREFS = binderdump_sys::binder_driver_command_protocol_BC_INCREFS,
    BC_ACQUIRE = binderdump_sys::binder_driver_command_protocol_BC_ACQUIRE,
    BC_RELEASE = binderdump_sys::binder_driver_command_protocol_BC_RELEASE,
    BC_DECREFS = binderdump_sys::binder_driver_command_protocol_BC_DECREFS,
    BC_INCREFS_DONE = binderdump_sys::binder_driver_command_protocol_BC_INCREFS_DONE,
    BC_ACQUIRE_DONE = binderdump_sys::binder_driver_command_protocol_BC_ACQUIRE_DONE,
    BC_ATTEMPT_ACQUIRE = binderdump_sys::binder_driver_command_protocol_BC_ATTEMPT_ACQUIRE,
    BC_REGISTER_LOOPER = binderdump_sys::binder_driver_command_protocol_BC_REGISTER_LOOPER,
    BC_ENTER_LOOPER = binderdump_sys::binder_driver_command_protocol_BC_ENTER_LOOPER,
    BC_EXIT_LOOPER = binderdump_sys::binder_driver_command_protocol_BC_EXIT_LOOPER,
    BC_REQUEST_DEATH_NOTIFICATION =
        binderdump_sys::binder_driver_command_protocol_BC_REQUEST_DEATH_NOTIFICATION,
    BC_CLEAR_DEATH_NOTIFICATION =
        binderdump_sys::binder_driver_command_protocol_BC_CLEAR_DEATH_NOTIFICATION,
    BC_DEAD_BINDER_DONE = binderdump_sys::binder_driver_command_protocol_BC_DEAD_BINDER_DONE,
    BC_TRANSACTION_SG = binderdump_sys::binder_driver_command_protocol_BC_TRANSACTION_SG,
    BC_REPLY_SG = binderdump_sys::binder_driver_command_protocol_BC_REPLY_SG,
    BC_REQUEST_FREEZE_NOTIFICATION = binderdump_sys::BC_REQUEST_FREEZE_NOTIFICATION,
    BC_CLEAR_FREEZE_NOTIFICATION = binderdump_sys::BC_CLEAR_FREEZE_NOTIFICATION,
    BC_FREEZE_NOTIFICATION_DONE = binderdump_sys::BC_FREEZE_NOTIFICATION_DONE,
}

#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct RefCommand {
    // target == 0 && (IncRefs || Acquire) -> get handle to context manager (servicemanager)
    target: u32,
}

#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct RefDoneCommand {
    #[epan(display = Hex)]
    node_ptr: u64,
    #[epan(display = Hex)]
    cookie: u64,
}

#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct FreeBufferCommand {
    #[epan(display = Hex)]
    data_ptr: u64,
}

#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C, packed)]
pub struct DeathCommand {
    target: u32,
    #[epan(display = Hex)]
    cookie: u64,
}

#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct DeathDoneCommand {
    #[epan(display = Hex)]
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
    RequestFreezeNotification(DeathCommand),
    ClearFreezeNotification(DeathCommand),
    FreezeNotificationDone(DeathDoneCommand),
}

unsafe impl Plain for RefCommand {}
unsafe impl Plain for RefDoneCommand {}
unsafe impl Plain for FreeBufferCommand {}
unsafe impl Plain for DeathCommand {}
unsafe impl Plain for DeathDoneCommand {}

impl BinderCommand {}

impl Bwr for BinderCommand {
    type HeaderType = binder_command;

    fn size(&self) -> usize {
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
            | BinderCommand::ClearDeathNotification(_)
            | BinderCommand::RequestFreezeNotification(_)
            | BinderCommand::ClearFreezeNotification(_) => size_of::<DeathCommand>(),
            BinderCommand::DeadBinderDone(_) | BinderCommand::FreezeNotificationDone(_) => {
                size_of::<DeathDoneCommand>()
            }
        };
        4 + inner_size
    }

    fn parse_with_header(bc: &binder_command, data: &[u8]) -> Result<Self, PlainError> {
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
            | binder_command::BC_CLEAR_DEATH_NOTIFICATION
            | binder_command::BC_REQUEST_FREEZE_NOTIFICATION
            | binder_command::BC_CLEAR_FREEZE_NOTIFICATION => {
                let mut command = DeathCommand::default();
                command.copy_from_bytes(data)?;
                match bc {
                    binder_command::BC_REQUEST_DEATH_NOTIFICATION => {
                        Self::RequestDeathNotification(command)
                    }
                    binder_command::BC_CLEAR_DEATH_NOTIFICATION => {
                        Self::ClearDeathNotification(command)
                    }
                    binder_command::BC_REQUEST_FREEZE_NOTIFICATION => {
                        Self::RequestFreezeNotification(command)
                    }
                    binder_command::BC_CLEAR_FREEZE_NOTIFICATION => {
                        Self::ClearFreezeNotification(command)
                    }
                    _ => unreachable!(),
                }
            }
            binder_command::BC_DEAD_BINDER_DONE | binder_command::BC_FREEZE_NOTIFICATION_DONE => {
                let mut command = DeathDoneCommand::default();
                command.copy_from_bytes(data)?;
                match bc {
                    binder_command::BC_DEAD_BINDER_DONE => Self::DeadBinderDone(command),
                    binder_command::BC_FREEZE_NOTIFICATION_DONE => {
                        Self::FreezeNotificationDone(command)
                    }
                    _ => unreachable!(),
                }
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

    fn is_transaction(&self) -> bool {
        match self {
            BinderCommand::TransactionSg(_)
            | BinderCommand::ReplySg(_)
            | BinderCommand::Transaction(_)
            | BinderCommand::Reply(_) => true,
            _ => false,
        }
    }

    fn get_header(&self) -> Self::HeaderType {
        match self {
            BinderCommand::IncRefs(_) => binder_command::BC_INCREFS,
            BinderCommand::Acquire(_) => binder_command::BC_ACQUIRE,
            BinderCommand::Release(_) => binder_command::BC_RELEASE,
            BinderCommand::DecRefs(_) => binder_command::BC_DECREFS,
            BinderCommand::IncRefsDone(_) => binder_command::BC_INCREFS_DONE,
            BinderCommand::AcquireDone(_) => binder_command::BC_ACQUIRE_DONE,
            BinderCommand::FreeBuffer(_) => binder_command::BC_FREE_BUFFER,
            BinderCommand::TransactionSg(_) => binder_command::BC_TRANSACTION_SG,
            BinderCommand::ReplySg(_) => binder_command::BC_REPLY_SG,
            BinderCommand::Transaction(_) => binder_command::BC_TRANSACTION,
            BinderCommand::Reply(_) => binder_command::BC_REPLY,
            BinderCommand::RegisterLooper => binder_command::BC_REGISTER_LOOPER,
            BinderCommand::EnterLooper => binder_command::BC_ENTER_LOOPER,
            BinderCommand::ExitLooper => binder_command::BC_EXIT_LOOPER,
            BinderCommand::RequestDeathNotification(_) => {
                binder_command::BC_REQUEST_DEATH_NOTIFICATION
            }
            BinderCommand::ClearDeathNotification(_) => binder_command::BC_CLEAR_DEATH_NOTIFICATION,
            BinderCommand::DeadBinderDone(_) => binder_command::BC_DEAD_BINDER_DONE,
            BinderCommand::RequestFreezeNotification(_) => {
                binder_command::BC_REQUEST_FREEZE_NOTIFICATION
            }
            BinderCommand::ClearFreezeNotification(_) => {
                binder_command::BC_CLEAR_FREEZE_NOTIFICATION
            }
            BinderCommand::FreezeNotificationDone(_) => binder_command::BC_FREEZE_NOTIFICATION_DONE,
        }
    }
}

impl TryFrom<&[u8]> for BinderCommand {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf<T: Copy>(header: u32, payload: T) -> Vec<u8> {
        let mut buf = header.to_ne_bytes().to_vec();
        let payload_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(&payload as *const _ as *const u8, std::mem::size_of::<T>())
        };
        buf.extend_from_slice(payload_bytes);
        buf
    }

    #[test]
    fn parses_bc_request_freeze_notification() {
        let header: u32 = binderdump_sys::BC_REQUEST_FREEZE_NOTIFICATION;
        let payload = DeathCommand {
            target: 42,
            cookie: 0xdeadbeef,
        };
        let buf = make_buf(header, payload);

        let r = BinderCommand::from_bytes(&buf).expect("must parse new opcode");
        match r {
            BinderCommand::RequestFreezeNotification(_) => {}
            _ => panic!("expected RequestFreezeNotification, got {:?}", r),
        }
    }

    #[test]
    fn parses_bc_clear_freeze_notification() {
        let header: u32 = binderdump_sys::BC_CLEAR_FREEZE_NOTIFICATION;
        let payload = DeathCommand {
            target: 7,
            cookie: 0xc0ffee,
        };
        let buf = make_buf(header, payload);

        let r = BinderCommand::from_bytes(&buf).expect("must parse new opcode");
        assert!(matches!(r, BinderCommand::ClearFreezeNotification(_)));
    }

    #[test]
    fn parses_bc_freeze_notification_done() {
        // _IOW('c', 21, struct binder_handle_cookie), sizeof == 12.
        assert_eq!(binderdump_sys::BC_FREEZE_NOTIFICATION_DONE, 1074553621);
        let header: u32 = binderdump_sys::BC_FREEZE_NOTIFICATION_DONE;
        let payload = DeathDoneCommand { cookie: 0 };
        let buf = make_buf(header, payload);

        let r = BinderCommand::from_bytes(&buf).expect("must parse new opcode");
        assert!(matches!(r, BinderCommand::FreezeNotificationDone(_)));
    }

    fn parse(header: u32, payload: impl Copy) -> BinderCommand {
        BinderCommand::from_bytes(&make_buf(header, payload)).expect("parse")
    }

    #[test]
    fn parses_ref_commands_and_reports_size() {
        use binderdump_sys as sys;
        let cases = [
            (
                sys::binder_driver_command_protocol_BC_INCREFS,
                binder_command::BC_INCREFS,
            ),
            (
                sys::binder_driver_command_protocol_BC_ACQUIRE,
                binder_command::BC_ACQUIRE,
            ),
            (
                sys::binder_driver_command_protocol_BC_RELEASE,
                binder_command::BC_RELEASE,
            ),
            (
                sys::binder_driver_command_protocol_BC_DECREFS,
                binder_command::BC_DECREFS,
            ),
        ];
        for (header, want) in cases {
            let cmd = parse(header, RefCommand { target: 5 });
            assert!(matches!(
                (&cmd, want),
                (BinderCommand::IncRefs(_), binder_command::BC_INCREFS)
                    | (BinderCommand::Acquire(_), binder_command::BC_ACQUIRE)
                    | (BinderCommand::Release(_), binder_command::BC_RELEASE)
                    | (BinderCommand::DecRefs(_), binder_command::BC_DECREFS)
            ));
            assert!(!cmd.is_transaction());
            assert_eq!(cmd.size(), 4 + std::mem::size_of::<RefCommand>());
        }
    }

    #[test]
    fn parses_ref_done_and_free_buffer() {
        use binderdump_sys as sys;
        let inc = parse(
            sys::binder_driver_command_protocol_BC_INCREFS_DONE,
            RefDoneCommand {
                node_ptr: 1,
                cookie: 2,
            },
        );
        assert!(matches!(inc, BinderCommand::IncRefsDone(_)));
        assert_eq!(inc.size(), 4 + std::mem::size_of::<RefDoneCommand>());

        let acq = parse(
            sys::binder_driver_command_protocol_BC_ACQUIRE_DONE,
            RefDoneCommand {
                node_ptr: 3,
                cookie: 4,
            },
        );
        assert!(matches!(acq, BinderCommand::AcquireDone(_)));

        let fb = parse(
            sys::binder_driver_command_protocol_BC_FREE_BUFFER,
            FreeBufferCommand { data_ptr: 0xabcd },
        );
        assert!(matches!(fb, BinderCommand::FreeBuffer(_)));
        assert_eq!(fb.size(), 4 + std::mem::size_of::<FreeBufferCommand>());
        assert!(matches!(fb.get_header(), binder_command::BC_FREE_BUFFER));
    }

    #[test]
    fn parses_death_and_dead_binder_done() {
        use binderdump_sys as sys;
        let req = parse(
            sys::binder_driver_command_protocol_BC_REQUEST_DEATH_NOTIFICATION,
            DeathCommand {
                target: 1,
                cookie: 2,
            },
        );
        assert!(matches!(req, BinderCommand::RequestDeathNotification(_)));
        assert_eq!(req.size(), 4 + std::mem::size_of::<DeathCommand>());

        let clr = parse(
            sys::binder_driver_command_protocol_BC_CLEAR_DEATH_NOTIFICATION,
            DeathCommand {
                target: 3,
                cookie: 4,
            },
        );
        assert!(matches!(clr, BinderCommand::ClearDeathNotification(_)));

        let done = parse(
            sys::binder_driver_command_protocol_BC_DEAD_BINDER_DONE,
            DeathDoneCommand { cookie: 9 },
        );
        assert!(matches!(done, BinderCommand::DeadBinderDone(_)));
        assert_eq!(done.size(), 4 + std::mem::size_of::<DeathDoneCommand>());
    }

    #[test]
    fn parses_looper_commands_with_no_payload() {
        use binderdump_sys as sys;
        let reg = parse(sys::binder_driver_command_protocol_BC_REGISTER_LOOPER, ());
        assert!(matches!(reg, BinderCommand::RegisterLooper));
        assert_eq!(reg.size(), 4);
        assert!(matches!(
            reg.get_header(),
            binder_command::BC_REGISTER_LOOPER
        ));
        assert!(matches!(
            parse(sys::binder_driver_command_protocol_BC_ENTER_LOOPER, ()),
            BinderCommand::EnterLooper
        ));
        assert!(matches!(
            parse(sys::binder_driver_command_protocol_BC_EXIT_LOOPER, ()),
            BinderCommand::ExitLooper
        ));
    }

    #[test]
    fn parses_transactions_and_marks_them_as_transactions() {
        use binderdump_sys as sys;
        let txn = parse(
            sys::binder_driver_command_protocol_BC_TRANSACTION,
            Transaction::default(),
        );
        assert!(matches!(txn, BinderCommand::Transaction(_)));
        assert!(txn.is_transaction());
        assert_eq!(txn.size(), 4 + std::mem::size_of::<Transaction>());
        assert!(matches!(txn.get_header(), binder_command::BC_TRANSACTION));

        let reply = parse(
            sys::binder_driver_command_protocol_BC_REPLY,
            Transaction::default(),
        );
        assert!(matches!(reply, BinderCommand::Reply(_)));

        let sg = parse(
            sys::binder_driver_command_protocol_BC_TRANSACTION_SG,
            TransactionSg::default(),
        );
        assert!(matches!(sg, BinderCommand::TransactionSg(_)));
        assert!(sg.is_transaction());
        assert_eq!(sg.size(), 4 + std::mem::size_of::<TransactionSg>());

        let reply_sg = parse(
            sys::binder_driver_command_protocol_BC_REPLY_SG,
            TransactionSg::default(),
        );
        assert!(matches!(reply_sg, BinderCommand::ReplySg(_)));
    }

    #[test]
    fn try_from_slice_dispatches_to_from_bytes() {
        let buf = make_buf(
            binderdump_sys::binder_driver_command_protocol_BC_ACQUIRE,
            RefCommand { target: 0 },
        );
        let cmd = BinderCommand::try_from(buf.as_slice()).expect("try_from");
        assert!(matches!(cmd, BinderCommand::Acquire(_)));
    }
}
