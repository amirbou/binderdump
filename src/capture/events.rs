use super::common_types::{
    self, binder_event, binder_event_ioctl, binder_event_ioctl_done, binder_event_write_read,
    binder_transaction_data,
};
use crate::binder::{binder_command, binder_ioctl, binder_write_read};
use anyhow::{anyhow, Context};
use num::FromPrimitive;
use num_derive::FromPrimitive;
use plain::Plain;
use pretty_hex::*;
use std::{
    ffi::{CStr, CString},
    fmt::Display,
};

unsafe impl Plain for binder_event_ioctl {}
unsafe impl Plain for binder_event {}
unsafe impl Plain for binder_write_read {}
unsafe impl Plain for binder_event_write_read {}
unsafe impl Plain for binder_event_ioctl_done {}

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum BinderProcessState {
    BINDER_INVALID = common_types::binder_process_state_t_BINDER_INVALID,
    BINDER_IOCTL = common_types::binder_process_state_t_BINDER_IOCTL,
    BINDER_COMMAND = common_types::binder_process_state_t_BINDER_COMMAND,
    BINDER_TXN = common_types::binder_process_state_t_BINDER_TXN,
    BINDER_WRITE_DONE = common_types::binder_process_state_t_BINDER_WRITE_DONE,
    BINDER_WAIT_FOR_WORK = common_types::binder_process_state_t_BINDER_WAIT_FOR_WORK,
    BINDER_RETURN = common_types::binder_process_state_t_BINDER_RETURN,
    BINDER_READ_DONE = common_types::binder_process_state_t_BINDER_READ_DONE,
    BINDER_TXN_RECEIVED = common_types::binder_process_state_t_BINDER_TXN_RECEIVED,
    BINDER_IOCTL_DONE = common_types::binder_process_state_t_BINDER_IOCTL_DONE,
    BINDER_INVALIDATE_PROCES = common_types::binder_process_state_t_BINDER_INVALIDATE_PROCESS,
    BINDER_WRITE = common_types::binder_process_state_t_BINDER_WRITE,
    BINDER_READ = common_types::binder_process_state_t_BINDER_READ,
}

#[derive(Debug)]
pub enum BinderEventData {
    BinderInvalidate,
    BinderIoctl(BinderEventIoctl),
    BinderWriteRead(BinderEventWriteRead),
    BinderIoctlDone(i32),
    BinderInvalidateProcess,
}

#[derive(Debug)]
pub struct BinderEvent {
    pub pid: i32,
    pub tid: i32,
    pub timestamp: u64,
    pub data: BinderEventData,
}

const HEADER_SIZE: usize = std::mem::size_of::<binder_event>();

trait ToAnyhow {
    fn to_anyhow(&self, msg: &str) -> anyhow::Error;
}

impl ToAnyhow for plain::Error {
    fn to_anyhow(&self, msg: &str) -> anyhow::Error {
        match self {
            plain::Error::TooShort => anyhow!("{} - not enough data", msg),
            plain::Error::BadAlignment => anyhow!("{} - bad alignment", msg),
        }
    }
}

impl TryFrom<&[u8]> for BinderEvent {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let header: &binder_event = plain::from_bytes(value)
            .map_err(|err| err.to_anyhow("Failed to parse binder_event"))?;

        let kind = BinderProcessState::from_u32(header.type_)
            .context("Failed to parse binder_event - invalid type")?;
        let data = match kind {
            BinderProcessState::BINDER_INVALID => BinderEventData::BinderInvalidate,
            BinderProcessState::BINDER_IOCTL => {
                let ioctl_data = &value[HEADER_SIZE..];
                let raw_ioctl_event: &common_types::binder_event_ioctl =
                    plain::from_bytes(ioctl_data)
                        .map_err(|err| err.to_anyhow("Failed to parse binder_event_ioctl"))?;
                BinderEventData::BinderIoctl(BinderEventIoctl::try_from(raw_ioctl_event)?)
            }
            BinderProcessState::BINDER_COMMAND => todo!(),
            BinderProcessState::BINDER_TXN => todo!(),
            BinderProcessState::BINDER_WRITE_DONE => todo!(),
            BinderProcessState::BINDER_WAIT_FOR_WORK => todo!(),
            BinderProcessState::BINDER_RETURN => todo!(),
            BinderProcessState::BINDER_READ_DONE => todo!(),
            BinderProcessState::BINDER_TXN_RECEIVED => todo!(),
            BinderProcessState::BINDER_IOCTL_DONE => {
                let data = &value[HEADER_SIZE..];
                let raw_ioctl_done_event: &binder_event_ioctl_done = plain::from_bytes(data)
                    .map_err(|err| err.to_anyhow("Failed to parse binder_event_ioctl_done"))?;
                BinderEventData::BinderIoctlDone(raw_ioctl_done_event.ret)
            }
            BinderProcessState::BINDER_INVALIDATE_PROCES => {
                BinderEventData::BinderInvalidateProcess
            }
            BinderProcessState::BINDER_WRITE => {
                let data = &value[HEADER_SIZE..];
                BinderEventData::BinderWriteRead(BinderEventWriteRead::BinderEventWrite(
                    BinderEventWriteReadData::try_from(data)?,
                ))
            }
            BinderProcessState::BINDER_READ => {
                let data = &value[HEADER_SIZE..];
                BinderEventData::BinderWriteRead(BinderEventWriteRead::BinderEventRead(
                    BinderEventWriteReadData::try_from(data)?,
                ))
            }
        };
        Ok(Self {
            pid: header.pid,
            tid: header.tid,
            timestamp: header.timestamp,
            data: data,
        })
    }
}

#[derive(Debug)]
pub struct BinderEventIoctl {
    pub fd: i32,
    pub comm: CString,
    pub uid: u32,
    pub gid: u32,
    pub cmd: binder_ioctl,
    pub arg: u64,
}

impl TryFrom<&common_types::binder_event_ioctl> for BinderEventIoctl {
    type Error = anyhow::Error;

    fn try_from(value: &common_types::binder_event_ioctl) -> Result<Self, Self::Error> {
        let cmd = binder_ioctl::from_i32(value.cmd as i32)
            .context(format!("Invalid binder ioctl cmd {}", value.cmd))?;
        let comm = unsafe { CStr::from_ptr(value.comm.as_ptr()) };
        let comm = comm.to_owned();

        Ok(BinderEventIoctl {
            fd: value.fd,
            comm: comm,
            uid: value.uid,
            gid: value.gid,
            cmd: cmd,
            arg: value.arg,
        })
    }
}

#[derive(Debug)]
pub struct BinderEventWriteReadData {
    bwr: binder_write_read,
    buffer: Vec<u8>,
}

impl BinderEventWriteReadData {
    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    pub fn raw(&self) -> &binder_write_read {
        &self.bwr
    }

    pub fn data(&self) -> &[u8] {
        &self.buffer
    }
}

#[derive(Debug)]
pub enum BinderEventWriteRead {
    BinderEventRead(BinderEventWriteReadData),
    BinderEventWrite(BinderEventWriteReadData),
}

impl BinderEventWriteRead {
    pub fn is_write(&self) -> bool {
        match self {
            BinderEventWriteRead::BinderEventWrite(_) => true,
            _ => false,
        }
    }
}

impl Display for BinderEventWriteRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let event = match self {
            BinderEventWriteRead::BinderEventRead(e) => e,
            BinderEventWriteRead::BinderEventWrite(e) => e,
        };
        writeln!(f, "BinderEventWriteRead (")?;
        writeln!(
            f,
            "  size: {}/{} buffer: 0x{:x} read: {}/{} buffer: 0x{:x}",
            event.bwr.write_consumed,
            event.bwr.write_size,
            event.bwr.write_buffer,
            event.bwr.read_consumed,
            event.bwr.read_size,
            event.bwr.read_buffer
        )?;
        let mut hexconfig = HexConfig::default();
        hexconfig.max_bytes = 0x100;

        if self.is_write() {
            writeln!(f, "  write data:")?;
        } else {
            writeln!(f, "  read data:")?;
        }
        writeln!(f, "{:?}", event.data().hex_conf(hexconfig))?;
        writeln!(f, ")")
    }
}

const BWR_SIZE: usize = std::mem::size_of::<binder_write_read>();

impl TryFrom<&[u8]> for BinderEventWriteReadData {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw_bwr: &binder_write_read = plain::from_bytes(value)
            .map_err(|err| err.to_anyhow("Failed to parse binder_write_read struct"))?;
        let buffer = &value[BWR_SIZE..];

        Ok(Self {
            bwr: *raw_bwr,
            buffer: buffer.into(),
        })
    }
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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ScatterGatherCommand {
    transaction_data: [u8; std::mem::size_of::<binder_transaction_data>()],
    buffers_size: u64,
}

impl Default for ScatterGatherCommand {
    fn default() -> Self {
        Self {
            transaction_data: [0; std::mem::size_of::<binder_transaction_data>()],
            buffers_size: 0,
        }
    }
}

#[allow(non_snake_case)]
const fn B_PACK_CHARS(c1: char, c2: char, c3: char, c4: char) -> u32 {
    ((c1 as u32) << 24) | ((c2 as u32) << 16) | ((c3 as u32) << 8) | (c4 as u32)
}

const PING_TRANSACTION: u32 = B_PACK_CHARS('_', 'P', 'N', 'G');
const START_RECORDING_TRANSACTION: u32 = B_PACK_CHARS('_', 'S', 'R', 'D');
const STOP_RECORDING_TRANSACTION: u32 = B_PACK_CHARS('_', 'E', 'R', 'D');
const DUMP_TRANSACTION: u32 = B_PACK_CHARS('_', 'D', 'M', 'P');
const SHELL_COMMAND_TRANSACTION: u32 = B_PACK_CHARS('_', 'C', 'M', 'D');
const INTERFACE_TRANSACTION: u32 = B_PACK_CHARS('_', 'N', 'T', 'F');
const SYSPROPS_TRANSACTION: u32 = B_PACK_CHARS('_', 'S', 'P', 'R');
const EXTENSION_TRANSACTION: u32 = B_PACK_CHARS('_', 'E', 'X', 'T');
const DEBUG_PID_TRANSACTION: u32 = B_PACK_CHARS('_', 'P', 'I', 'D');
const SET_RPC_CLIENT_TRANSACTION: u32 = B_PACK_CHARS('_', 'R', 'P', 'C');

// See android.os.IBinder.TWEET_TRANSACTION
// Most importantly, messages can be anything not exceeding 130 UTF-8
// characters, and callees should exclaim "jolly good message old boy!"
const TWEET_TRANSACTION: u32 = B_PACK_CHARS('_', 'T', 'W', 'T');

// See android.os.IBinder.LIKE_TRANSACTION
// Improve binder self-esteem.
const LIKE_TRANSACTION: u32 = B_PACK_CHARS('_', 'L', 'I', 'K');

struct Code {
    code: u32,
}

impl Code {
    fn new(code: u32) -> Self {
        Self { code }
    }
}

impl Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            PING_TRANSACTION => write!(f, "'_PNG'"),
            START_RECORDING_TRANSACTION => write!(f, "'_SRD'"),
            STOP_RECORDING_TRANSACTION => write!(f, "'_ERD'"),
            DUMP_TRANSACTION => write!(f, "'_DMP'"),
            SHELL_COMMAND_TRANSACTION => write!(f, "'_CMD'"),
            INTERFACE_TRANSACTION => write!(f, "'_NTF'"),
            SYSPROPS_TRANSACTION => write!(f, "'_SPR'"),
            EXTENSION_TRANSACTION => write!(f, "'_EXT'"),
            DEBUG_PID_TRANSACTION => write!(f, "'_PID'"),
            SET_RPC_CLIENT_TRANSACTION => write!(f, "'_RPC'"),
            TWEET_TRANSACTION => write!(f, "'_TWT'"),
            LIKE_TRANSACTION => write!(f, "'_LIK'"),
            _ => write!(f, "{}", self.code),
        }
    }
}

impl std::fmt::Debug for binder_transaction_data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("binder_transaction_data")
            .field(
                "target",
                &format_args!(
                    "handle {:x} - ptr {:x}",
                    unsafe { &self.target.handle },
                    unsafe { &self.target.ptr }
                ),
            )
            .field("cookie", &self.cookie)
            .field("code", &format_args!("{}", Code::new(self.code)))
            .field("flags", &self.flags)
            .field("sender_pid", &self.sender_pid)
            .field("sender_euid", &self.sender_euid)
            .field("data_size", &self.data_size)
            .field("offsets_size", &self.offsets_size)
            .field(
                "data",
                &format_args!("{:x} - {:x?}", unsafe { &self.data.ptr.buffer }, unsafe {
                    &self.data.buf
                }),
            )
            .finish()
    }
}

unsafe impl Plain for binder_transaction_data {}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TransactionCommand {
    transaction_data: binder_transaction_data,
}

impl Default for TransactionCommand {
    fn default() -> Self {
        let transaction_data = unsafe { std::mem::zeroed::<binder_transaction_data>() };
        Self { transaction_data }
    }
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
#[repr(C)]
pub enum BinderCommand {
    IncRefs(RefCommand),
    Acquire(RefCommand),
    Release(RefCommand),
    DecRefs(RefCommand),
    IncRefsDone(RefDoneCommand),
    AcquireDone(RefDoneCommand),
    FreeBuffer(FreeBufferCommand),
    TransactionSg(ScatterGatherCommand),
    ReplySg(ScatterGatherCommand),
    Transaction(TransactionCommand),
    Reply(TransactionCommand),
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
unsafe impl Plain for ScatterGatherCommand {}
unsafe impl Plain for TransactionCommand {}
unsafe impl Plain for DeathCommand {}
unsafe impl Plain for DeathDoneCommand {}

impl BinderCommand {
    pub fn command_size(&self) -> usize {
        let inner_size = match self {
            BinderCommand::IncRefs(_)
            | BinderCommand::Acquire(_)
            | BinderCommand::Release(_)
            | BinderCommand::DecRefs(_) => std::mem::size_of::<RefCommand>(),
            BinderCommand::IncRefsDone(_) | BinderCommand::AcquireDone(_) => {
                std::mem::size_of::<RefDoneCommand>()
            }
            BinderCommand::FreeBuffer(_) => std::mem::size_of::<FreeBufferCommand>(),
            BinderCommand::TransactionSg(_) | BinderCommand::ReplySg(_) => {
                std::mem::size_of::<ScatterGatherCommand>()
            }
            BinderCommand::Transaction(_) | BinderCommand::Reply(_) => {
                std::mem::size_of::<TransactionCommand>()
            }
            BinderCommand::RegisterLooper
            | BinderCommand::EnterLooper
            | BinderCommand::ExitLooper => 0,
            BinderCommand::RequestDeathNotification(_)
            | BinderCommand::ClearDeathNotification(_) => std::mem::size_of::<DeathCommand>(),
            BinderCommand::DeadBinderDone(_) => std::mem::size_of::<DeathDoneCommand>(),
        };
        4 + inner_size
    }
}

impl TryFrom<&[u8]> for BinderCommand {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bc: &u32 =
            plain::from_bytes(value).map_err(|err| err.to_anyhow("Failed to read BC"))?;
        let bc = binder_command::from_u32(*bc).context("Failed to cast BC to enum")?;

        let data = &value[4..];
        let s = match bc {
            binder_command::BC_TRANSACTION | binder_command::BC_REPLY => {
                let mut command = TransactionCommand::default();
                command
                    .copy_from_bytes(data)
                    .map_err(|err| err.to_anyhow(&format!("Failed to read {:?}", bc)))?;
                match bc {
                    binder_command::BC_TRANSACTION => Self::Transaction(command),
                    binder_command::BC_REPLY => Self::Reply(command),
                    _ => unreachable!(),
                }
            }
            binder_command::BC_ACQUIRE_RESULT => todo!(),
            binder_command::BC_FREE_BUFFER => {
                let mut command = FreeBufferCommand::default();
                command.copy_from_bytes(data).map_err(|err| {
                    err.to_anyhow(&format!(
                        "Failed to read BC_FREE_BUFFER data: {:?}",
                        data.hex_dump()
                    ))
                })?;
                Self::FreeBuffer(command)
            }
            binder_command::BC_INCREFS
            | binder_command::BC_ACQUIRE
            | binder_command::BC_RELEASE
            | binder_command::BC_DECREFS => {
                let command = *RefCommand::from_bytes(data)
                    .map_err(|err| err.to_anyhow(&format!("Failed to read {:?}", bc)))?;
                match bc {
                    binder_command::BC_INCREFS => Self::IncRefs(command),
                    binder_command::BC_ACQUIRE => Self::Acquire(command),
                    binder_command::BC_RELEASE => Self::Release(command),
                    binder_command::BC_DECREFS => Self::DecRefs(command),
                    _ => unreachable!(),
                }
            }
            binder_command::BC_INCREFS_DONE | binder_command::BC_ACQUIRE_DONE => {
                let command = *RefDoneCommand::from_bytes(data)
                    .map_err(|err| err.to_anyhow(&format!("Failed to read {:?}", bc)))?;
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
                let command = *DeathCommand::from_bytes(data)
                    .map_err(|err| err.to_anyhow(&format!("Failed to read {:?}", bc)))?;
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
            binder_command::BC_DEAD_BINDER_DONE => Self::DeadBinderDone(
                *DeathDoneCommand::from_bytes(data)
                    .map_err(|err| err.to_anyhow("Failed to read BC_DEAD_BINDER_DONE"))?,
            ),
            binder_command::BC_TRANSACTION_SG | binder_command::BC_REPLY_SG => {
                let command = *ScatterGatherCommand::from_bytes(data)
                    .map_err(|err| err.to_anyhow(&format!("Failed to read {:?}", bc)))?;
                match bc {
                    binder_command::BC_TRANSACTION_SG => Self::TransactionSg(command),
                    binder_command::BC_REPLY_SG => Self::ReplySg(command),
                    _ => unreachable!(),
                }
            }
        };
        Ok(s)
    }
}
