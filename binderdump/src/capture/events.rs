use super::common_types::{
    self, binder_event, binder_event_ioctl, binder_event_ioctl_done, binder_event_transaction,
    binder_event_transaction_received, binder_event_write_read,
};
use anyhow::{anyhow, Context};
use binderdump_structs::binder_types::{
    binder_command, binder_ioctl, binder_return, binder_write_read, bwr_trait::Bwr,
};
use binderdump_structs::bwr_layer::Transaction;
use binderdump_structs::errors::ToAnyhow;
use log::warn;
use num::FromPrimitive;
use num_derive::FromPrimitive;
use plain::Plain;
use std::{
    ffi::{CStr, CString},
    fmt::Display,
};

unsafe impl Plain for binder_event_ioctl {}
unsafe impl Plain for binder_event {}
unsafe impl Plain for binder_event_write_read {}
unsafe impl Plain for binder_event_ioctl_done {}
unsafe impl Plain for binder_event_transaction {}
unsafe impl Plain for binder_event_transaction_received {}

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
    BINDER_COMMAND_TXN = common_types::binder_process_state_t_BINDER_COMMAND_TXN,
}

impl From<&binder_event_transaction> for Transaction {
    fn from(value: &binder_event_transaction) -> Self {
        Self {
            debug_id: value.debug_id,
            target_node: value.target_node,
            to_proc: value.to_proc,
            to_thread: value.to_thread,
            reply: value.reply,
            code: value.code,
            flags: value.flags,
        }
    }
}

#[derive(Debug, Clone)]
pub enum BinderEventData {
    BinderInvalidate,
    BinderIoctl(BinderEventIoctl),
    BinderWriteRead(BinderEventWriteRead),
    BinderIoctlDone(i32),
    BinderTransaction(Transaction),
    BinderTransactionReceived(std::ffi::c_int),
    BinderTransactionData(BinderTransactionContents),
    BinderInvalidateProcess,
}

impl BinderEventData {
    pub fn is_invalidate_process(&self) -> bool {
        match self {
            BinderEventData::BinderInvalidateProcess => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BinderEvent {
    pub pid: i32,
    pub tid: i32,
    pub timestamp: u64,
    pub data: BinderEventData,
}

impl BinderEvent {
    pub fn is_invalidate_process(&self) -> bool {
        self.data.is_invalidate_process()
    }
}

const HEADER_SIZE: usize = std::mem::size_of::<binder_event>();

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
            BinderProcessState::BINDER_TXN => {
                let data = &value[HEADER_SIZE..];
                let raw_event: &binder_event_transaction = plain::from_bytes(data)
                    .map_err(|err| err.to_anyhow("Failed to parse binder_event_transaction"))?;
                BinderEventData::BinderTransaction(raw_event.into())
            }
            BinderProcessState::BINDER_WRITE_DONE => todo!(),
            BinderProcessState::BINDER_WAIT_FOR_WORK => todo!(),
            BinderProcessState::BINDER_RETURN => todo!(),
            BinderProcessState::BINDER_READ_DONE => todo!(),
            BinderProcessState::BINDER_TXN_RECEIVED => {
                let data = &value[HEADER_SIZE..];
                let raw_event: &binder_event_transaction_received = plain::from_bytes(data)
                    .map_err(|err| {
                        err.to_anyhow("Failed to parse binder_event_transaction_received")
                    })?;
                BinderEventData::BinderTransactionReceived(raw_event.debug_id)
            }
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
            BinderProcessState::BINDER_COMMAND_TXN => {
                let data = &value[HEADER_SIZE..];
                BinderEventData::BinderTransactionData(BinderTransactionContents::try_from(data)?)
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

#[derive(Debug, Clone)]
pub struct BinderEventIoctl {
    pub fd: i32,
    pub comm: CString,
    pub uid: u32,
    pub gid: u32,
    pub cmd: binder_ioctl,
    pub arg: u64,
    pub ioctl_id: u64,
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
            ioctl_id: 0,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BinderEventWriteReadData {
    bwr: binder_write_read,
    buffer: Vec<u8>,
}

impl BinderEventWriteReadData {
    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    pub fn get_bwr(&self) -> &binder_write_read {
        &self.bwr
    }

    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    pub fn take_data(self) -> Vec<u8> {
        self.buffer
    }
}

// TODO - change to iterator
impl TryFrom<&BinderEventWriteRead> for Vec<binder_command::BinderCommand> {
    type Error = anyhow::Error;

    fn try_from(value: &BinderEventWriteRead) -> Result<Self, Self::Error> {
        match value {
            BinderEventWriteRead::BinderEventRead(_) => Err(anyhow::anyhow!(
                "No way to parse bwr read event as BinderCommand"
            )),
            BinderEventWriteRead::BinderEventWrite(bw) => {
                let mut commands = Vec::new();
                let data = bw.data();
                let mut pos = 0;
                while pos < data.len() {
                    let bc = binder_command::BinderCommand::try_from(&data[pos..])?;
                    pos += bc.size();
                    commands.push(bc);
                }
                if pos != data.len() {
                    return Err(anyhow!(
                        "Only {} out of {} bytes comsumed from bwr write command",
                        pos,
                        data.len()
                    ));
                }
                Ok(commands)
            }
        }
    }
}

impl TryFrom<&BinderEventWriteRead> for Vec<binder_return::BinderReturn> {
    type Error = anyhow::Error;

    fn try_from(value: &BinderEventWriteRead) -> Result<Self, Self::Error> {
        match value {
            BinderEventWriteRead::BinderEventWrite(_) => Err(anyhow::anyhow!(
                "No way to parse bwr write event as BinderReturn"
            )),
            BinderEventWriteRead::BinderEventRead(br) => {
                let mut returns = Vec::new();
                let data = br.data();
                let mut pos = 0;
                while pos < data.len() {
                    let br = binder_return::BinderReturn::try_from(&data[pos..])?;
                    pos += br.size();
                    returns.push(br);
                }
                if pos != data.len() {
                    return Err(anyhow!(
                        "Only {} out of {} bytes comsumed from bwr read command",
                        pos,
                        data.len()
                    ));
                }
                Ok(returns)
            }
        }
    }
}

#[derive(Clone)]
pub enum BinderEventWriteRead {
    BinderEventRead(BinderEventWriteReadData),
    BinderEventWrite(BinderEventWriteReadData),
}

impl BinderEventWriteRead {
    pub fn is_read(&self) -> bool {
        match self {
            BinderEventWriteRead::BinderEventRead(_) => true,
            BinderEventWriteRead::BinderEventWrite(_) => false,
        }
    }

    fn any_transaction_impl<T: Bwr>(data: &[u8]) -> anyhow::Result<bool> {
        let mut pos = 0;
        while pos < data.len() {
            let bc = T::from_bytes(&data[pos..])?;
            pos += bc.size();
            if bc.is_transaction() {
                return Ok(true);
            }
        }
        if pos != data.len() {
            return Err(anyhow!(
                "Only {} out of {} bytes comsumed from bwr command",
                pos,
                data.len()
            ));
        }
        Ok(false)
    }

    pub fn any_transaction(&self) -> anyhow::Result<bool> {
        match self {
            BinderEventWriteRead::BinderEventRead(br) => {
                Self::any_transaction_impl::<binder_return::BinderReturn>(br.data())
                    .context("Failed parsing BinderReturn")
            }
            BinderEventWriteRead::BinderEventWrite(bw) => {
                Self::any_transaction_impl::<binder_command::BinderCommand>(bw.data())
                    .context("Failed parsing BinderCommand")
            }
        }
    }
    // returns true if we expect the bwr ioctl to block until a response is received,
    // this is true if we are writing, and we have a BR_TRANSACTION (or any of its variations) to send
    pub fn is_blocking(&self) -> anyhow::Result<bool> {
        match self {
            BinderEventWriteRead::BinderEventRead(_) => Ok(false),
            BinderEventWriteRead::BinderEventWrite(_) => self.any_transaction(),
        }
    }

    pub fn get_bwr(&self) -> &binder_write_read {
        match self {
            BinderEventWriteRead::BinderEventRead(br) => br.get_bwr(),
            BinderEventWriteRead::BinderEventWrite(bw) => bw.get_bwr(),
        }
    }
}

impl Display for BinderEventWriteRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let event = match self {
            BinderEventWriteRead::BinderEventRead(e) => e,
            BinderEventWriteRead::BinderEventWrite(e) => e,
        };
        write!(
            f,
            "BinderEventWriteRead (write: {}/{} 0x{:x} read: {}/{} 0x{:x})",
            event.bwr.write_consumed,
            event.bwr.write_size,
            event.bwr.write_buffer,
            event.bwr.read_consumed,
            event.bwr.read_size,
            event.bwr.read_buffer
        )
    }
}

impl std::fmt::Debug for BinderEventWriteRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinderEventWriteRead::BinderEventRead(br) => {
                write!(f, "BinderEventWriteRead::BinderEventRead({})", br.size())
            }
            BinderEventWriteRead::BinderEventWrite(bc) => {
                write!(f, "BinderEventWriteRead::BinderEventWrite({})", bc.size())
            }
        }
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

#[derive(Clone)]
pub struct BinderTransactionData {
    pub total_size: usize,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for BinderTransactionData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BinderTransactionData({}/{})",
            self.data.len(),
            self.total_size
        )
    }
}

#[derive(Debug, Clone)]
pub enum BinderTransactionContents {
    Data(BinderTransactionData),
    Offsets(BinderTransactionData),
}

impl TryFrom<&[u8]> for BinderTransactionContents {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw_bwr: &binder_write_read = plain::from_bytes(value)
            .map_err(|err| err.to_anyhow("Failed to parse binder_write_read struct of txn"))?;
        let buffer = &value[BWR_SIZE..];

        if raw_bwr.write_buffer == 1 {
            if raw_bwr.write_consumed != raw_bwr.write_size {
                warn!(
                    "truncated txn data: {}/{}",
                    raw_bwr.write_consumed, raw_bwr.write_size
                );
            }
            return Ok(Self::Data(BinderTransactionData {
                total_size: raw_bwr.write_size as usize,
                data: buffer.to_vec(),
            }));
        } else if raw_bwr.read_buffer == 1 {
            if raw_bwr.read_consumed != raw_bwr.read_size {
                warn!(
                    "trunacted txn offsets: {}/{}",
                    raw_bwr.read_consumed, raw_bwr.read_size
                );
            }
            return Ok(Self::Offsets(BinderTransactionData {
                total_size: raw_bwr.read_size as usize,
                data: buffer.to_vec(),
            }));
        }

        Err(anyhow::anyhow!("Invalid BinderTransactionContents"))
    }
}
