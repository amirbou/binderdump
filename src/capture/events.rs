use super::common_types::{
    self, binder_event, binder_event_ioctl, binder_event_ioctl_done, binder_event_transaction,
    binder_event_transaction_received, binder_event_write_read, binder_transaction_data,
};
use crate::binder::{binder_command, binder_ioctl, binder_write_read};
use crate::errors::ToAnyhow;
use anyhow::Context;
use binrw::binrw;
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
}

#[derive(Debug)]
pub struct BinderEventTransaction {
    debug_id: i32,
    target_node: i32,
    to_proc: i32,
    to_thread: i32,
    reply: i32,
    code: u32,
    flags: u32,
}

impl From<&binder_event_transaction> for BinderEventTransaction {
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

#[derive(Debug)]
pub struct BinderEventTransactionReceived {
    debug_id: i32,
}

#[derive(Debug)]
pub enum BinderEventData {
    BinderInvalidate,
    BinderIoctl(BinderEventIoctl),
    BinderWriteRead(BinderEventWriteRead),
    BinderIoctlDone(i32),
    BinderTransaction(BinderEventTransaction),
    BinderTransactionReceived(BinderEventTransactionReceived),
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
                BinderEventData::BinderTransaction(BinderEventTransaction::from(raw_event))
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
                BinderEventData::BinderTransactionReceived(BinderEventTransactionReceived {
                    debug_id: raw_event.debug_id,
                })
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

pub enum BinderEventWriteRead {
    BinderEventRead(BinderEventWriteReadData),
    BinderEventWrite(BinderEventWriteReadData),
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
        write!(f, "BinderEventWriteRead(...)")
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
