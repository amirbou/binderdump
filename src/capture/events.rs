use super::common_types::{self, binder_event};
use crate::binder::{binder_ioctl, binder_write_read};
use anyhow::{anyhow, Context};
use num::FromPrimitive;
use num_derive::FromPrimitive;
use plain::Plain;
use pretty_hex::*;
use std::{
    ffi::{CStr, CString},
    fmt::Display,
};

unsafe impl Plain for common_types::binder_event_ioctl {}
unsafe impl Plain for common_types::binder_event {}
unsafe impl Plain for binder_write_read {}

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
    BINDER_IOCTL_WRITE_READ = common_types::binder_process_state_t_BINDER_IOCTL_WRITE_READ,
}

#[derive(Debug)]
pub enum BinderEventData {
    BinderInvalidate,
    BinderIoctl(BinderEventIoctl),
    BinderWriteRead(BinderEventWriteRead),
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
            BinderProcessState::BINDER_IOCTL_DONE => todo!(),
            BinderProcessState::BINDER_INVALIDATE_PROCES => {
                BinderEventData::BinderInvalidateProcess
            }
            BinderProcessState::BINDER_IOCTL_WRITE_READ => {
                let data = &value[HEADER_SIZE..];
                BinderEventData::BinderWriteRead(BinderEventWriteRead::try_from(data)?)
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
pub struct BinderEventWriteRead {
    bwr: binder_write_read,
    write_buffer: Vec<u8>,
    read_buffer: Vec<u8>,
}

impl BinderEventWriteRead {
    pub fn total_size(&self) -> usize {
        self.write_buffer.len() + self.read_buffer.len()
    }

    pub fn write_size(&self) -> usize {
        self.write_buffer.len()
    }

    pub fn read_size(&self) -> usize {
        self.read_buffer.len()
    }

    pub fn write_data(&self) -> &[u8] {
        &self.write_buffer
    }

    pub fn read_data(&self) -> &[u8] {
        &self.read_buffer
    }

    pub fn raw(&self) -> &binder_write_read {
        &self.bwr
    }
}

impl Display for BinderEventWriteRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "BinderEventWriteRead (")?;
        writeln!(
            f,
            "  write_size: {} write_buffer: 0x{:x} read_size: {} read_buffer: 0x{:x}",
            self.bwr.write_size, self.bwr.write_buffer, self.bwr.read_size, self.bwr.read_buffer
        )?;
        let mut hexconfig = HexConfig::default();
        hexconfig.max_bytes = 64;

        writeln!(f, "  write data:")?;
        writeln!(f, "{:?}", self.write_data().hex_conf(hexconfig.clone()))?;

        writeln!(f, "  read data:")?;
        writeln!(f, "{:?}", self.read_data().hex_conf(hexconfig))?;
        writeln!(f, ")")
    }
}

const BWR_SIZE: usize = std::mem::size_of::<binder_write_read>();

impl TryFrom<&[u8]> for BinderEventWriteRead {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw_bwr: &binder_write_read = plain::from_bytes(value)
            .map_err(|err| err.to_anyhow("Failed to parse binder_write_read struct"))?;
        let bufs = &value[BWR_SIZE..];
        let write_buf = &bufs[..raw_bwr.write_size as usize];
        let read_buf = &bufs[raw_bwr.write_size as usize..];
        if read_buf.len() != raw_bwr.read_size as usize {
            return Err(anyhow!("BINDER_WRITE_READ data was truncated"));
        }

        Ok(Self {
            bwr: *raw_bwr,
            write_buffer: write_buf.into(),
            read_buffer: read_buf.into(),
        })
    }
}
