use std::{default, ffi::CString};

use crate::{
    binder::{binder_ioctl, binder_write_read},
    capture::{events::BinderEventIoctl, process_cache::BinderType},
};
use binrw::binrw;
use libbpf_rs::ErrorExt;

use super::bwr_layer::BinderWriteReadProtocol;

#[binrw]
#[brw(repr = u8)]
#[derive(PartialEq, Eq, Default)]
pub enum EventType {
    FinishedIoctl = 0,
    SplitIoctl = 1,
    DeadProcess = 2,
    #[default]
    Invalid = 4,
}

#[binrw]
#[derive(Default)]
pub struct EventProtocol {
    timestamp: u64,
    pid: i32,
    tid: i32,
    comm: [u8; 16],
    event_type: EventType,
    binder_type: BinderType,
    #[bw(calc = cmdline.len() as u16)]
    cmdline_length: u16,
    #[br(count = cmdline_length)]
    cmdline: Vec<u8>,
    #[br(if(event_type != EventType::DeadProcess))]
    #[bw(if(*event_type != EventType::DeadProcess))]
    ioctl_data: IoctlProtocol,
}

impl EventProtocol {
    pub fn builder(timestamp: u64, pid: i32, tid: i32) -> EventProtocolBuilder {
        EventProtocolBuilder::new(timestamp, pid, tid)
    }

    pub fn binder_type(&self) -> BinderType {
        self.binder_type
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

#[derive(Default)]
pub struct EventProtocolBuilder {
    timestamp: u64,
    pid: i32,
    tid: i32,
    comm: Option<String>,
    event_type: EventType,
    binder_type: BinderType,
    cmdline: Option<String>,
    ioctl_data: Option<IoctlProtocol>,
}

impl EventProtocolBuilder {
    pub fn new(timestamp: u64, pid: i32, tid: i32) -> Self {
        Self {
            timestamp,
            pid,
            tid,
            ..Default::default()
        }
    }

    pub fn comm(mut self, comm: String) -> Self {
        self.comm = Some(comm);
        self
    }

    pub fn event_type(mut self, event_type: EventType) -> Self {
        self.event_type = event_type;
        self
    }

    pub fn binder_type(mut self, binder_type: BinderType) -> Self {
        self.binder_type = binder_type;
        self
    }

    pub fn cmdline(mut self, cmdline: String) -> Self {
        self.cmdline = Some(cmdline);
        self
    }

    pub fn ioctl_data(mut self, ioctl_data: IoctlProtocol) -> Self {
        self.ioctl_data = Some(ioctl_data);
        self
    }

    pub fn build(self) -> anyhow::Result<EventProtocol> {
        let mut comm_vec = self.comm.unwrap_or_default().into_bytes();
        comm_vec.resize(16, 0);
        let comm: [u8; 16] = comm_vec.try_into().or(Err(anyhow::anyhow!(
            "failed to convert comm String to [u8; 16]"
        )))?;

        Ok(EventProtocol {
            timestamp: self.timestamp,
            pid: self.pid,
            tid: self.tid,
            comm: comm,
            event_type: self.event_type,
            binder_type: self.binder_type,
            cmdline: self.cmdline.map(|s| s.into_bytes()).unwrap_or_default(),
            ioctl_data: self.ioctl_data.unwrap_or_default(),
        })
    }
}

#[binrw]
#[derive(Default)]
pub struct IoctlProtocol {
    fd: i32,
    cmd: binder_ioctl,
    arg: u64,
    result: i32,
    uid: u32,
    gid: u32,
    ioctl_id: u64,
    #[br(if(cmd == binder_ioctl::BINDER_WRITE_READ))]
    #[bw(if(*cmd == binder_ioctl::BINDER_WRITE_READ))]
    bwr: BinderWriteReadProtocol,
}

impl IoctlProtocol {
    pub fn builder() -> IoctlProtocolBuilder {
        IoctlProtocolBuilder::default()
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }
}

#[derive(Default)]
pub struct IoctlProtocolBuilder {
    fd: i32,
    cmd: binder_ioctl,
    arg: u64,
    result: i32,
    uid: u32,
    gid: u32,
    ioctl_id: u64,
    bwr: Option<BinderWriteReadProtocol>,
}

impl IoctlProtocolBuilder {
    pub fn with_ioctl_event(mut self, event: &BinderEventIoctl) -> Self {
        self.fd = event.fd;
        self.uid = event.uid;
        self.gid = event.gid;
        self.cmd = event.cmd;
        self.arg = event.arg;
        self.ioctl_id = event.ioctl_id;
        self
    }

    pub fn bwr(mut self, bwr: BinderWriteReadProtocol) -> Self {
        self.bwr = Some(bwr);
        self
    }

    pub fn result(mut self, result: i32) -> Self {
        self.result = result;
        self
    }

    pub fn build(self) -> IoctlProtocol {
        IoctlProtocol {
            fd: self.fd,
            cmd: self.cmd,
            arg: self.arg,
            result: self.result,
            uid: self.uid,
            gid: self.gid,
            ioctl_id: self.ioctl_id,
            bwr: self.bwr.unwrap_or_default(),
        }
    }
}
