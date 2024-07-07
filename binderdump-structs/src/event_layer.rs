use super::bwr_layer::BinderWriteReadProtocol;
use crate::binder_types::{binder_ioctl, BinderInterface};
use binderdump_derive::{EpanProtocol, EpanProtocolEnum};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[repr(u8)]
#[derive(PartialEq, Eq, Default, Serialize_repr, Deserialize_repr, EpanProtocolEnum)]
pub enum EventType {
    FinishedIoctl = 0,
    SplitIoctl = 1,
    DeadProcess = 2,
    #[default]
    Invalid = 4,
}

#[derive(Default, Serialize, Deserialize, EpanProtocol)]
pub struct EventProtocol {
    timestamp: u64,
    pid: i32,
    tid: i32,
    #[epan(display = StrAsciis, ftype = String)]
    comm: [u8; 16],
    event_type: EventType,
    binder_interface: BinderInterface,
    #[epan(display = StrAsciis, ftype = String)]
    cmdline: Vec<u8>,
    ioctl_data: Option<IoctlProtocol>,
}

impl EventProtocol {
    pub fn new(
        timestamp: u64,
        pid: i32,
        tid: i32,
        comm: [u8; 16],
        event_type: EventType,
        binder_interface: BinderInterface,
        cmdline: Vec<u8>,
        ioctl_data: Option<IoctlProtocol>,
    ) -> Self {
        Self {
            timestamp,
            pid,
            tid,
            comm,
            event_type,
            binder_interface,
            cmdline,
            ioctl_data,
        }
    }

    pub fn binder_interface(&self) -> BinderInterface {
        self.binder_interface
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

#[derive(Default, Serialize, Deserialize, EpanProtocol)]
pub struct IoctlProtocol {
    fd: i32,
    cmd: binder_ioctl,
    arg: u64,
    result: i32,
    uid: u32,
    gid: u32,
    ioctl_id: u64,
    bwr: Option<BinderWriteReadProtocol>,
}

impl IoctlProtocol {
    pub fn new(
        fd: i32,
        cmd: binder_ioctl,
        arg: u64,
        result: i32,
        uid: u32,
        gid: u32,
        ioctl_id: u64,
        bwr: Option<BinderWriteReadProtocol>,
    ) -> Self {
        Self {
            fd,
            cmd,
            arg,
            result,
            uid,
            gid,
            ioctl_id,
            bwr,
        }
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }
}
