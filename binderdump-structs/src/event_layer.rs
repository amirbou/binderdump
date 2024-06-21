use crate::binder_types::{binder_ioctl, BinderInterface};
// use capture::events::BinderEventIoctl};
use binrw::binrw;

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
    binder_interface: BinderInterface,
    #[bw(calc = cmdline.len() as u16)]
    cmdline_length: u16,
    #[br(count = cmdline_length)]
    cmdline: Vec<u8>,
    #[br(if(event_type != EventType::DeadProcess))]
    #[bw(if(*event_type != EventType::DeadProcess))]
    ioctl_data: IoctlProtocol,
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
        ioctl_data: IoctlProtocol,
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
    pub fn new(
        fd: i32,
        cmd: binder_ioctl,
        arg: u64,
        result: i32,
        uid: u32,
        gid: u32,
        ioctl_id: u64,
        bwr: BinderWriteReadProtocol,
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
