use crate::binder_types::{binder_ioctl, BinderInterface};
// use capture::events::BinderEventIoctl};
use binrw::binrw;

use super::bwr_layer::BinderWriteReadProtocol;
use super::PosRWValue;

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
    timestamp: PosRWValue<u64>,
    pid: PosRWValue<i32>,
    tid: PosRWValue<i32>,
    comm: PosRWValue<[u8; 16]>,
    event_type: PosRWValue<EventType>,
    binder_interface: PosRWValue<BinderInterface>,
    #[bw(calc = (cmdline.len() as u16).into())]
    cmdline_length: PosRWValue<u16>,
    #[br(count = *cmdline_length)]
    cmdline: PosRWValue<Vec<u8>>,
    #[br(if(event_type != EventType::DeadProcess))]
    #[bw(if(*event_type != EventType::DeadProcess))]
    ioctl_data: PosRWValue<IoctlProtocol>,
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
            timestamp: timestamp.into(),
            pid: pid.into(),
            tid: tid.into(),
            comm: comm.into(),
            event_type: event_type.into(),
            binder_interface: binder_interface.into(),
            cmdline: cmdline.into(),
            ioctl_data: ioctl_data.into(),
        }
    }

    pub fn binder_interface(&self) -> BinderInterface {
        *self.binder_interface
    }

    pub fn timestamp(&self) -> u64 {
        *self.timestamp
    }
}

#[binrw]
#[derive(Default)]
pub struct IoctlProtocol {
    fd: PosRWValue<i32>,
    cmd: PosRWValue<binder_ioctl>,
    arg: PosRWValue<u64>,
    result: PosRWValue<i32>,
    uid: PosRWValue<u32>,
    gid: PosRWValue<u32>,
    ioctl_id: PosRWValue<u64>,
    #[br(if(cmd == binder_ioctl::BINDER_WRITE_READ))]
    #[bw(if(*cmd == binder_ioctl::BINDER_WRITE_READ))]
    bwr: PosRWValue<BinderWriteReadProtocol>,
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
            fd: fd.into(),
            cmd: cmd.into(),
            arg: arg.into(),
            result: result.into(),
            uid: uid.into(),
            gid: gid.into(),
            ioctl_id: ioctl_id.into(),
            bwr: bwr.into(),
        }
    }

    pub fn fd(&self) -> i32 {
        *self.fd
    }
}
