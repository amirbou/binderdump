use super::bwr_layer::BinderWriteReadProtocol;
use crate::binder_types::{binder_ioctl, BinderInterface};
use binderdump_derive::{EpanProtocol, EpanProtocolEnum};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[repr(u8)]
#[derive(PartialEq, Eq, Default, Serialize_repr, Deserialize_repr, EpanProtocolEnum, Debug)]
pub enum EventType {
    FinishedIoctl = 0,
    SplitIoctl = 1,
    DeadProcess = 2,
    DeadThread = 3,
    #[default]
    Invalid = 4,
}

#[derive(Default, Serialize, Deserialize, EpanProtocol, Debug)]
pub struct EventProtocol {
    pub timestamp: u64,
    pub pid: i32,
    pub tid: i32,
    #[epan(display = StrAsciis, ftype = String)]
    pub comm: [u8; 16],
    pub event_type: EventType,
    pub binder_interface: BinderInterface,
    pub android_sdk: u32,
    #[epan(display = StrAsciis, ftype = String)]
    pub cmdline: Vec<u8>,
    pub ioctl_data: Option<IoctlProtocol>,
}

impl EventProtocol {
    pub fn new(
        timestamp: u64,
        pid: i32,
        tid: i32,
        comm: [u8; 16],
        event_type: EventType,
        binder_interface: BinderInterface,
        android_sdk: u32,
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
            android_sdk,
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

    pub fn android_sdk(&self) -> u32 {
        self.android_sdk
    }
}

#[derive(Default, Serialize, Deserialize, EpanProtocol, Debug)]
pub struct IoctlProtocol {
    pub fd: i32,
    pub cmd: binder_ioctl,
    #[epan(display = Hex)]
    pub arg: u64,
    pub result: i32,
    pub uid: u32,
    pub gid: u32,
    pub ioctl_id: u64,
    pub read_only: bool,
    pub bwr: Option<BinderWriteReadProtocol>,
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
        read_only: bool,
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
            read_only,
            bwr,
        }
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binder_serde::{de::from_bytes, ser::to_bytes};
    use crate::binder_types::binder_ioctl;

    fn comm(name: &[u8]) -> [u8; 16] {
        let mut c = [0u8; 16];
        c[..name.len()].copy_from_slice(name);
        c
    }

    #[test]
    fn ioctl_protocol_new_exposes_fd() {
        let ioctl = IoctlProtocol::new(
            7,
            binder_ioctl::BINDER_WRITE_READ,
            0xcafe,
            0,
            1000,
            1000,
            42,
            false,
            None,
        );
        assert_eq!(ioctl.fd(), 7);
    }

    #[test]
    fn event_protocol_round_trips_and_accessors_read_back() {
        let ioctl = IoctlProtocol::new(
            3,
            binder_ioctl::BINDER_WRITE_READ,
            0x1000,
            0,
            0,
            0,
            99,
            true,
            None,
        );
        let event = EventProtocol::new(
            123_456,
            111,
            222,
            comm(b"system_server"),
            EventType::FinishedIoctl,
            BinderInterface::HWBINDER,
            34,
            b"/system/bin/foo".to_vec(),
            Some(ioctl),
        );

        let bytes = to_bytes(&event).unwrap();
        let decoded: EventProtocol = from_bytes(&bytes).unwrap();

        // No PartialEq on the wire structs; re-serializing must reproduce bytes.
        assert_eq!(bytes, to_bytes(&decoded).unwrap());
        assert_eq!(decoded.timestamp(), 123_456);
        assert_eq!(decoded.android_sdk(), 34);
        assert!(matches!(
            decoded.binder_interface(),
            BinderInterface::HWBINDER
        ));
        assert_eq!(decoded.ioctl_data.as_ref().unwrap().fd(), 3);
    }

    #[test]
    fn event_protocol_round_trips_without_ioctl_data() {
        let event = EventProtocol::new(
            1,
            2,
            3,
            comm(b"init"),
            EventType::DeadThread,
            BinderInterface::BINDER,
            0,
            Vec::new(),
            None,
        );
        let bytes = to_bytes(&event).unwrap();
        let decoded: EventProtocol = from_bytes(&bytes).unwrap();
        assert_eq!(bytes, to_bytes(&decoded).unwrap());
        assert!(decoded.ioctl_data.is_none());
    }
}
