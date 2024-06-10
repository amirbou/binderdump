use crate::{
    binder::{binder_ioctl, binder_write_read},
    capture::process_cache::BinderType,
};
use binrw::binrw;

#[binrw]
pub struct EventLayer {
    pid: i32,
    tid: i32,
    comm: [u8; 16],
    binder_type: BinderType,
    event: u8,
    #[bw(calc = cmdline.len() as u16)]
    cmdline_length: u16,
    #[br(count = cmdline_length)]
    cmdline: Vec<u8>,
}

#[binrw]
pub struct SimpleIoctlProtocol {
    fd: i32,
    cmd: binder_ioctl,
    arg: u64,
    result: i32,
}
