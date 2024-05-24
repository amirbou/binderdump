use crate::binder::binder_ioctl;
use crate::capture::common_types;
#[allow(non_camel_case_types)]
#[derive(Debug)]
#[repr(u32)]
pub enum binder_process_state {
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
}

#[derive(Debug)]
pub enum BinderEventData {
    BinderInvalidate,
    BinderIoctl(BinderEventIoctl),
}

#[derive(Debug)]
pub struct BinderEvent {
    tid: i32,
    timestamp: u64,
    data: BinderEventData,
}

#[derive(Debug)]
pub struct BinderEventIoctl {
    fd: i32,
    cmd: binder_ioctl,
    arg: u64,
}

impl TryFrom<common_types::binder_event_ioctl> for BinderEventIoctl {
    type Error = anyhow::Error;

    fn try_from(value: common_types::binder_event_ioctl) -> Result<Self, Self::Error> {
        todo!()
    }
}
