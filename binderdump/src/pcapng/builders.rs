use crate::capture::events::BinderEventIoctl;
use binderdump_structs::binder_types::{binder_ioctl, BinderInterface};
use binderdump_structs::bwr_layer::BinderWriteReadProtocol;
pub use binderdump_structs::event_layer::EventType;
use binderdump_structs::event_layer::{EventProtocol, IoctlProtocol};

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
        IoctlProtocol::new(
            self.fd,
            self.cmd,
            self.arg,
            self.result,
            self.uid,
            self.gid,
            self.ioctl_id,
            self.bwr,
        )
    }
}

#[derive(Default)]
pub struct EventProtocolBuilder {
    timestamp: u64,
    pid: i32,
    tid: i32,
    comm: Option<String>,
    event_type: EventType,
    binder_interface: BinderInterface,
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

    pub fn binder_interface(mut self, binder_interface: BinderInterface) -> Self {
        self.binder_interface = binder_interface;
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

        Ok(EventProtocol::new(
            self.timestamp,
            self.pid,
            self.tid,
            comm,
            self.event_type,
            self.binder_interface,
            self.cmdline.map(|s| s.into_bytes()).unwrap_or_default(),
            self.ioctl_data,
        ))
    }
}
