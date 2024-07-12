use crate::capture::events::{BinderEventIoctl, BinderEventWriteRead};
use crate::capture::process_cache::ProcessCache;
use anyhow::Context;
use binderdump_structs::binder_types::{binder_ioctl, BinderInterface};
use binderdump_structs::bwr_layer::{
    BinderWriteReadProtocol, BinderWriteReadType, Transaction, TransactionProtocol,
};
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
    non_empty: bool,
}

impl IoctlProtocolBuilder {
    pub fn with_ioctl_event(mut self, event: &BinderEventIoctl) -> Self {
        self.fd = event.fd;
        self.uid = event.uid;
        self.gid = event.gid;
        self.cmd = event.cmd;
        self.arg = event.arg;
        self.ioctl_id = event.ioctl_id;
        self.non_empty = true;
        self
    }

    pub fn bwr(mut self, bwr: Option<BinderWriteReadProtocol>) -> Self {
        self.bwr = bwr;
        self.non_empty = true;
        self
    }

    pub fn result(mut self, result: i32) -> Self {
        self.result = result;
        // TODO - is this correct? if we only have result, we missed the start of the ioctl
        // self.non_empty = true;
        self
    }

    pub fn build(self) -> Option<IoctlProtocol> {
        if self.non_empty {
            Some(IoctlProtocol::new(
                self.fd,
                self.cmd,
                self.arg,
                self.result,
                self.uid,
                self.gid,
                self.ioctl_id,
                self.bwr,
            ))
        } else {
            None
        }
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

    pub fn ioctl_data(mut self, ioctl_data: Option<IoctlProtocol>) -> Self {
        self.ioctl_data = ioctl_data;
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

#[derive(Default)]
pub struct BinderWriteReadProtocolBuilder {
    bwr: Option<BinderWriteReadProtocol>,
}

impl BinderWriteReadProtocolBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> Option<BinderWriteReadProtocol> {
        self.bwr
    }

    pub fn bwr_event(mut self, event: BinderEventWriteRead) -> anyhow::Result<Self> {
        let mut bwr = BinderWriteReadProtocol::default();

        let data = match event {
            BinderEventWriteRead::BinderEventRead(br) => {
                bwr.bwr_type = BinderWriteReadType::Read;
                br
            }
            BinderEventWriteRead::BinderEventWrite(bw) => {
                bwr.bwr_type = BinderWriteReadType::Write;
                bw
            }
        };
        let bwr_info = data.get_bwr();

        bwr.write_size = bwr_info.write_size;
        bwr.write_consumed = bwr_info.write_consumed;
        bwr.write_buffer = bwr_info.write_buffer;

        bwr.read_size = bwr_info.read_size;
        bwr.read_consumed = bwr_info.read_consumed;
        bwr.read_buffer = bwr_info.read_buffer;

        bwr.data = data.take_data();

        self.bwr = Some(bwr);
        Ok(self)
    }

    pub fn transaction(mut self, txn: Option<TransactionProtocol>) -> anyhow::Result<Self> {
        if txn.is_none() {
            return Ok(self);
        }
        let bwr = self.bwr.as_mut().ok_or(anyhow::anyhow!(
            "Tried to add transaction to an empty BinderWriteReadProtocol"
        ))?;
        bwr.transaction = txn;
        Ok(self)
    }
}

#[derive(Default)]
pub struct TransactionProtocolBuilder {
    txn: Option<TransactionProtocol>,
}

impl TransactionProtocolBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> Option<TransactionProtocol> {
        self.txn
    }

    pub fn transaction(
        mut self,
        txn: Transaction,
        procs: &mut ProcessCache,
    ) -> anyhow::Result<Self> {
        let to_thread = if txn.to_thread > 0 {
            txn.to_thread
        } else {
            txn.to_proc
        };
        let proc_info = procs
            .get_proc(txn.to_proc, to_thread, None)
            .context(format!("failed to get target process for txn: {:?}", txn))?;

        let comm = proc_info.get_comm();
        let mut comm_vec = comm.to_string().into_bytes();
        comm_vec.resize(16, 0);
        let comm: [u8; 16] = comm_vec.try_into().or(Err(anyhow::anyhow!(
            "failed to convert comm String to [u8; 16]"
        )))?;

        self.txn = Some(TransactionProtocol {
            transaction: txn,
            target_comm: comm,
            target_cmdline: proc_info.get_cmdline().to_string().into_bytes(),
        });

        Ok(self)
    }
}
