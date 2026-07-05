use crate::capture::events::{
    BinderEventIoctl, BinderEventWriteRead, BinderTransactionContents, BinderTransactionData,
    BinderTransactionPtrChunk, BinderTransactionStack,
};
use crate::capture::process_cache::ProcessCache;
use anyhow::{Context, Ok};
use binderdump_structs::binder_types::transaction::binder_transaction_data;
use binderdump_structs::binder_types::{binder_ioctl, BinderInterface};
use binderdump_structs::bwr_layer::{
    BinderWriteReadProtocol, BinderWriteReadType, PtrPayload, Transaction, TransactionProtocol,
};
pub use binderdump_structs::event_layer::EventType;
use binderdump_structs::event_layer::{EventProtocol, IoctlProtocol};
use std::collections::BTreeMap;

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
    read_only: bool,
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
        self.read_only = event.read_only;
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
                self.read_only,
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
    android_sdk: u32,
    cmdline: Option<String>,
    ioctl_data: Option<IoctlProtocol>,
}

impl EventProtocolBuilder {
    pub fn new(timestamp: u64, pid: i32, tid: i32, android_sdk: u32) -> Self {
        Self {
            timestamp,
            pid,
            tid,
            android_sdk,
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
            self.android_sdk,
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
    txn_stack: Option<BinderTransactionStack>,
    data: Option<BinderTransactionData>,
    offsets: Option<BinderTransactionData>,
    command_data: Option<binder_transaction_data>,
    is_compat: bool,
    // Reassembly buffer for PTR scatter-gather payloads. Keyed by offset_index
    // (one entry in `offsets` may span multiple chunks if its `length` exceeds
    // MAX_PTR_PAYLOAD); inner BTreeMap is keyed by chunk_index to keep ordering.
    ptr_payloads: BTreeMap<u32, PtrPayloadAccum>,
}

#[derive(Default)]
struct PtrPayloadAccum {
    buffer_addr: u64,
    total_size: u64,
    chunks: BTreeMap<u32, Vec<u8>>,
}

impl TransactionProtocolBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> Option<TransactionProtocol> {
        let mut txn = self.txn?;

        if let Some(data) = self.data {
            txn.data = data.data;
        }

        if let Some(offsets) = self.offsets {
            txn.offsets = offsets.data;
        }

        match self.txn_stack {
            Some(txn_stack) => {
                // Validate the transaction stack matches the transaction
                txn.in_reply_to_debug_id = txn_stack.request_debug_id;
            }
            None => (),
        }

        if let Some(cmd) = self.command_data {
            // SAFETY: target is a tagged union of (handle: u32, ptr: u64). Reading
            // both members is sound for any binder_transaction_data — the union is
            // 8 bytes of plain old data, not a Rust enum.
            unsafe {
                txn.target_handle = cmd.target.handle;
                txn.target_ptr = cmd.target.ptr;
            }
            txn.cookie = cmd.cookie;
            txn.sender_pid = cmd.sender_pid;
            txn.sender_euid = cmd.sender_euid;
        }

        txn.is_compat = self.is_compat;

        // move the accumulated scatter-gather payloads onto the wire struct;
        // concatenate each entry's chunks in chunk_index order.
        txn.ptr_payloads = self
            .ptr_payloads
            .into_iter()
            .map(|(offset_index, accum)| PtrPayload {
                offset_index,
                buffer_addr: accum.buffer_addr,
                total_size: accum.total_size,
                data: accum.chunks.into_values().flatten().collect(),
            })
            .collect();

        Some(txn)
    }

    pub fn is_compat(mut self, is_compat: bool) -> Self {
        self.is_compat = is_compat;
        self
    }

    pub fn ptr_payload_chunk(mut self, chunk: BinderTransactionPtrChunk) -> Self {
        let entry = self.ptr_payloads.entry(chunk.offset_index).or_default();
        entry.buffer_addr = chunk.buffer_addr;
        entry.total_size = chunk.total_size;
        entry.chunks.insert(chunk.chunk_index, chunk.data);
        self
    }

    pub fn command_data(mut self, data: binder_transaction_data) -> Self {
        self.command_data = Some(data);
        self
    }

    pub fn transaction(
        mut self,
        txn: Transaction,
        procs: &mut ProcessCache,
    ) -> anyhow::Result<Self> {
        if self.txn.is_some() {
            return Err(anyhow::anyhow!("Transaction already set!"));
        }

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
            debug_id: txn.debug_id,
            in_reply_to_debug_id: txn.in_reply_to_debug_id,
            target_node: txn.target_node,
            to_proc: txn.to_proc,
            to_thread: txn.to_thread,
            reply: txn.reply,
            code: txn.code,
            flags: txn.flags,
            target_comm: comm,
            target_cmdline: proc_info.get_cmdline().to_string().into_bytes(),
            ..Default::default()
        });
        self.validate_transaction_stack()?;

        Ok(self)
    }

    pub fn transcation_contents(mut self, txn: BinderTransactionContents) -> anyhow::Result<Self> {
        match txn {
            BinderTransactionContents::Data(txn) => match self.data {
                Some(existing_data) => {
                    if existing_data.chunk_index + 1 != txn.chunk_index {
                        return Err(anyhow::anyhow!(
                            "Out of order transaction data chunks: existing {}, new {}",
                            existing_data.chunk_index,
                            txn.chunk_index
                        ));
                    }
                    if existing_data.total_size != txn.total_size {
                        return Err(anyhow::anyhow!(
                            "Mismatched transaction data total_size: existing {}, new {}",
                            existing_data.total_size,
                            txn.total_size
                        ));
                    }

                    let mut combined_data = existing_data.data;
                    combined_data.extend_from_slice(&txn.data);
                    self.data = Some(BinderTransactionData {
                        total_size: existing_data.total_size,
                        data: combined_data,
                        chunk_index: txn.chunk_index,
                    });
                }
                None => self.data = Some(txn),
            },
            BinderTransactionContents::Offsets(txn) => self.offsets = Some(txn),
        }
        Ok(self)
    }

    fn validate_transaction_stack(&self) -> anyhow::Result<()> {
        if self.txn_stack.is_none() {
            return Ok(());
        }
        if self.txn.is_none() {
            return Ok(());
        }

        let txn = self.txn.as_ref().unwrap();
        let txn_stack = self.txn_stack.as_ref().unwrap();

        if txn.debug_id != txn_stack.reply_debug_id {
            return Err(anyhow::anyhow!(
                "Transaction debug_id {} does not match transaction stack reply_debug_id {}",
                txn.debug_id,
                txn_stack.reply_debug_id
            ));
        }

        Ok(())
    }

    pub fn transaction_stack(mut self, txn_stack: BinderTransactionStack) -> anyhow::Result<Self> {
        self.txn_stack = Some(txn_stack);
        self.validate_transaction_stack()?;

        Ok(self)
    }
}
