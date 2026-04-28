use binderdump_derive::{EpanProtocol, EpanProtocolEnum};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[repr(u8)]
#[derive(Default, Eq, PartialEq, Serialize_repr, Deserialize_repr, EpanProtocolEnum, Debug)]
pub enum BinderWriteReadType {
    #[default]
    Write = 0,
    Read,
}

impl BinderWriteReadType {
    pub fn is_read(&self) -> bool {
        match self {
            Self::Read => true,
            _ => false,
        }
    }

    pub fn is_write(&self) -> bool {
        !self.is_read()
    }
}

#[derive(Default, Serialize, Deserialize, EpanProtocol, Debug)]
pub struct BinderWriteReadProtocol {
    pub bwr_type: BinderWriteReadType,
    pub write_size: u64,
    pub write_consumed: u64,
    #[epan(display = Hex)]
    pub write_buffer: u64,
    pub read_size: u64,
    pub read_consumed: u64,
    #[epan(display = Hex)]
    pub read_buffer: u64,
    pub data: Vec<u8>,
    pub transaction: Option<TransactionProtocol>,
}

impl BinderWriteReadProtocol {
    pub fn is_read(&self) -> bool {
        self.bwr_type.is_read()
    }

    pub fn is_write(&self) -> bool {
        self.bwr_type.is_write()
    }

    pub fn is_transaction(&self) -> bool {
        self.transaction.is_some()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, EpanProtocol)]
pub struct Transaction {
    pub debug_id: i32,
    pub in_reply_to_debug_id: i32,
    pub target_node: i32,
    pub to_proc: i32,
    pub to_thread: i32,
    pub reply: i32,
    #[epan(display = SepSpace, ftype = Bytes)]
    pub code: u32,
    pub flags: u32,
}

#[derive(Default, Serialize, Deserialize, EpanProtocol, Debug)]
pub struct TransactionProtocol {
    pub debug_id: i32,
    pub in_reply_to_debug_id: i32,
    pub target_node: i32,
    pub to_proc: i32,
    pub to_thread: i32,
    pub reply: i32,
    #[epan(display = SepSpace, ftype = Bytes)]
    pub code: u32,
    pub flags: u32,

    #[epan(display = StrAsciis, ftype = String)]
    pub target_comm: [u8; 16],
    #[epan(display = StrAsciis, ftype = String)]
    pub target_cmdline: Vec<u8>,

    // Re-exported from the wire BC_TRANSACTION / BR_TRANSACTION command so all
    // transaction info shows up under TransactionProtocol without forcing the
    // user to dig into the Commands array.
    #[epan(display = Hex)]
    pub target_handle: u32,
    #[epan(display = Hex)]
    pub target_ptr: u64,
    #[epan(display = Hex)]
    pub cookie: u64,
    pub sender_pid: i32,
    pub sender_euid: u32,

    #[epan(display = SepSpace)]
    pub data: Vec<u8>,
    #[epan(display = SepSpace)]
    pub offsets: Vec<u8>,

    pub is_compat: bool,

    // Payloads of BINDER_TYPE_PTR scatter-gather buffers found by walking the
    // transaction's offsets array. The custom handler for `offsets` renders
    // them inline under `offsets[i].payload`, so we mark them `#[epan(skip)]`
    // to avoid duplicate Wireshark fields.
    #[epan(skip)]
    pub ptr_payloads: Vec<PtrPayload>,
}

#[derive(Default, Serialize, Deserialize, EpanProtocol, Debug)]
pub struct PtrPayload {
    pub offset_index: u32,
    #[epan(display = Hex)]
    pub buffer_addr: u64,
    pub total_size: u64,
    #[epan(display = SepSpace)]
    pub data: Vec<u8>,
}
