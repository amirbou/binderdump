use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[repr(u8)]
#[derive(Default, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum BinderWriteReadType {
    #[default]
    Write = 0,
    Read,
    WriteTransaction,
    ReadTransaction,
}

impl BinderWriteReadType {
    pub fn is_read(&self) -> bool {
        match self {
            Self::Read | Self::ReadTransaction => true,
            _ => false,
        }
    }

    pub fn is_write(&self) -> bool {
        !self.is_read()
    }

    pub fn is_transaction(&self) -> bool {
        match self {
            BinderWriteReadType::WriteTransaction | BinderWriteReadType::ReadTransaction => true,
            _ => false,
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct BinderWriteReadProtocol {
    bwr_type: BinderWriteReadType,
    write_size: u64,
    write_consumed: u64,
    write_buffer: u64,
    read_size: u64,
    read_consumed: u64,
    read_buffer: u64,
    data: Vec<u8>,
    transaction: Option<TransactionProtocol>,
}

impl BinderWriteReadProtocol {
    pub fn is_read(&self) -> bool {
        self.bwr_type.is_read()
    }

    pub fn is_write(&self) -> bool {
        self.bwr_type.is_write()
    }

    pub fn is_transaction(&self) -> bool {
        self.bwr_type.is_transaction()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Transaction {
    debug_id: i32,
    target_node: i32,
    to_proc: i32,
    to_thread: i32,
    reply: i32,
    code: u32,
    flags: u32,
}

#[derive(Default, Serialize, Deserialize)]
pub struct TransactionProtocol {
    transaction: Transaction,
    target_comm: [u8; 16],
    target_cmdline: Vec<u8>,
}
