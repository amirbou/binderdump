use crate::PosRWValue;
use binrw::binrw;

#[binrw]
#[brw(repr(u8))]
#[derive(Default, Eq, PartialEq)]
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

#[binrw]
#[derive(Default)]
pub struct BinderWriteReadProtocol {
    bwr_type: PosRWValue<BinderWriteReadType>,
    write_size: PosRWValue<u64>,
    write_consumed: PosRWValue<u64>,
    write_buffer: PosRWValue<u64>,
    read_size: PosRWValue<u64>,
    read_consumed: PosRWValue<u64>,
    read_buffer: PosRWValue<u64>,
    #[brw(if(bwr_type.is_read()))]
    #[br(count = *read_consumed)]
    read_data: PosRWValue<Vec<u8>>,

    #[brw(if(bwr_type.is_write()))]
    #[br(count = *write_size)]
    write_data: PosRWValue<Vec<u8>>,

    #[brw(if(bwr_type.is_transaction()))]
    transaction: PosRWValue<TransactionProtocol>,
}

#[binrw]
#[derive(Debug, Clone, Default)]
pub struct Transaction {
    debug_id: i32,
    target_node: i32,
    to_proc: i32,
    to_thread: i32,
    reply: i32,
    code: u32,
    flags: u32,
}

#[binrw]
#[derive(Default)]
pub struct TransactionProtocol {
    transaction: PosRWValue<Transaction>,
    target_comm: PosRWValue<[u8; 16]>,
    #[bw(calc = (target_cmdline.len() as u16).into())]
    target_cmdline_length: PosRWValue<u16>,
    #[br(count = *target_cmdline_length)]
    target_cmdline: PosRWValue<Vec<u8>>,
}
