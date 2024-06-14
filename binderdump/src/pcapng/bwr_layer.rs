use binrw::binrw;

use crate::capture::events::BinderEventTransaction;

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
    bwr_type: BinderWriteReadType,
    write_size: u64,
    write_consumed: u64,
    write_buffer: u64,
    read_size: u64,
    read_consumed: u64,
    read_buffer: u64,
    #[brw(if(bwr_type.is_read()))]
    #[br(count = read_consumed)]
    read_data: Vec<u8>,

    #[brw(if(bwr_type.is_write()))]
    #[br(count = write_size)]
    write_data: Vec<u8>,

    #[brw(if(bwr_type.is_transaction()))]
    transaction: TransactionProtocol,
}

#[binrw]
#[derive(Default)]
pub struct TransactionProtocol {
    transaction: BinderEventTransaction,
    target_comm: [u8; 16],
    #[bw(calc = target_cmdline.len() as u16)]
    target_cmdline_length: u16,
    #[br(count = target_cmdline_length)]
    target_cmdline: Vec<u8>,
}