use binderdump_derive::EpanProtocol;
pub use binderdump_sys::binder_transaction_data;
use binderdump_trait::{EpanProtocol, FieldDisplay, FieldInfo, FtEnum};
use plain::Plain;

unsafe impl Plain for Transaction {}
unsafe impl Plain for TransactionSg {}

// SG = Scatter Gather
#[derive(Debug, Clone, Copy, Default, EpanProtocol)]
#[repr(C)]
pub struct TransactionSg {
    transaction: Transaction,
    buffers_size: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Transaction {
    transaction_data: binder_transaction_data,
}

impl Default for Transaction {
    fn default() -> Self {
        let transaction_data = unsafe { std::mem::zeroed::<binder_transaction_data>() };
        Self { transaction_data }
    }
}

fn concat_abbrev(abbrev: &String, suffix: &str) -> String {
    let mut abbrev = abbrev.clone();
    abbrev.push_str(suffix);
    abbrev
}

macro_rules! txn_field_info {
    ($abbrev:expr, $name:literal, $ftype:ident, $display:ident) => {
        FieldInfo {
            name: $name.into(),
            abbrev: concat_abbrev(&$abbrev, $name),
            ftype: FtEnum::$ftype,
            display: FieldDisplay::$display,
            strings: None,
        }
    };
}

impl EpanProtocol for Transaction {
    fn get_info(
        _name: String,
        abbrev: String,
        _ftype: Option<binderdump_trait::FtEnum>,
        _display: Option<binderdump_trait::FieldDisplay>,
    ) -> Vec<binderdump_trait::FieldInfo> {
        vec![
            txn_field_info!(abbrev, "target.handle", U32, Dec),
            txn_field_info!(abbrev, "target.ptr", U64, Hex),
            txn_field_info!(abbrev, "cookie", U64, Hex),
            txn_field_info!(abbrev, "code", U32, DecHex),
            txn_field_info!(abbrev, "flags", U32, Hex), // TODO - bitfield
            txn_field_info!(abbrev, "sender_pid", I32, Dec),
            txn_field_info!(abbrev, "sender_euid", U32, Dec),
            txn_field_info!(abbrev, "data_size", U64, Dec),
            txn_field_info!(abbrev, "offsets_size", U64, Dec),
            txn_field_info!(abbrev, "data.ptr.buffer", U64, Hex),
            txn_field_info!(abbrev, "data.ptr.offsets", U64, Hex),
            txn_field_info!(abbrev, "data.buf", Bytes, SepSpace),
        ]
    }
}
