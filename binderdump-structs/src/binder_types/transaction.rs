use binderdump_derive::{ConstOffsets, EpanProtocol};
pub use binderdump_sys::binder_transaction_data;
use binderdump_trait::{
    ConstOffsets, EpanProtocol, FieldDisplay, FieldInfo, FieldOffset, FtEnum, StructOffset,
};
use plain::Plain;

unsafe impl Plain for Transaction {}
unsafe impl Plain for TransactionSg {}

// SG = Scatter Gather
#[derive(Debug, Clone, Copy, Default, EpanProtocol, ConstOffsets)]
#[repr(C)]
pub struct TransactionSg {
    transaction: Transaction,
    buffers_size: u64,
}

impl TransactionSg {
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Transaction {
    transaction_data: binder_transaction_data,
}

impl Transaction {
    pub fn data(&self) -> &binder_transaction_data {
        &self.transaction_data
    }
}

impl Default for Transaction {
    fn default() -> Self {
        let transaction_data = unsafe { std::mem::zeroed::<binder_transaction_data>() };
        Self { transaction_data }
    }
}

fn concat_abbrev(abbrev: &String, suffix: &str) -> String {
    let mut abbrev = abbrev.clone();
    abbrev.push('.');
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

macro_rules! txn_field_offset {
    ($base:expr, $name:ident, $ty:ty) => {
        FieldOffset {
            field_name: std::borrow::Cow::Borrowed(stringify!($name)),
            offset: $base + core::mem::offset_of!(binder_transaction_data, $name),
            size: std::mem::size_of::<$ty>(),
            inner_struct: None,
        }
    };
}

impl ConstOffsets for Transaction {
    fn get_offsets(base: usize) -> Option<StructOffset> {
        Some(StructOffset {
            name: "Transaction",
            offset: base,
            size: std::mem::size_of::<Self>(),
            fields: vec![
                FieldOffset {
                    field_name: std::borrow::Cow::Borrowed("target.handle"),
                    offset: base
                        + core::mem::offset_of!(binder_transaction_data, target)
                        + core::mem::offset_of!(
                            binderdump_sys::binder_transaction_data__bindgen_ty_1,
                            handle
                        ),
                    size: std::mem::size_of::<u32>(),
                    inner_struct: None,
                },
                FieldOffset {
                    field_name: std::borrow::Cow::Borrowed("target.ptr"),
                    offset: base
                        + core::mem::offset_of!(binder_transaction_data, target)
                        + core::mem::offset_of!(
                            binderdump_sys::binder_transaction_data__bindgen_ty_1,
                            ptr
                        ),
                    size: std::mem::size_of::<u64>(),
                    inner_struct: None,
                },
                txn_field_offset!(base, cookie, u64),
                txn_field_offset!(base, code, u32),
                txn_field_offset!(base, flags, u32),
                txn_field_offset!(base, sender_pid, i32),
                txn_field_offset!(base, sender_euid, u32),
                txn_field_offset!(base, data_size, u64),
                txn_field_offset!(base, offsets_size, u64),
                FieldOffset {
                    field_name: std::borrow::Cow::Borrowed("data.ptr.buffer"),
                    offset: base
                        + core::mem::offset_of!(binder_transaction_data, data)
                        + core::mem::offset_of!(
                            binderdump_sys::binder_transaction_data__bindgen_ty_2,
                            ptr
                        )
                        + core::mem::offset_of!(
                            binderdump_sys::binder_transaction_data__bindgen_ty_2__bindgen_ty_1,
                            buffer
                        ),
                    size: std::mem::size_of::<u64>(),
                    inner_struct: None,
                },
                FieldOffset {
                    field_name: std::borrow::Cow::Borrowed("data.ptr.offsets"),
                    offset: base
                        + core::mem::offset_of!(binder_transaction_data, data)
                        + core::mem::offset_of!(
                            binderdump_sys::binder_transaction_data__bindgen_ty_2,
                            ptr
                        )
                        + core::mem::offset_of!(
                            binderdump_sys::binder_transaction_data__bindgen_ty_2__bindgen_ty_1,
                            offsets
                        ),
                    size: std::mem::size_of::<u64>(),
                    inner_struct: None,
                },
                FieldOffset {
                    field_name: std::borrow::Cow::Borrowed("data.buf"),
                    offset: base
                        + core::mem::offset_of!(binder_transaction_data, data)
                        + core::mem::offset_of!(
                            binderdump_sys::binder_transaction_data__bindgen_ty_2,
                            buf
                        ),
                    size: std::mem::size_of::<[u8; 8usize]>(),
                    inner_struct: None,
                },
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Transaction, TransactionSg};
    use binderdump_trait::{ConstOffsets, EpanProtocol};

    #[test]
    fn default_transaction_is_zeroed_and_accessible() {
        let txn = Transaction::default();
        assert_eq!(txn.data().code, 0);
        assert_eq!(txn.data().flags, 0);
    }

    #[test]
    fn transaction_sg_exposes_its_inner_transaction() {
        let sg = TransactionSg::default();
        assert_eq!(sg.transaction().data().code, 0);
    }

    #[test]
    fn get_info_registers_all_transaction_fields() {
        let info = Transaction::get_info(
            "Transaction".into(),
            "binder.transaction".into(),
            None,
            None,
        );
        assert_eq!(info.len(), 12);
        // abbrevs are the parent abbrev joined with the field name.
        assert!(info
            .iter()
            .any(|f| f.abbrev == "binder.transaction.target.handle"));
    }

    #[test]
    fn const_offsets_cover_all_transaction_fields() {
        let offsets = Transaction::get_offsets(0).expect("Transaction has offsets");
        assert_eq!(offsets.name, "Transaction");
        assert_eq!(offsets.size, std::mem::size_of::<Transaction>());
        assert_eq!(offsets.fields.len(), 12);
    }
}
