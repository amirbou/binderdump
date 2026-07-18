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
    // #[epan(display = SepSpace, ftype = Bytes)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binder_serde::{de::from_bytes, ser::to_bytes};

    #[test]
    fn read_write_type_predicates() {
        assert!(BinderWriteReadType::Read.is_read());
        assert!(!BinderWriteReadType::Read.is_write());
        assert!(BinderWriteReadType::Write.is_write());
        assert!(!BinderWriteReadType::Write.is_read());
    }

    #[test]
    fn protocol_predicates_delegate_to_type_and_transaction() {
        let mut bwr = BinderWriteReadProtocol {
            bwr_type: BinderWriteReadType::Write,
            transaction: None,
            ..Default::default()
        };
        assert!(bwr.is_write());
        assert!(!bwr.is_read());
        assert!(!bwr.is_transaction());

        bwr.bwr_type = BinderWriteReadType::Read;
        bwr.transaction = Some(TransactionProtocol::default());
        assert!(bwr.is_read());
        assert!(bwr.is_transaction());
    }

    #[test]
    fn bwr_protocol_round_trips_through_binder_serde() {
        let bwr = BinderWriteReadProtocol {
            bwr_type: BinderWriteReadType::Read,
            write_size: 1,
            write_consumed: 2,
            write_buffer: 0xdead_beef,
            read_size: 3,
            read_consumed: 4,
            read_buffer: 0xfeed_face,
            data: vec![1, 2, 3, 4, 5],
            transaction: Some(TransactionProtocol {
                debug_id: 42,
                code: 7,
                data: vec![9, 9, 9],
                offsets: vec![0, 0, 0, 0],
                ..Default::default()
            }),
        };
        let bytes = to_bytes(&bwr).unwrap();
        let decoded: BinderWriteReadProtocol = from_bytes(&bytes).unwrap();
        // No PartialEq on the wire structs; re-serializing must reproduce the bytes.
        assert_eq!(bytes, to_bytes(&decoded).unwrap());
        assert!(decoded.is_read());
        assert!(decoded.is_transaction());
    }
}
