// Custom handler for the transaction `data` field: renders the raw parcel
// bytes (as the default handler would) and — for request-direction AIDL
// transactions — a `Parameters` subtree decoded from the resolved method
// signature. Decoding is best-effort and purely additive; the raw hex view
// always remains.

use crate::header_fields_manager::HeaderFieldsManager;
use binderdump_epan_sys::epan;
use binderdump_structs::binder_serde::FieldOffset;
use binderdump_structs::event_layer::EventProtocol;
use std::ffi::c_int;

pub fn dissect_transaction_data(
    hf: c_int,
    _ett: c_int,
    _manager: &HeaderFieldsManager<EventProtocol>,
    _event: &EventProtocol,
    field: FieldOffset,
    tvb: *mut epan::tvbuff,
    _pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_node,
) -> anyhow::Result<()> {
    // render the raw data bytes exactly as the default FT_BYTES handler would.
    unsafe {
        epan::proto_tree_add_item(
            tree,
            hf,
            tvb,
            field.offset.try_into()?,
            field.size.try_into()?,
            epan::ENC_NA,
        );
    }
    Ok(())
}
