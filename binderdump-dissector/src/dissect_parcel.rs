// Custom handler for the transaction `data` field: renders the raw parcel
// bytes (as the default handler would) and — for request-direction AIDL
// transactions — a `Parameters` subtree decoded from the resolved method
// signature. Decoding is best-effort and purely additive; the raw hex view
// always remains.
//
// each decoded parameter is shown via a per-(interface, method, param) field
// registered lazily on first sighting (radius/diameter/protobuf do the same —
// Wireshark allows registering header fields after proto_register). this lets
// users filter binderdump.parcel.<iface>.<method>.<param> in the GUI. these
// fields are not visible to tshark -e/-Y, which compile filters before
// dissection; the undecodable tail uses a static `parcel.raw` field, which is.

use crate::header_fields_manager::HeaderFieldsManager;
use binderdump_aidl::{decode_aidl_params, DecodedNode, DecodedValue};
use binderdump_epan_sys::epan;
use binderdump_structs::binder_serde::FieldOffset;
use binderdump_structs::event_layer::EventProtocol;
use std::collections::HashMap;
use std::ffi::{c_int, CString};
use std::sync::{Mutex, OnceLock};

pub fn dissect_transaction_data(
    hf: c_int,
    _ett: c_int,
    manager: &HeaderFieldsManager<EventProtocol>,
    event: &EventProtocol,
    field: FieldOffset,
    tvb: *mut epan::tvbuff,
    _pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_node,
) -> anyhow::Result<()> {
    let data_off: usize = field.offset;

    // raw bytes, exactly as the default FT_BYTES handler would render them.
    unsafe {
        epan::proto_tree_add_item(
            tree,
            hf,
            tvb,
            data_off.try_into()?,
            field.size.try_into()?,
            epan::ENC_NA,
        );
    }

    let Some(txn) = event
        .ioctl_data
        .as_ref()
        .and_then(|i| i.bwr.as_ref())
        .and_then(|b| b.transaction.as_ref())
    else {
        return Ok(());
    };

    // request direction only; replies carry no writeInterfaceToken (later
    // sub-project handles them via in_reply_to_debug_id correlation).
    if txn.reply != 0 {
        return Ok(());
    }

    let r = crate::aidl_resolve::resolve(
        crate::aidl_resolve::registry(),
        event.binder_interface(),
        txn.code,
        event.android_sdk(),
        &txn.data,
    );
    let (Some(method), Some(start)) = (r.method, r.params_start) else {
        return Ok(());
    };
    let nodes = decode_aidl_params(method, &txn.data, start);
    if nodes.is_empty() {
        return Ok(());
    }

    // open the Parameters subtree over the whole data buffer.
    let ett = manager
        .get_handle("binderdump.ioctl_data.bwr.transaction.parcel")
        .unwrap_or(-1);
    let title = CString::new("Parameters")?;
    let params_tree = unsafe {
        epan::proto_tree_add_subtree(
            tree,
            tvb,
            data_off.try_into()?,
            field.size.try_into()?,
            ett,
            std::ptr::null_mut(),
            title.as_ptr(),
        )
    };

    let iface = r.interface.as_deref().unwrap_or("unknown");
    for node in &nodes {
        render_node(
            manager,
            params_tree,
            tvb,
            data_off,
            iface,
            &method.name,
            node,
        )?;
    }

    Ok(())
}

fn render_node(
    manager: &HeaderFieldsManager<EventProtocol>,
    tree: *mut epan::proto_node,
    tvb: *mut epan::tvbuff,
    data_off: usize,
    iface: &str,
    method: &str,
    node: &DecodedNode,
) -> anyhow::Result<()> {
    let off: c_int = (data_off + node.start).try_into()?;
    let len: c_int = node.len.try_into()?;

    // undecodable tail: no known type, rendered through the static raw field so
    // it is filterable from tshark too ("transactions we couldn't fully
    // decode"). decoded values get per-param fields below.
    if let DecodedValue::Raw = node.value {
        let h = handle(manager, "raw")?;
        unsafe {
            epan::proto_tree_add_item(tree, h, tvb, off, len, epan::ENC_NA);
        }
        return Ok(());
    }

    // each decoded value renders through its per-(interface, method, param)
    // field. registration can only fail if the proto handle isn't available
    // yet (never at dissection time), so skip the node rather than mis-render.
    let fqn = fqn_handle(iface, method, node);
    if fqn < 0 {
        return Ok(());
    }
    add_typed(tree, fqn, tvb, off, len, &node.value);

    Ok(())
}

// add a decoded value to `hf` using the matching typed add.
fn add_typed(
    tree: *mut epan::proto_node,
    hf: c_int,
    tvb: *mut epan::tvbuff,
    off: c_int,
    len: c_int,
    value: &DecodedValue,
) {
    match value {
        DecodedValue::I64(v) => unsafe {
            epan::proto_tree_add_int64(tree, hf, tvb, off, len, *v);
        },
        // bool goes through the int field (FT_INT64) as 0/1.
        DecodedValue::Bool(v) => unsafe {
            epan::proto_tree_add_int64(tree, hf, tvb, off, len, *v as i64);
        },
        DecodedValue::U64(v) => unsafe {
            epan::proto_tree_add_uint64(tree, hf, tvb, off, len, *v);
        },
        DecodedValue::F64(v) => unsafe {
            epan::proto_tree_add_double(tree, hf, tvb, off, len, *v);
        },
        DecodedValue::Str(s) => {
            let shown = s.clone().unwrap_or_else(|| "<null>".to_string());
            // "<invalid>" is a literal with no interior NUL, so this unwrap can't fail.
            let c = CString::new(shown).unwrap_or_else(|_| CString::new("<invalid>").unwrap());
            unsafe {
                epan::proto_tree_add_string(tree, hf, tvb, off, len, c.as_ptr());
            }
        }
        // Raw is rendered by render_node through the static field, never here.
        DecodedValue::Raw => {}
    }
}

// ftype + display for the dynamic per-param field; matches the value variant so
// add_typed renders into it correctly.
fn value_ftype(
    value: &DecodedValue,
) -> (
    binderdump_epan_sys::ftenum,
    binderdump_epan_sys::field_display_e,
) {
    use binderdump_epan_sys::{field_display_e, ftenum};
    match value {
        DecodedValue::I64(_) | DecodedValue::Bool(_) => {
            (ftenum::FT_INT64, field_display_e::BASE_DEC)
        }
        DecodedValue::U64(_) => (ftenum::FT_UINT64, field_display_e::BASE_DEC),
        DecodedValue::F64(_) => (ftenum::FT_DOUBLE, field_display_e::BASE_NONE),
        DecodedValue::Str(_) => (ftenum::FT_STRING, field_display_e::BASE_NONE),
        DecodedValue::Raw => (ftenum::FT_BYTES, field_display_e::BASE_NONE),
    }
}

fn handle(manager: &HeaderFieldsManager<EventProtocol>, leaf: &str) -> anyhow::Result<c_int> {
    let path = format!("binderdump.ioctl_data.bwr.transaction.parcel.{}", leaf);
    manager
        .get_handle(&path)
        .ok_or_else(|| anyhow::anyhow!("missing hf handle for {}", path))
}

// dynamically-registered per-(interface, method, param) fields, keyed by abbrev.
// the map persists for the session: fields only accrete, so re-registration on
// file reload never happens and no deregistration is needed.
static DYN_FIELDS: OnceLock<Mutex<HashMap<String, c_int>>> = OnceLock::new();

fn dyn_fields() -> &'static Mutex<HashMap<String, c_int>> {
    DYN_FIELDS.get_or_init(|| Mutex::new(HashMap::new()))
}

// abbrev components are restricted to what Wireshark accepts in a field path.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// register (or fetch) the field for one param. abbrev is
// binderdump...parcel.<iface>.<method>.<param>; the display name is the bare
// param name. returns -1 if the proto handle isn't available yet.
fn fqn_handle(iface: &str, method: &str, node: &DecodedNode) -> c_int {
    // shorter, top-level path (not the deep struct path) so the filter is
    // ergonomic: binderdump.parcel.<iface>.<method>.<param>.
    let abbrev = format!(
        "binderdump.parcel.{}.{}.{}",
        sanitize(iface),
        sanitize(method),
        sanitize(&node.name),
    );

    let mut map = match dyn_fields().lock() {
        Ok(m) => m,
        Err(_) => return -1,
    };
    if let Some(&h) = map.get(&abbrev) {
        return h;
    }
    let proto = match crate::epan_plugin::proto_handle() {
        Some(p) if p >= 0 => p,
        _ => return -1,
    };

    let (ft, display) = value_ftype(&node.value);
    // the name/abbrev strings and the hf_register_info must outlive the field,
    // i.e. the process — leak them. bounded by the distinct params actually seen.
    let (Ok(name_c), Ok(abbrev_c)) = (
        CString::new(node.name.clone()),
        CString::new(abbrev.clone()),
    ) else {
        return -1;
    };
    let name_ptr = Box::leak(name_c.into_boxed_c_str()).as_ptr();
    let abbrev_ptr = Box::leak(abbrev_c.into_boxed_c_str()).as_ptr();
    let p_id: &'static mut c_int = Box::leak(Box::new(-1));
    let hf: &'static mut binderdump_epan_sys::hf_register_info =
        Box::leak(Box::new(binderdump_epan_sys::hf_register_info {
            p_id: p_id as *mut c_int,
            hfinfo: binderdump_epan_sys::header_field_info {
                name: name_ptr,
                abbrev: abbrev_ptr,
                type_: ft,
                display: display as c_int,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: std::ptr::null(),
                // HFILL defaults
                id: -1,
                parent: 0,
                ref_type: binderdump_epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        }));
    unsafe {
        binderdump_epan_sys::proto_register_field_array(proto, hf as *mut _, 1);
    }
    let h = *p_id;
    map.insert(abbrev, h);
    h
}
