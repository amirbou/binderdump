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
    let nodes = decode_aidl_params(
        crate::aidl_resolve::registry(),
        event.android_sdk(),
        method,
        &txn.data,
        start,
    );
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
        render_value(
            manager,
            params_tree,
            tvb,
            data_off,
            iface,
            &method.name,
            &node.name,
            node,
        )?;
    }

    Ok(())
}

// render one decoded node into the wireshark tree.
// `leaf_name` is the field-path segment used for dynamic field registration;
// for top-level params this equals node.name, for array elements this is the
// parent array's name so all elements land on the same per-param field.
fn render_value(
    manager: &HeaderFieldsManager<EventProtocol>,
    tree: *mut epan::proto_node,
    tvb: *mut epan::tvbuff,
    data_off: usize,
    iface: &str,
    method: &str,
    leaf_name: &str,
    node: &DecodedNode,
) -> anyhow::Result<()> {
    let off: c_int = (data_off + node.start).try_into()?;
    let len: c_int = node.len.try_into()?;

    match &node.value {
        // undecodable tail: static raw field so it is filterable from tshark.
        DecodedValue::Raw => {
            let h = handle(manager, "raw")?;
            unsafe {
                epan::proto_tree_add_item(tree, h, tvb, off, len, epan::ENC_NA);
            }
        }

        // byte[]: render as a raw bytes blob using the static parcel.raw field.
        DecodedValue::Bytes => {
            let h = handle(manager, "raw")?;
            unsafe {
                epan::proto_tree_add_item(tree, h, tvb, off, len, epan::ENC_NA);
            }
        }

        // array: open a subtree then recurse into each child. children are
        // associated with the array param's field path (leaf_name), so
        // repeated elements share the same registered field.
        DecodedValue::Array {
            len: elem_count,
            null,
        } => {
            let title = if *null {
                format!("{}: null", node.name)
            } else {
                let s = if *elem_count == 1 { "" } else { "s" };
                format!("{}: {} item{}", node.name, elem_count, s)
            };
            let ett = manager
                .get_handle("binderdump.ioctl_data.bwr.transaction.parcel")
                .unwrap_or(-1);
            // "<invalid>" is a literal with no interior NUL, so this unwrap can't fail.
            let title_c =
                CString::new(title).unwrap_or_else(|_| CString::new("<invalid>").unwrap());
            let sub = unsafe {
                epan::proto_tree_add_subtree(
                    tree,
                    tvb,
                    off,
                    len,
                    ett,
                    std::ptr::null_mut(),
                    title_c.as_ptr(),
                )
            };
            for child in &node.children {
                render_value(manager, sub, tvb, data_off, iface, method, leaf_name, child)?;
            }
        }

        // parcelable: a subtree titled "<name>: <fqn>" (or "<name>: null"); each
        // field is its own dotted dynamic field (leaf.<field>). null -> no children.
        // (mirrors the existing Array arm's subtree + null-title shape.)
        DecodedValue::Parcelable { fqn, null } => {
            render_struct_subtree(
                manager, tree, tvb, data_off, iface, method, leaf_name, node, off, len, fqn, *null,
            )?;
        }

        // union: identical render shape to parcelable — a titled subtree with
        // a single dotted-leaf child for the active member (empty if null).
        DecodedValue::Union { fqn, null } => {
            render_struct_subtree(
                manager, tree, tvb, data_off, iface, method, leaf_name, node, off, len, fqn, *null,
            )?;
        }

        // enum: per-param field with a val64_string so wireshark shows NAME (n).
        DecodedValue::Enum { repr, variants } => {
            let fqn = fqn_handle_enum(iface, method, leaf_name, variants);
            if fqn >= 0 {
                unsafe {
                    epan::proto_tree_add_int64(tree, fqn, tvb, off, len, *repr);
                }
            }
        }

        // scalars: per-param field, typed add matching value_ftype.
        _ => {
            let fqn = fqn_handle(iface, method, leaf_name, node);
            if fqn >= 0 {
                add_typed(tree, fqn, tvb, off, len, &node.value);
            }
        }
    }

    Ok(())
}

// render a parcelable/union as a titled subtree whose children are dotted
// per-(iface,method,field) dynamic fields. shared by the Parcelable and Union arms.
fn render_struct_subtree(
    manager: &HeaderFieldsManager<EventProtocol>,
    tree: *mut epan::proto_node,
    tvb: *mut epan::tvbuff,
    data_off: usize,
    iface: &str,
    method: &str,
    leaf_name: &str,
    node: &DecodedNode,
    off: c_int,
    len: c_int,
    fqn: &str,
    null: bool,
) -> anyhow::Result<()> {
    let title = if null {
        format!("{}: null", node.name)
    } else {
        format!("{}: {}", node.name, fqn)
    };
    let ett = manager
        .get_handle("binderdump.ioctl_data.bwr.transaction.parcel")
        .unwrap_or(-1);
    // "<invalid>" is a literal with no interior NUL, so this unwrap can't fail.
    let title_c = CString::new(title).unwrap_or_else(|_| CString::new("<invalid>").unwrap());
    let sub = unsafe {
        epan::proto_tree_add_subtree(
            tree,
            tvb,
            off,
            len,
            ett,
            std::ptr::null_mut(),
            title_c.as_ptr(),
        )
    };
    for child in &node.children {
        let child_leaf = if child.name.is_empty() {
            leaf_name.to_string()
        } else {
            format!("{}.{}", leaf_name, child.name)
        };
        render_value(
            manager,
            sub,
            tvb,
            data_off,
            iface,
            method,
            &child_leaf,
            child,
        )?;
    }
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
        // these variants are handled by render_value before add_typed is called.
        DecodedValue::Raw
        | DecodedValue::Bytes
        | DecodedValue::Array { .. }
        | DecodedValue::Enum { .. }
        | DecodedValue::Parcelable { .. }
        | DecodedValue::Union { .. } => {}
    }
}

// ftype + display for the dynamic per-param field; matches the value variant so
// add_typed renders into it correctly. Enum/Array/Bytes use dedicated paths.
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
        // Raw/Bytes/Array/Enum go through dedicated render paths, not this fn.
        _ => (ftenum::FT_BYTES, field_display_e::BASE_NONE),
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

// register (or fetch) a plain scalar per-param field. abbrev is
// binderdump.parcel.<iface>.<method>.<leaf>; display name is the bare leaf.
// returns -1 if the proto handle isn't available yet.
fn fqn_handle(iface: &str, method: &str, leaf: &str, node: &DecodedNode) -> c_int {
    let abbrev = format!(
        "binderdump.parcel.{}.{}.{}",
        sanitize(iface),
        sanitize(method),
        sanitize(leaf),
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
    // name/abbrev strings and hf_register_info must outlive the field (process
    // lifetime) — leak them. bounded by the distinct params actually seen.
    let (Ok(name_c), Ok(abbrev_c)) = (CString::new(leaf), CString::new(abbrev.clone())) else {
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

// register (or fetch) an enum per-param field. same abbrev scheme as
// fqn_handle but FT_INT64 + a leaked val64_string so wireshark shows NAME (n).
// variants is (repr_value, name). returns -1 if proto handle isn't ready.
fn fqn_handle_enum(iface: &str, method: &str, leaf: &str, variants: &[(i64, String)]) -> c_int {
    use binderdump_epan_sys::{field_display_e, ftenum};

    let abbrev = format!(
        "binderdump.parcel.{}.{}.{}",
        sanitize(iface),
        sanitize(method),
        sanitize(leaf),
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

    // build a leaked val64_string array (NUL-sentinel terminated). name strings
    // are also leaked; bounded by distinct (iface, method, param) triples.
    let vs_ptr: *const std::ffi::c_void = if variants.is_empty() {
        std::ptr::null()
    } else {
        let mut raw: Vec<binderdump_epan_sys::val64_string> =
            Vec::with_capacity(variants.len() + 1);
        for (repr, name) in variants {
            // CString::new fails only on interior NUL which enum names won't have.
            let s = CString::new(name.as_str()).unwrap_or_else(|_| CString::new("?").unwrap());
            let strptr = Box::leak(s.into_boxed_c_str()).as_ptr();
            raw.push(binderdump_epan_sys::val64_string {
                value: *repr as u64,
                strptr,
            });
        }
        // sentinel
        raw.push(binderdump_epan_sys::val64_string {
            value: 0,
            strptr: std::ptr::null_mut(),
        });
        let boxed: *mut [binderdump_epan_sys::val64_string] = Box::into_raw(raw.into_boxed_slice());
        boxed as *const std::ffi::c_void
    };

    let display = field_display_e::BASE_DEC as c_int
        | binderdump_epan_sys::BASE_VAL64_STRING as c_int
        | binderdump_epan_sys::BASE_SPECIAL_VALS as c_int;

    let (Ok(name_c), Ok(abbrev_c)) = (CString::new(leaf), CString::new(abbrev.clone())) else {
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
                type_: ftenum::FT_INT64,
                display,
                strings: vs_ptr,
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
