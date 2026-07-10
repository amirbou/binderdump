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

use crate::decode_status;
use crate::header_fields_manager::HeaderFieldsManager;
use binderdump_aidl::decode::{decode_aidl_reply, decode_native_reply, ParcelCursor};
use binderdump_aidl::decode_hidl::{decode_hidl_params, decode_hidl_reply};
use binderdump_aidl::{
    decode_aidl_params, produces_no_reply_data, takes_no_input_params, DecodedNode, DecodedValue,
};
use binderdump_epan_sys::epan;
use binderdump_structs::binder_serde::FieldOffset;
use binderdump_structs::binder_types::BinderInterface;
use binderdump_structs::bwr_layer::PtrPayload;
use binderdump_structs::event_layer::EventProtocol;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{c_int, CString};
use std::sync::{Mutex, OnceLock};

pub fn dissect_transaction_data(
    hf: c_int,
    _ett: c_int,
    manager: &HeaderFieldsManager<EventProtocol>,
    event: &EventProtocol,
    field: FieldOffset,
    tvb: *mut epan::tvbuff,
    pinfo: *mut epan::packet_info,
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

    // replies carry no writeInterfaceToken; recover the originating method via
    // reply correlation and decode the status header + return value + out params.
    if txn.reply != 0 {
        let off: c_int = data_off.try_into()?;
        let len: c_int = field.size.try_into()?;

        // BR_REPLY (read side) carries in_reply_to_debug_id == 0, so fall back to the
        // reply's own debug_id to find the originating request (see txn_for_reply).
        let Some(state) =
            crate::reply_correlation::txn_for_reply(txn.in_reply_to_debug_id, txn.debug_id)
        else {
            let input = decode_status::StatusInput {
                method_source: "aosp",
                is_hwbinder: false,
                interface: None,
                method_name: None,
                sdk: event.android_sdk(),
                code: txn.code,
                is_reply: true,
                reply_correlated: false,
                reply_method_known: false,
                decoded_params: 0,
                raw_tail_reason: None,
                undecoded_bytes: 0,
                payload_decoder_missing: false,
            };
            if let Some(status) = decode_status::build_status(&input) {
                decode_status::emit(manager, tree, tvb as *mut _, pinfo, off, len, &status)?;
            }
            return Ok(());
        };
        let Some(method) = state.method else {
            // INTERFACE_TRANSACTION (getInterfaceDescriptor) carries no resolved Method because
            // the kernel handles it as a special transaction code rather than an AIDL interface
            // method. The reply payload is a bare String16 at offset 0 — the interface descriptor.
            // HIDL uses a different string wire format (hidl_string fat pointer), so skip it there.
            if state.method_name.as_deref() == Some("INTERFACE_TRANSACTION") && !state.is_hidl {
                let iface = state.interface.as_deref().unwrap_or("unknown");
                let mut cur = ParcelCursor::new(&txn.data, 0);
                if let Some(s) = cur.read_string16() {
                    let slen = cur.pos;
                    let descriptor_node = DecodedNode {
                        name: "descriptor".to_string(),
                        type_label: "String".to_string(),
                        start: 0,
                        len: slen,
                        value: DecodedValue::Str(s),
                        children: vec![],
                    };
                    let sub = open_subtree(manager, tree, tvb, off, len, "Reply");
                    render_value(
                        manager,
                        sub,
                        tvb,
                        data_off,
                        iface,
                        "INTERFACE_TRANSACTION",
                        "descriptor",
                        &descriptor_node,
                    )?;
                    let undecoded = txn.data.len().saturating_sub(slen);
                    let input = decode_status::StatusInput {
                        method_source: "aosp",
                        is_hwbinder: false,
                        interface: state.interface.as_deref(),
                        method_name: Some("INTERFACE_TRANSACTION"),
                        sdk: event.android_sdk(),
                        code: txn.code,
                        is_reply: true,
                        reply_correlated: true,
                        reply_method_known: true,
                        decoded_params: 1,
                        raw_tail_reason: None,
                        undecoded_bytes: undecoded,
                        payload_decoder_missing: false,
                    };
                    if let Some(status) = decode_status::build_status(&input) {
                        decode_status::emit(
                            manager,
                            tree,
                            tvb as *mut _,
                            pinfo,
                            off,
                            len,
                            &status,
                        )?;
                    }
                    return Ok(());
                }
                // short/garbled payload: fall through to the "method unknown" status
            }
            let input = decode_status::StatusInput {
                method_source: "aosp",
                is_hwbinder: false,
                interface: None,
                method_name: None,
                sdk: event.android_sdk(),
                code: txn.code,
                is_reply: true,
                reply_correlated: true,
                reply_method_known: false,
                decoded_params: 0,
                raw_tail_reason: None,
                undecoded_bytes: 0,
                payload_decoder_missing: false,
            };
            if let Some(status) = decode_status::build_status(&input) {
                decode_status::emit(manager, tree, tvb as *mut _, pinfo, off, len, &status)?;
            }
            return Ok(());
        };
        // reply payload starts at offset 0 (no interface token).
        let ptr_payloads = assemble_ptr_payloads(&txn.ptr_payloads);
        let nodes = if state.is_native {
            decode_native_reply(
                crate::aidl_resolve::registry(),
                event.android_sdk(),
                method,
                &txn.data,
                0,
                &txn.offsets,
            )
        } else if state.is_hidl {
            let candidate_pkgs = hidl_candidate_pkgs(
                crate::aidl_resolve::registry(),
                event.android_sdk(),
                state.interface.as_deref(),
            );
            decode_hidl_reply(
                crate::aidl_resolve::registry(),
                event.android_sdk(),
                method,
                &txn.data,
                0,
                &txn.offsets,
                &ptr_payloads,
                &candidate_pkgs,
                state.interface.as_deref(),
            )
        } else {
            decode_aidl_reply(
                crate::aidl_resolve::registry(),
                event.android_sdk(),
                method,
                &txn.data,
                0,
                &txn.offsets,
            )
        };
        if !nodes.is_empty() {
            let iface = state.interface.as_deref().unwrap_or("unknown");
            let sub = open_subtree(manager, tree, tvb, off, len, "Reply");
            for node in &nodes {
                render_value(
                    manager,
                    sub,
                    tvb,
                    data_off,
                    iface,
                    &method.name,
                    &node.name,
                    node,
                )?;
            }
        } else if !state.is_hidl && !state.is_native && produces_no_reply_data(method) {
            // resolved AIDL method that returns nothing — mark it so the empty
            // Reply region isn't mistaken for a decode failure. Gated to real
            // AIDL: native synthetic corpus uses opaque `void name()` stubs where
            // an empty signature means "unmodeled", not "no return value", and
            // "returns void" is AIDL phrasing.
            open_subtree(
                manager,
                tree,
                tvb,
                off,
                len,
                "Return value: none (method returns void)",
            );
        }
        let (decoded_params, raw_tail_reason, tail_bytes) = decode_stats(&nodes, txn.data.len());
        let input = decode_status::StatusInput {
            method_source: "aosp",
            is_hwbinder: false,
            interface: None,
            method_name: None,
            sdk: event.android_sdk(),
            code: txn.code,
            is_reply: true,
            reply_correlated: true,
            reply_method_known: true,
            decoded_params,
            raw_tail_reason,
            undecoded_bytes: tail_bytes,
            payload_decoder_missing: false,
        };
        if let Some(status) = decode_status::build_status(&input) {
            decode_status::emit(manager, tree, tvb as *mut _, pinfo, off, len, &status)?;
        }
        return Ok(());
    }

    let r = crate::aidl_resolve::resolve(
        crate::aidl_resolve::registry(),
        event.binder_interface(),
        txn.code,
        event.android_sdk(),
        &txn.data,
    );
    let is_hwbinder = matches!(event.binder_interface(), BinderInterface::HWBINDER);
    let off: c_int = data_off.try_into()?;
    let len: c_int = field.size.try_into()?;

    // unresolved (no method) -> status only, no params subtree.
    let (Some(method), Some(start)) = (r.method, r.params_start) else {
        let input = decode_status::StatusInput {
            method_source: r.method_source,
            is_hwbinder,
            interface: r.interface.as_deref(),
            method_name: r.method_name.as_deref(),
            sdk: event.android_sdk(),
            code: txn.code,
            is_reply: false,
            reply_correlated: true,
            reply_method_known: true,
            decoded_params: 0,
            raw_tail_reason: None,
            undecoded_bytes: 0,
            payload_decoder_missing: false,
        };
        if let Some(status) = decode_status::build_status(&input) {
            decode_status::emit(manager, tree, tvb as *mut _, pinfo, off, len, &status)?;
        }
        return Ok(());
    };

    let ptr_payloads = assemble_ptr_payloads(&txn.ptr_payloads);
    let nodes = if r.is_hidl {
        let candidate_pkgs = hidl_candidate_pkgs(
            crate::aidl_resolve::registry(),
            event.android_sdk(),
            r.interface.as_deref(),
        );
        decode_hidl_params(
            crate::aidl_resolve::registry(),
            event.android_sdk(),
            method,
            &txn.data,
            start,
            &txn.offsets,
            &ptr_payloads,
            &candidate_pkgs,
            r.interface.as_deref(),
        )
    } else {
        decode_aidl_params(
            crate::aidl_resolve::registry(),
            event.android_sdk(),
            method,
            &txn.data,
            start,
            &txn.offsets,
        )
    };

    // render whatever decoded (unchanged), if any.
    if !nodes.is_empty() {
        let ett = manager
            .get_handle("binderdump.ioctl_data.bwr.transaction.parcel")
            .unwrap_or(-1);
        let title = CString::new("Parameters")?;
        let params_tree = unsafe {
            epan::proto_tree_add_subtree(
                tree,
                tvb,
                off,
                len,
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
    } else if !r.is_hidl && r.method_source != "native" && takes_no_input_params(method) {
        // resolved AIDL method that takes no arguments — mark it so the empty
        // Parameters region isn't mistaken for a decode failure. Gated to real
        // AIDL (aosp/overlay): native synthetic corpus uses opaque `void name()`
        // stubs where an empty signature means "unmodeled", not "no arguments".
        open_subtree(
            manager,
            tree,
            tvb,
            off,
            len,
            "Parameters: none (method takes no parameters)",
        );
    }

    // status: stub (0 params + leftover) or raw-tail partial.
    let (decoded_params, raw_tail_reason, tail_bytes) = decode_stats(&nodes, txn.data.len());
    let undecoded_bytes = if raw_tail_reason.is_some() {
        tail_bytes
    } else {
        txn.data.len().saturating_sub(start) // only read by build_status when decoded_params == 0 (opaque stub)
    };
    // HIDL decoder returns a single top-level RawTail when it hits an unsupported
    // aggregate type or an opaque handle/memory type. signal that distinctly from
    // the AIDL "opaque stub" path so decode_status can say "not implemented".
    let payload_decoder_missing = r.is_hidl
        && nodes.len() == 1
        && matches!(&nodes[0].value, DecodedValue::RawTail { reason } if {
            let r = reason.as_str();
            r.contains("not yet supported") || r.contains("opaque") || r.contains("aggregate") || r.contains("handle")
        });
    let input = decode_status::StatusInput {
        method_source: r.method_source,
        is_hwbinder,
        interface: r.interface.as_deref(),
        method_name: r.method_name.as_deref(),
        sdk: event.android_sdk(),
        code: txn.code,
        is_reply: false,
        reply_correlated: true,
        reply_method_known: true,
        decoded_params,
        raw_tail_reason,
        undecoded_bytes,
        payload_decoder_missing,
    };
    if let Some(status) = decode_status::build_status(&input) {
        decode_status::emit(manager, tree, tvb as *mut _, pinfo, off, len, &status)?;
    }
    Ok(())
}

// build the ordered list of package fqns used for resolving bare HIDL type names.
// the current package (derived from the interface fqn) comes first, followed by any
// packages that the interface's definition explicitly imports.
fn hidl_candidate_pkgs(
    reg: &binderdump_aidl::Registry,
    sdk: u32,
    iface_fqn: Option<&str>,
) -> Vec<String> {
    let fqn = match iface_fqn {
        Some(f) => f,
        None => return vec![],
    };
    let mut pkgs = Vec::new();
    // current package: pkg@ver from "pkg@ver::IName"
    if let Some((pkg, _)) = fqn.split_once("::") {
        if pkg.contains('@') {
            pkgs.push(pkg.to_string());
        }
    }
    // explicit imports from the interface definition
    if let Some(iface) = reg.iface_def(sdk, fqn) {
        for import_pkg in &iface.imports {
            if !pkgs.contains(import_pkg) {
                pkgs.push(import_pkg.clone());
            }
        }
    }
    pkgs
}

// group PtrPayload chunks by offset_index, concatenate data in slice order, and
// return as Vec<(offset_index, payload_bytes)> sorted by offset_index. the
// decoder expects exactly this form.
fn assemble_ptr_payloads(raw: &[PtrPayload]) -> Vec<(u32, Vec<u8>)> {
    let mut map: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for p in raw {
        map.entry(p.offset_index)
            .or_default()
            .extend_from_slice(&p.data);
    }
    map.into_iter().collect()
}

// returns (decoded_param_count, raw_tail_reason, undecoded_bytes) from a decoded
// node list. a trailing RawTail means decode stopped; its start marks the
// undecoded region.
//
// only detects a trailing top-level RawTail. a field that truncates inside a
// parcelable is resynced to its size boundary and surfaces as a Bytes child, so
// such a frame currently reports no decode_status (known limitation).
fn decode_stats<'a>(nodes: &'a [DecodedNode], data_len: usize) -> (usize, Option<&'a str>, usize) {
    if let Some(last) = nodes.last() {
        if let DecodedValue::RawTail { reason } = &last.value {
            return (
                nodes.len() - 1,
                Some(reason.as_str()),
                data_len.saturating_sub(last.start),
            );
        }
    }
    (nodes.len(), None, 0)
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
        DecodedValue::Raw | DecodedValue::RawTail { .. } => {
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
            let sub = open_subtree(manager, tree, tvb, off, len, &title);
            for child in &node.children {
                render_value(manager, sub, tvb, data_off, iface, method, leaf_name, child)?;
            }
        }

        // map: subtree of entry subtrees, each with a key and value child.
        DecodedValue::Map { len: map_len, null } => {
            let title = if *null {
                format!("{}: null", node.name)
            } else {
                let s = if *map_len == 1 { "y" } else { "ies" };
                format!("{}: {} entr{}", node.name, map_len, s)
            };
            let sub = open_subtree(manager, tree, tvb, off, len, &title);
            for child in &node.children {
                render_value(manager, sub, tvb, data_off, iface, method, leaf_name, child)?;
            }
        }

        // bundle: subtree of key-named children (keys are plain strings, so each
        // entry renders directly under its key rather than as an entry/key/value trio).
        DecodedValue::Bundle { len: n, null } => {
            let title = if *null {
                format!("{}: null", node.name)
            } else if *n == 0 {
                format!("{}: 0 entries", node.name)
            } else {
                let s = if *n == 1 { "y" } else { "ies" };
                format!("{}: {} entr{}", node.name, n, s)
            };
            let sub = open_subtree(manager, tree, tvb, off, len, &title);
            for child in &node.children {
                let child_leaf = format!("{}.{}", leaf_name, child.name);
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
        }

        DecodedValue::MapEntry => {
            let sub = open_subtree(manager, tree, tvb, off, len, "entry");
            for child in &node.children {
                let child_leaf = format!("{}.{}", leaf_name, child.name);
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

        // serializable: titled subtree over the opaque Java object stream.
        DecodedValue::Serializable { class_name } => {
            let cls = class_name.as_deref().unwrap_or("?");
            let title = format!("{}: Serializable {}", node.name, cls);
            let sub = open_subtree(manager, tree, tvb, off, len, &title);
            let h = handle(manager, "raw")?;
            unsafe {
                epan::proto_tree_add_item(sub, h, tvb, off, len, epan::ENC_NA);
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
// open a child subtree under the parcel ett with the given title. shared by the
// array/map/mapentry/parcelable/union render arms.
fn open_subtree(
    manager: &HeaderFieldsManager<EventProtocol>,
    tree: *mut epan::proto_node,
    tvb: *mut epan::tvbuff,
    off: c_int,
    len: c_int,
    title: &str,
) -> *mut epan::proto_tree {
    let ett = manager
        .get_handle("binderdump.ioctl_data.bwr.transaction.parcel")
        .unwrap_or(-1);
    // "<invalid>" is a literal with no interior NUL, so this unwrap can't fail.
    let title_c = CString::new(title).unwrap_or_else(|_| CString::new("<invalid>").unwrap());
    unsafe {
        epan::proto_tree_add_subtree(
            tree,
            tvb,
            off,
            len,
            ett,
            std::ptr::null_mut(),
            title_c.as_ptr(),
        )
    }
}

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
    let sub = open_subtree(manager, tree, tvb, off, len, &title);
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
        DecodedValue::Binder { handle, strong } => {
            let s = format!(
                "{} 0x{:x}",
                if *strong { "binder" } else { "handle" },
                handle
            );
            // "<invalid>" is a literal with no interior NUL, so this unwrap can't fail.
            let c = CString::new(s).unwrap_or_else(|_| CString::new("<invalid>").unwrap());
            unsafe {
                epan::proto_tree_add_string(tree, hf, tvb, off, len, c.as_ptr());
            }
        }
        // these variants are handled by render_value before add_typed is called.
        DecodedValue::Raw
        | DecodedValue::RawTail { .. }
        | DecodedValue::Bytes
        | DecodedValue::Array { .. }
        | DecodedValue::Enum { .. }
        | DecodedValue::Parcelable { .. }
        | DecodedValue::Union { .. }
        | DecodedValue::Map { .. }
        | DecodedValue::Bundle { .. }
        | DecodedValue::Serializable { .. }
        | DecodedValue::MapEntry => {}
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
        DecodedValue::Binder { .. } => (ftenum::FT_STRING, field_display_e::BASE_NONE),
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
