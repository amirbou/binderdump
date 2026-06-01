use anyhow::{anyhow, Context};
use binderdump_epan_sys::epan;
use binderdump_structs::binder_serde::FieldOffset;
use binderdump_structs::binder_types::binder_type;
use binderdump_structs::bwr_layer::{PtrPayload, TransactionProtocol};
use binderdump_structs::event_layer::EventProtocol;
use std::ffi::{c_int, CString};
use std::ptr::null_mut;

use crate::header_fields_manager::HeaderFieldsManager;

macro_rules! offsets_prefix {
    ($s:literal) => {
        concat!("binderdump.ioctl_data.bwr.transaction.offsets.", $s)
    };
}

const ENTRY_SUBTREE: &str = offsets_prefix!("entry");
const ENTRY_TYPE_HF: &str = offsets_prefix!("entry.type");

const FLAT_BINDER_PREFIX: &str = offsets_prefix!("entry.binder");
const FLAT_HANDLE_PREFIX: &str = offsets_prefix!("entry.handle");
const FLAT_FD_PREFIX: &str = offsets_prefix!("entry.fd");
const FLAT_PTR_PREFIX: &str = offsets_prefix!("entry.ptr");
const FLAT_FDA_PREFIX: &str = offsets_prefix!("entry.fda");

const SIZE_FLAT_BINDER: usize = 24;
const SIZE_FLAT_FD: usize = 24;
const SIZE_FLAT_PTR: usize = 40;
const SIZE_FLAT_FDA: usize = 32;
const ENTRY_SIZE: usize = 8;
const PTR_SIZE: usize = 8;

// Fixed-size header per PtrPayload before the variable-length `data` bytes:
// offset_index(4) + buffer_addr(8) + total_size(8) + data_len(2).
const PTR_PAYLOAD_FIXED_HEADER: usize = 4 + 8 + 8 + 2;

const T_BINDER: u32 = binder_type::BINDER as u32;
const T_WEAK_BINDER: u32 = binder_type::WEAK_BINDER as u32;
const T_HANDLE: u32 = binder_type::HANDLE as u32;
const T_WEAK_HANDLE: u32 = binder_type::WEAK_HANDLE as u32;
const T_FD: u32 = binder_type::FD as u32;
const T_PTR: u32 = binder_type::PTR as u32;
const T_FDA: u32 = binder_type::FDA as u32;

struct FieldRefs {
    type_hf: c_int,
    flat_binder: VariantRefs,
    flat_handle: VariantHandleRefs,
    flat_fd: VariantFdRefs,
    flat_ptr: VariantPtrRefs,
    flat_fda: VariantFdaRefs,
}

struct VariantRefs {
    flags: c_int,
    binder: c_int,
    cookie: c_int,
}

struct VariantHandleRefs {
    flags: c_int,
    handle: c_int,
    cookie: c_int,
}

struct VariantFdRefs {
    pad_flags: c_int,
    fd: c_int,
    cookie: c_int,
}

struct VariantPtrRefs {
    flags: c_int,
    buffer: c_int,
    length: c_int,
    parent: c_int,
    parent_offset: c_int,
    payload: c_int,
}

struct VariantFdaRefs {
    num_fds: c_int,
    parent: c_int,
    parent_offset: c_int,
    fds: c_int,
}

fn lookup(manager: &HeaderFieldsManager<EventProtocol>, path: &str) -> anyhow::Result<c_int> {
    manager
        .get_handle(path)
        .with_context(|| format!("missing handle: {}", path))
}

fn lookup_field(
    manager: &HeaderFieldsManager<EventProtocol>,
    prefix: &str,
    field: &str,
) -> anyhow::Result<c_int> {
    lookup(manager, &format!("{}.{}", prefix, field))
}

fn collect_refs(manager: &HeaderFieldsManager<EventProtocol>) -> anyhow::Result<FieldRefs> {
    Ok(FieldRefs {
        type_hf: lookup(manager, ENTRY_TYPE_HF)?,
        flat_binder: VariantRefs {
            flags: lookup_field(manager, FLAT_BINDER_PREFIX, "flags")?,
            binder: lookup_field(manager, FLAT_BINDER_PREFIX, "binder")?,
            cookie: lookup_field(manager, FLAT_BINDER_PREFIX, "cookie")?,
        },
        flat_handle: VariantHandleRefs {
            flags: lookup_field(manager, FLAT_HANDLE_PREFIX, "flags")?,
            handle: lookup_field(manager, FLAT_HANDLE_PREFIX, "handle")?,
            cookie: lookup_field(manager, FLAT_HANDLE_PREFIX, "cookie")?,
        },
        flat_fd: VariantFdRefs {
            pad_flags: lookup_field(manager, FLAT_FD_PREFIX, "pad_flags")?,
            fd: lookup_field(manager, FLAT_FD_PREFIX, "fd")?,
            cookie: lookup_field(manager, FLAT_FD_PREFIX, "cookie")?,
        },
        flat_ptr: VariantPtrRefs {
            flags: lookup_field(manager, FLAT_PTR_PREFIX, "flags")?,
            buffer: lookup_field(manager, FLAT_PTR_PREFIX, "buffer")?,
            length: lookup_field(manager, FLAT_PTR_PREFIX, "length")?,
            parent: lookup_field(manager, FLAT_PTR_PREFIX, "parent")?,
            parent_offset: lookup_field(manager, FLAT_PTR_PREFIX, "parent_offset")?,
            payload: lookup_field(manager, FLAT_PTR_PREFIX, "payload")?,
        },
        flat_fda: VariantFdaRefs {
            num_fds: lookup_field(manager, FLAT_FDA_PREFIX, "num_fds")?,
            parent: lookup_field(manager, FLAT_FDA_PREFIX, "parent")?,
            parent_offset: lookup_field(manager, FLAT_FDA_PREFIX, "parent_offset")?,
            fds: lookup_field(manager, FLAT_FDA_PREFIX, "fds")?,
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedEntry {
    Binder,
    Handle,
    Fd,
    Ptr,
    Fda,
    Unknown,
}

/// One step of walking `txn.offsets`: the entry's index within the offsets
/// array, the byte position it points to inside `txn.data`, the raw type
/// id read from those bytes, and the classified variant.
pub struct FlatObjectEntry {
    pub idx: usize,
    pub pos: usize,
    pub type_id: u32,
    pub parsed: ParsedEntry,
}

pub struct FlatObjectsIter<'a> {
    data: &'a [u8],
    offsets: &'a [u8],
    cursor: usize,
    idx: usize,
}

impl<'a> Iterator for FlatObjectsIter<'a> {
    type Item = FlatObjectEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor + ENTRY_SIZE > self.offsets.len() {
            return None;
        }
        let bytes = self.offsets.get(self.cursor..self.cursor + ENTRY_SIZE)?;
        self.cursor += ENTRY_SIZE;
        let pos = u64::from_le_bytes(bytes.try_into().ok()?) as usize;
        let type_id = read_u32(self.data, pos)?;
        let parsed = classify(type_id);
        let idx = self.idx;
        self.idx += 1;
        Some(FlatObjectEntry {
            idx,
            pos,
            type_id,
            parsed,
        })
    }
}

/// Yields one `FlatObjectEntry` per offsets-array entry in `txn.offsets`,
/// stopping early on bounds-check failure. Shared between the main
/// dissector (which renders each entry into the proto tree) and the
/// Follow Stream view (which extracts decoded field values via
/// `parse_offset_summaries`).
pub fn iter_flat_objects<'a>(data: &'a [u8], offsets: &'a [u8]) -> FlatObjectsIter<'a> {
    FlatObjectsIter {
        data,
        offsets,
        cursor: 0,
        idx: 0,
    }
}

fn classify(type_: u32) -> ParsedEntry {
    match type_ {
        T_BINDER | T_WEAK_BINDER => ParsedEntry::Binder,
        T_HANDLE | T_WEAK_HANDLE => ParsedEntry::Handle,
        T_FD => ParsedEntry::Fd,
        T_PTR => ParsedEntry::Ptr,
        T_FDA => ParsedEntry::Fda,
        _ => ParsedEntry::Unknown,
    }
}

fn variant_label(type_: u32) -> &'static str {
    match type_ {
        T_BINDER => "BINDER",
        T_WEAK_BINDER => "WEAK_BINDER",
        T_HANDLE => "HANDLE",
        T_WEAK_HANDLE => "WEAK_HANDLE",
        T_FD => "FD",
        T_PTR => "PTR",
        T_FDA => "FDA",
        _ => "UNKNOWN",
    }
}

fn variant_size(entry: ParsedEntry) -> usize {
    match entry {
        ParsedEntry::Binder | ParsedEntry::Handle => SIZE_FLAT_BINDER,
        ParsedEntry::Fd => SIZE_FLAT_FD,
        ParsedEntry::Ptr => SIZE_FLAT_PTR,
        ParsedEntry::Fda => SIZE_FLAT_FDA,
        ParsedEntry::Unknown => 0,
    }
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    let bytes = data.get(off..off + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

// Compute tvb offset of the i-th PtrPayload entry. Each entry has a 22-byte
// fixed header followed by `data_len` bytes of payload, so the offset is found
// by walking previous entries' lengths.
fn ptr_payload_tvb_offsets(base: usize, payloads: &[PtrPayload]) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(payloads.len());
    let mut cur = base;
    for p in payloads {
        let header = cur;
        let data = cur + PTR_PAYLOAD_FIXED_HEADER;
        out.push((header, data));
        cur = data + p.data.len();
    }
    out
}

pub fn dissect_offsets_array(
    _hf: c_int,
    ett: c_int,
    manager: &HeaderFieldsManager<EventProtocol>,
    event: &EventProtocol,
    field: FieldOffset,
    tvb: *mut epan::tvbuff,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_node,
) -> anyhow::Result<()> {
    let _ = pinfo;
    let txn = match event
        .ioctl_data
        .as_ref()
        .and_then(|i| i.bwr.as_ref())
        .and_then(|b| b.transaction.as_ref())
    {
        Some(t) => t,
        None => return Ok(()),
    };

    if txn.offsets.is_empty() {
        return Ok(());
    }

    let refs = collect_refs(manager)?;
    // ett for the offsets subtree comes from the custom-handler dispatch,
    // not from the regular fields_to_handles map (custom-handled abbrevs
    // live in HeaderFieldsManager::custom_subtrees).
    let ett_offsets = ett;
    let ett_entry = lookup(manager, ENTRY_SUBTREE)?;

    if txn.offsets.len() % ENTRY_SIZE != 0 {
        return Err(anyhow!(
            "offsets buffer not aligned: len={}, entry_size={}",
            txn.offsets.len(),
            ENTRY_SIZE
        ));
    }
    let entry_count = txn.offsets.len() / ENTRY_SIZE;

    // Tvb byte position of `txn.data`. `field.offset` points at the offsets
    // bytes, which the serializer prefixes with a u32 length; the data bytes
    // sit immediately before that prefix. (binder_serde length-prefixes every
    // byte sequence with a u32 — see ser.rs serialize_bytes/serialize_seq.)
    let data_tvb_off = field
        .offset
        .checked_sub(4 + txn.data.len())
        .ok_or_else(|| anyhow!("data field offset underflow"))?;

    // Tvb byte position of the first PtrPayload entry's serialized form.
    // Layout after `offsets`: is_compat (1 byte), ptr_payloads_len (u32),
    // ptr_payloads (variable).
    let ptr_payloads_base = field.offset + txn.offsets.len() + 1 + 4;
    let payload_tvb = ptr_payload_tvb_offsets(ptr_payloads_base, &txn.ptr_payloads);

    let offsets_tree = unsafe {
        epan::proto_tree_add_subtree(
            tree,
            tvb,
            field.offset.try_into()?,
            field.size.try_into()?,
            ett_offsets,
            null_mut(),
            c"Offsets".as_ptr(),
        )
    };

    let mut walked = 0usize;
    for FlatObjectEntry {
        idx,
        pos: entry,
        type_id,
        parsed,
    } in iter_flat_objects(&txn.data, &txn.offsets)
    {
        walked += 1;
        if matches!(parsed, ParsedEntry::Unknown) {
            return Err(anyhow!(
                "unknown flat_binder_object type 0x{:x} at offsets[{}] pos {}",
                type_id,
                idx,
                entry
            ));
        }
        let object_size = variant_size(parsed);
        let abs_off = data_tvb_off + entry;

        let label = format!("offsets[{}] {}", idx, variant_label(type_id));
        let label_c = CString::new(label)?;

        let entry_tree = unsafe {
            epan::proto_tree_add_subtree(
                offsets_tree,
                tvb,
                abs_off.try_into()?,
                object_size.try_into()?,
                ett_entry,
                null_mut(),
                label_c.as_ptr(),
            )
        };

        // type_ field — first u32 in every variant.
        unsafe {
            epan::proto_tree_add_item(
                entry_tree,
                refs.type_hf,
                tvb,
                abs_off.try_into()?,
                4,
                epan::ENC_LITTLE_ENDIAN,
            );
        }

        match parsed {
            ParsedEntry::Binder => {
                render_flat_binder(tvb, entry_tree, &refs.flat_binder, abs_off)?;
            }
            ParsedEntry::Handle => {
                render_flat_handle(tvb, entry_tree, &refs.flat_handle, abs_off)?;
            }
            ParsedEntry::Fd => {
                render_flat_fd(tvb, entry_tree, &refs.flat_fd, abs_off)?;
            }
            ParsedEntry::Ptr => {
                let payload_idx = txn
                    .ptr_payloads
                    .iter()
                    .position(|p| p.offset_index as usize == idx);
                let payload_data_pos = payload_idx.map(|k| (k, payload_tvb[k].1));
                render_flat_ptr(
                    tvb,
                    entry_tree,
                    &refs.flat_ptr,
                    abs_off,
                    payload_idx.map(|k| &txn.ptr_payloads[k]),
                    payload_data_pos.map(|(_, d)| d),
                )?;
            }
            ParsedEntry::Fda => {
                render_flat_fda(
                    tvb,
                    entry_tree,
                    &refs.flat_fda,
                    abs_off,
                    &txn.data,
                    entry,
                    &txn.ptr_payloads,
                    &payload_tvb,
                )?;
            }
            ParsedEntry::Unknown => unreachable!("filtered above"),
        }
    }

    if walked != entry_count {
        return Err(anyhow!(
            "offsets walk produced {} entries, expected {}",
            walked,
            entry_count
        ));
    }

    Ok(())
}

fn render_flat_binder(
    tvb: *mut epan::tvbuff,
    tree: *mut epan::proto_node,
    refs: &VariantRefs,
    abs_off: usize,
) -> anyhow::Result<()> {
    unsafe {
        epan::proto_tree_add_item(
            tree,
            refs.flags,
            tvb,
            (abs_off + 4).try_into()?,
            4,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.binder,
            tvb,
            (abs_off + 8).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.cookie,
            tvb,
            (abs_off + 8 + PTR_SIZE).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
    }
    Ok(())
}

fn render_flat_handle(
    tvb: *mut epan::tvbuff,
    tree: *mut epan::proto_node,
    refs: &VariantHandleRefs,
    abs_off: usize,
) -> anyhow::Result<()> {
    unsafe {
        epan::proto_tree_add_item(
            tree,
            refs.flags,
            tvb,
            (abs_off + 4).try_into()?,
            4,
            epan::ENC_LITTLE_ENDIAN,
        );
        // The handle/binder union shares the first 4 bytes; the upper 4 bytes
        // of the 8-byte slot are padding.
        epan::proto_tree_add_item(
            tree,
            refs.handle,
            tvb,
            (abs_off + 8).try_into()?,
            4,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.cookie,
            tvb,
            (abs_off + 8 + PTR_SIZE).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
    }
    Ok(())
}

fn render_flat_fd(
    tvb: *mut epan::tvbuff,
    tree: *mut epan::proto_node,
    refs: &VariantFdRefs,
    abs_off: usize,
) -> anyhow::Result<()> {
    unsafe {
        epan::proto_tree_add_item(
            tree,
            refs.pad_flags,
            tvb,
            (abs_off + 4).try_into()?,
            4,
            epan::ENC_LITTLE_ENDIAN,
        );
        // The fd/pad_binder union: fd lives in the lower 4 bytes of the union.
        epan::proto_tree_add_item(
            tree,
            refs.fd,
            tvb,
            (abs_off + 8).try_into()?,
            4,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.cookie,
            tvb,
            (abs_off + 8 + PTR_SIZE).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
    }
    Ok(())
}

fn render_flat_ptr(
    tvb: *mut epan::tvbuff,
    tree: *mut epan::proto_node,
    refs: &VariantPtrRefs,
    abs_off: usize,
    payload: Option<&PtrPayload>,
    payload_data_tvb: Option<usize>,
) -> anyhow::Result<()> {
    unsafe {
        epan::proto_tree_add_item(
            tree,
            refs.flags,
            tvb,
            (abs_off + 4).try_into()?,
            4,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.buffer,
            tvb,
            (abs_off + 8).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.length,
            tvb,
            (abs_off + 8 + PTR_SIZE).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.parent,
            tvb,
            (abs_off + 8 + 2 * PTR_SIZE).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.parent_offset,
            tvb,
            (abs_off + 8 + 3 * PTR_SIZE).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
    }

    if let (Some(p), Some(data_tvb)) = (payload, payload_data_tvb) {
        let len = p.data.len();
        if len > 0 {
            unsafe {
                epan::proto_tree_add_item(
                    tree,
                    refs.payload,
                    tvb,
                    data_tvb.try_into()?,
                    len.try_into()?,
                    epan::ENC_NA,
                );
            }
        }
    }

    Ok(())
}

fn render_flat_fda(
    tvb: *mut epan::tvbuff,
    tree: *mut epan::proto_node,
    refs: &VariantFdaRefs,
    abs_off: usize,
    data: &[u8],
    entry: usize,
    ptr_payloads: &[PtrPayload],
    payload_tvb: &[(usize, usize)],
) -> anyhow::Result<()> {
    unsafe {
        epan::proto_tree_add_item(
            tree,
            refs.num_fds,
            tvb,
            (abs_off + 8).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.parent,
            tvb,
            (abs_off + 8 + PTR_SIZE).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
        epan::proto_tree_add_item(
            tree,
            refs.parent_offset,
            tvb,
            (abs_off + 8 + 2 * PTR_SIZE).try_into()?,
            PTR_SIZE.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
    }

    let num_fds = read_u64(data, entry + 8).unwrap_or(0) as usize;
    let parent = read_u64(data, entry + 8 + PTR_SIZE).unwrap_or(0) as usize;
    let parent_offset = read_u64(data, entry + 8 + 2 * PTR_SIZE).unwrap_or(0) as usize;

    if num_fds == 0 {
        return Ok(());
    }

    // The parent is an offsets-array index (not a byte offset). It points at
    // the BINDER_TYPE_PTR object whose buffer holds the fd values starting at
    // `parent_offset` bytes from the buffer's start.
    let payload_idx = ptr_payloads
        .iter()
        .position(|p| p.offset_index as usize == parent);
    let Some(idx) = payload_idx else {
        return Ok(());
    };
    let payload = &ptr_payloads[idx];
    let payload_data_tvb = payload_tvb[idx].1;

    for k in 0..num_fds {
        let fd_off_in_payload = parent_offset + k * 4;
        if fd_off_in_payload + 4 > payload.data.len() {
            // The payload was truncated; rendering the rest of the fd values
            // would point at bytes that aren't in tvb, so stop here.
            break;
        }
        unsafe {
            epan::proto_tree_add_item(
                tree,
                refs.fds,
                tvb,
                (payload_data_tvb + fd_off_in_payload).try_into()?,
                4,
                epan::ENC_LITTLE_ENDIAN,
            );
        }
    }

    Ok(())
}

/// Fully decoded view of one flat_binder_object / binder_buffer_object found
/// by walking `TransactionProtocol.offsets`. Shared between the main
/// dissector (which renders proto-tree entries via tvb add_item, keyed on
/// `kind` for the variant size) and the Follow Stream view (which renders
/// the same info as a text summary).
#[derive(Debug, Clone)]
pub struct OffsetSummary {
    pub idx: u32,
    pub offset_in_buffer: u64,
    pub kind: OffsetKind,
}

#[derive(Debug, Clone)]
pub enum OffsetKind {
    Binder {
        weak: bool,
        ptr: u64,
        cookie: u64,
    },
    Handle {
        weak: bool,
        handle: u32,
        cookie: u64,
    },
    Fd {
        fd: i32,
    },
    FdArray {
        num_fds: u64,
        parent: u64,
    },
    Ptr {
        size: u64,
        buffer_addr: u64,
        parent: u64,
        payload: Option<Vec<u8>>,
    },
}

/// Walk `txn.offsets` (8-byte-per-entry array of byte offsets into
/// `txn.data`) and parse each flat_binder_object / binder_buffer_object it
/// points at. PTR entries get their captured payload attached by matching
/// on `offset_index`. Uses the shared `iter_flat_objects` walker so this
/// path and the main dissector path stay in lock-step. Errors on an
/// unrecognised type id or a truncated object — refusing to silently drop
/// bad data so the post-dissector + the Follow Stream view agree.
pub fn parse_offset_summaries(txn: &TransactionProtocol) -> anyhow::Result<Vec<OffsetSummary>> {
    let mut out = Vec::new();
    for FlatObjectEntry {
        idx,
        pos,
        type_id,
        parsed,
    } in iter_flat_objects(&txn.data, &txn.offsets)
    {
        let kind = decode_kind(&txn.data, pos, type_id, parsed, idx, &txn.ptr_payloads)?;
        out.push(OffsetSummary {
            idx: idx as u32,
            offset_in_buffer: pos as u64,
            kind,
        });
    }
    Ok(out)
}

fn decode_kind(
    data: &[u8],
    pos: usize,
    type_id: u32,
    parsed: ParsedEntry,
    entry_idx: usize,
    ptr_payloads: &[PtrPayload],
) -> anyhow::Result<OffsetKind> {
    let need = |size: usize| -> anyhow::Result<()> {
        if pos + size > data.len() {
            return Err(anyhow!(
                "flat_binder_object at pos {} truncated (need {} bytes, have {})",
                pos,
                size,
                data.len().saturating_sub(pos)
            ));
        }
        Ok(())
    };
    Ok(match parsed {
        ParsedEntry::Binder => {
            need(SIZE_FLAT_BINDER)?;
            let ptr = read_u64(data, pos + 8).unwrap_or(0);
            let cookie = read_u64(data, pos + 16).unwrap_or(0);
            OffsetKind::Binder {
                weak: type_id == T_WEAK_BINDER,
                ptr,
                cookie,
            }
        }
        ParsedEntry::Handle => {
            need(SIZE_FLAT_BINDER)?;
            let handle = read_u32(data, pos + 8).unwrap_or(0);
            let cookie = read_u64(data, pos + 16).unwrap_or(0);
            OffsetKind::Handle {
                weak: type_id == T_WEAK_HANDLE,
                handle,
                cookie,
            }
        }
        ParsedEntry::Fd => {
            need(SIZE_FLAT_FD)?;
            let fd = read_u32(data, pos + 8).unwrap_or(0) as i32;
            OffsetKind::Fd { fd }
        }
        ParsedEntry::Fda => {
            need(SIZE_FLAT_FDA)?;
            let num_fds = read_u64(data, pos + 8).unwrap_or(0);
            let parent = read_u64(data, pos + 16).unwrap_or(0);
            OffsetKind::FdArray { num_fds, parent }
        }
        ParsedEntry::Ptr => {
            need(SIZE_FLAT_PTR)?;
            let buffer_addr = read_u64(data, pos + 8).unwrap_or(0);
            let size = read_u64(data, pos + 16).unwrap_or(0);
            let parent = read_u64(data, pos + 24).unwrap_or(0);
            let payload = ptr_payloads
                .iter()
                .find(|p| p.offset_index as usize == entry_idx)
                .map(|p| p.data.clone());
            OffsetKind::Ptr {
                size,
                buffer_addr,
                parent,
                payload,
            }
        }
        ParsedEntry::Unknown => {
            return Err(anyhow!(
                "unknown flat_binder_object type 0x{:x} at pos {}",
                type_id,
                pos
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure-logic walker wrapper used by the tests below. Yields just the
    // (pos, type_id) pairs the older tests assert against.
    fn parse_offset_entries(data: &[u8], offsets: &[u8]) -> Vec<(usize, u32)> {
        iter_flat_objects(data, offsets)
            .map(|e| (e.pos, e.type_id))
            .collect()
    }

    fn write_offsets(entries: &[u64]) -> Vec<u8> {
        let mut v = Vec::new();
        for e in entries {
            v.extend_from_slice(&e.to_le_bytes());
        }
        v
    }

    fn make_flat_binder(type_: u32, flags: u32, binder: u64, cookie: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&type_.to_le_bytes());
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(&binder.to_le_bytes());
        v.extend_from_slice(&cookie.to_le_bytes());
        v
    }

    #[test]
    fn parse_one_binder() {
        let obj = make_flat_binder(binder_type::BINDER as u32, 0x100, 0xdead_beef, 0xcafe);
        let offsets = write_offsets(&[0]);
        let parsed = parse_offset_entries(&obj, &offsets);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, 0);
        assert_eq!(parsed[0].1, binder_type::BINDER as u32);
    }

    #[test]
    fn parse_two_handles() {
        let mut data = Vec::new();
        data.extend(make_flat_binder(binder_type::HANDLE as u32, 0, 5, 0));
        data.extend(make_flat_binder(binder_type::WEAK_HANDLE as u32, 0, 7, 0));
        let offsets = write_offsets(&[0, 24]);
        let parsed = parse_offset_entries(&data, &offsets);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].1, binder_type::HANDLE as u32);
        assert_eq!(parsed[1].1, binder_type::WEAK_HANDLE as u32);
    }
}
