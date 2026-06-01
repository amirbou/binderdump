use anyhow::anyhow;
use binderdump_epan_sys::epan;
use binderdump_structs;
use binderdump_structs::binder_serde::FieldOffset;
use binderdump_structs::event_layer::EventProtocol;
use binderdump_trait::{EpanProtocol, EpanProtocolEnum};
use core::slice;
use std::collections::HashMap;
use std::ffi::{c_int, c_void, CStr, CString};
use std::ptr::null_mut;
use std::sync::{Mutex, OnceLock};

use crate::binderdump::collect_command_names;
use crate::col_info::{self, ColInputs, Direction};
use crate::txn_link::TxnLinkTable;

use crate::aidl_resolve;
use crate::binderdump::dissect_bwr_data;
use crate::binderdump::AddBinderTypes;
use crate::dissect_flat_objects;
use crate::dissect_offsets;
use crate::header_fields_manager::{
    FieldHandler, FieldHandlerFunc, HeaderField, HeaderFieldsManager,
};
use binderdump_structs::binder_types::{
    binder_type, FlatBinder, FlatFd, FlatFda, FlatHandle, FlatPtr,
};
use binderdump_trait::{FieldDisplay, FieldInfo, FtEnum};

pub struct Protocol {
    name: &'static CStr,
    short_name: &'static CStr,
    filter: &'static CStr,
    handle: c_int,
    exported_pdu_tap: c_int,
    dissector: Dissector,
    txn_link: Mutex<Option<TxnLinkTable>>,
}

impl Protocol {
    pub fn register(
        name: &'static CStr,
        short_name: &'static CStr,
        filter: &'static CStr,
        custom: HashMap<&'static str, FieldHandler<EventProtocol>>,
        extra_fields: Vec<HeaderField>,
        extra_subtrees: Vec<String>,
    ) -> Self {
        let mut proto = Self {
            name,
            short_name,
            filter,
            handle: -1,
            exported_pdu_tap: -1,
            dissector: Dissector {
                handle: DissectorHandle(null_mut()),
                field_manager: HeaderFieldsManager::new(
                    short_name.to_string_lossy().into_owned(),
                    filter.to_string_lossy().into_owned(),
                    custom,
                    extra_fields,
                    extra_subtrees,
                )
                .unwrap(),
            },
            txn_link: Mutex::new(None),
        };

        proto.register_proto();
        proto.register_dissector();
        proto.register_exported_pdu_tap();
        proto.register_hf_array();
        proto.register_subtrees();
        proto.register_prefs();

        proto
    }

    fn register_proto(&mut self) {
        self.handle = unsafe {
            epan::proto_register_protocol(
                self.name.as_ptr(),
                self.short_name.as_ptr(),
                self.filter.as_ptr(),
            )
        };
    }

    fn register_prefs(&self) {
        // Wireshark 4.x rejects a second prefs_register_protocol() call for the
        // same proto_id, so register the module once and add both prefs to it.
        unsafe {
            let module = epan::prefs_register_protocol(self.handle, None);
            if module.is_null() {
                return;
            }
            register_aidl_overlay_pref(module);
            register_aosp_dir_pref(module);
        }
    }

    fn register_dissector(&mut self) {
        self.dissector.handle.0 =
            unsafe { epan::register_dissector(self.filter.as_ptr(), Some(dissect), self.handle) };
    }

    fn register_exported_pdu_tap(&mut self) {
        self.exported_pdu_tap = unsafe { epan::register_export_pdu_tap(self.name.as_ptr()) };
    }

    fn register_hf_array(&mut self) {
        self.dissector.field_manager.register(self.handle);
    }

    fn register_subtrees(&mut self) {
        self.dissector.field_manager.register_subtrees();
    }

    fn ensure_table(&self) -> std::sync::MutexGuard<'_, Option<TxnLinkTable>> {
        let mut guard = self.txn_link.lock().unwrap();
        let need_new = match guard.as_ref() {
            None => true,
            Some(t) => unsafe { t.current_scope() != epan::wmem_file_scope() },
        };
        if need_new {
            *guard = Some(TxnLinkTable::new());
        }
        guard
    }

    fn record_and_render_frame_link(
        &self,
        event: &binderdump_structs::event_layer::EventProtocol,
        pinfo: *mut epan::packet_info,
        tvb: *mut epan::tvbuff_t,
        tree_item: *mut epan::proto_node,
    ) {
        let Some(bwr) = event.ioctl_data.as_ref().and_then(|i| i.bwr.as_ref()) else {
            return;
        };
        let Some(txn) = bwr.transaction.as_ref() else {
            return;
        };
        let debug_id = txn.debug_id;
        if debug_id == 0 {
            return;
        }

        let direction = if bwr.is_write() {
            Direction::Bc
        } else {
            Direction::Br
        };
        let frame_num = unsafe { (*(*pinfo).fd).num };
        let visited = unsafe { (*(*pinfo).fd).visited() != 0 };

        let guard = self.ensure_table();
        let Some(table) = guard.as_ref() else { return };

        if !visited {
            match direction {
                Direction::Bc => table.record_bc(debug_id, frame_num),
                Direction::Br => table.record_br(debug_id, frame_num),
            }
        }

        let Some(link) = table.lookup(debug_id) else {
            return;
        };
        let bc_hf = self
            .dissector
            .field_manager
            .get_handle("binderdump.ioctl_data.bwr.transaction.bc_frame")
            .unwrap_or(-1);
        let br_hf = self
            .dissector
            .field_manager
            .get_handle("binderdump.ioctl_data.bwr.transaction.br_frame")
            .unwrap_or(-1);
        unsafe {
            if direction == Direction::Br && link.bc_frame != 0 && bc_hf >= 0 {
                epan::proto_tree_add_uint(tree_item, bc_hf, tvb, 0, 0, link.bc_frame);
            }
            if direction == Direction::Bc && link.br_frame != 0 && br_hf >= 0 {
                epan::proto_tree_add_uint(tree_item, br_hf, tvb, 0, 0, link.br_frame);
            }
        }
    }

    fn add_exported_pdu(&self, tvb: *mut epan::tvbuff_t, pinfo: *mut epan::packet_info) {
        unsafe {
            if epan::have_tap_listener(self.exported_pdu_tap) {
                let exp_pdu_data = epan::export_pdu_create_tags(
                    pinfo,
                    self.filter.as_ptr(),
                    epan::EXP_PDU_TAG_PROTO_NAME as u16,
                    null_mut(),
                );

                (*exp_pdu_data).tvb_captured_length = epan::tvb_captured_length(tvb);
                (*exp_pdu_data).tvb_reported_length = epan::tvb_reported_length(tvb);
                (*exp_pdu_data).pdu_tvb = tvb;
                epan::tap_queue_packet(self.exported_pdu_tap, pinfo, exp_pdu_data as *mut c_void);
            }
        };
    }

    pub fn dissect(
        &self,
        tvb: *mut epan::tvbuff_t,
        pinfo: *mut epan::packet_info,
        tree: *mut epan::proto_tree,
        _data: *mut c_void,
    ) -> anyhow::Result<c_int> {
        unsafe {
            epan::col_set_str(
                (*pinfo).cinfo,
                epan::COL_PROTOCOL as c_int,
                self.short_name.as_ptr(),
            );
            epan::col_clear((*pinfo).cinfo, epan::COL_INFO as c_int);
            self.add_exported_pdu(tvb, pinfo);

            let len = epan::tvb_captured_length(tvb);
            let tree_item = epan::proto_tree_add_item(tree, self.handle, tvb, 0, -1, epan::ENC_NA);

            // per-frame version check via the IDB IfDescription option set by
            // the capture binary. fail the dissector when the pcap's
            // binderdump version doesn't match the one we were built against,
            // since wire-format compat across versions isn't promised.
            let interface_id = (*(*pinfo).rec).rec_header.packet_header.interface_id;
            let section_number = (*(*pinfo).rec).section_number;
            let descr_ptr =
                epan::epan_get_interface_description((*pinfo).epan, interface_id, section_number);
            if !descr_ptr.is_null() {
                let descr = CStr::from_ptr(descr_ptr);
                if let Ok(s) = descr.to_str() {
                    if let Some(captured) =
                        crate::version_check::captured_version_from_idb_description(s)
                    {
                        if crate::version_check::is_mismatch(captured) {
                            return Err(anyhow!(
                                "binderdump version mismatch: pcap captured with {}, dissector built against {}",
                                captured,
                                crate::version_check::DISSECTOR_VERSION
                            ));
                        }
                    }
                }
            }

            let data = epan::tvb_get_ptr(tvb, 0, len.try_into()?);
            let data = slice::from_raw_parts(data, len.try_into()?);

            let (event, offsets) = binderdump_structs::binder_serde::from_bytes_with_offsets::<
                binderdump_structs::event_layer::EventProtocol,
            >(data)?;

            let offsets = offsets?;

            dissect_offsets::dissect_offsets(
                &event,
                offsets,
                &self.dissector.field_manager,
                self.filter.to_string_lossy().into_owned(),
                tvb,
                pinfo,
                tree_item,
            )?;

            // first pass only: walk the BWR data buffer to feed
            // txn_complete_tracker so BR_TRANSACTION_COMPLETE frames can be
            // attributed to the BC that they ACK.
            let visited = (*(*pinfo).fd).visited() != 0;
            if !visited {
                if let Some(ioctl) = event.ioctl_data.as_ref() {
                    if let Some(bwr) = ioctl.bwr.as_ref() {
                        let frame = (*(*pinfo).fd).num;
                        let txn_debug_id = bwr.transaction.as_ref().map(|t| t.debug_id);
                        crate::txn_complete_tracker::process_bwr_data(
                            frame,
                            event.pid,
                            event.tid,
                            bwr.is_write(),
                            &bwr.data,
                            txn_debug_id,
                        );
                    }
                }
            }

            let source = format!(
                "{}:{}:{}",
                event.pid,
                event.tid,
                String::from_utf8(event.cmdline.clone())?
            );
            let csource = CString::new(source)?;
            let mut ctarget = None;
            let mut switch_src_dst = false;

            self.record_and_render_frame_link(&event, pinfo, tvb, tree_item);

            let col_string = build_col_string(&event);

            if let Some(ioctl) = event.ioctl_data {
                if let Some(bwr) = ioctl.bwr {
                    // on READ transactions, we want the src to be we sending process instead
                    switch_src_dst = bwr.is_read();
                    if let Some(txn) = bwr.transaction {
                        let target = format!(
                            "{}:{}:{}",
                            txn.to_proc,
                            txn.to_thread,
                            String::from_utf8(txn.target_cmdline)?
                        );

                        ctarget = Some(CString::new(target)?);
                    }
                }
            }

            let mut src_col = epan::COL_DEF_SRC;
            let mut dst_col = epan::COL_DEF_DST;
            if switch_src_dst {
                src_col = epan::COL_DEF_DST;
                dst_col = epan::COL_DEF_SRC;
            }

            epan::col_add_str((*pinfo).cinfo, src_col as c_int, csource.as_ptr());
            let ctarget = match ctarget {
                Some(ctarget) => ctarget,
                None => c"KERNEL".into(),
            };
            epan::col_add_str((*pinfo).cinfo, dst_col as c_int, ctarget.as_ptr());

            if !col_string.is_empty() {
                let cstr = std::ffi::CString::new(col_string)
                    .unwrap_or_else(|_| std::ffi::CString::default());
                epan::col_add_str((*pinfo).cinfo, epan::COL_INFO as c_int, cstr.as_ptr());
            }

            Ok(epan::tvb_captured_length(tvb) as c_int)
        }
    }
}

pub struct ProtocolBuilder {
    name: &'static CStr,
    short_name: &'static CStr,
    filter: &'static CStr,
    custom: HashMap<&'static str, FieldHandler<EventProtocol>>,
    extra_fields: Vec<HeaderField>,
    extra_subtrees: Vec<String>,
}

impl ProtocolBuilder {
    pub fn new(name: &'static CStr, short_name: &'static CStr, filter: &'static CStr) -> Self {
        Self {
            name,
            short_name,
            filter,
            custom: HashMap::new(),
            extra_fields: Vec::new(),
            extra_subtrees: Vec::new(),
        }
    }

    pub fn build(self) -> Protocol {
        Protocol::register(
            self.name,
            self.short_name,
            self.filter,
            self.custom,
            self.extra_fields,
            self.extra_subtrees,
        )
    }

    pub fn add_custom_handler(
        mut self,
        field: &'static str,
        handler: FieldHandlerFunc<EventProtocol>,
    ) -> Self {
        self.custom.insert(field, FieldHandler::new(handler));
        self
    }

    fn add_epan_type<T: EpanProtocol>(
        mut self,
        name: &'static str,
        abbrev: &'static str,
        add_subtree: bool,
    ) -> Self {
        let info = T::get_info(name.to_string(), abbrev.to_string(), None, None);

        for field in info {
            let field = HeaderField::try_from(field).unwrap();
            self.extra_fields.push(field);
        }

        if add_subtree {
            self.extra_subtrees
                .extend(T::get_subtrees(abbrev.to_string()));
        }

        self
    }

    pub fn add_extra_type<T: EpanProtocol>(self, name: &'static str, abbrev: &'static str) -> Self {
        self.add_epan_type::<T>(name, abbrev, true)
    }

    pub fn add_extra_enum<T: EpanProtocolEnum>(
        self,
        name: &'static str,
        abbrev: &'static str,
    ) -> Self {
        self.add_epan_type::<T>(name, abbrev, false)
    }

    pub fn add_extra_subtree(mut self, abbrev: &'static str) -> Self {
        self.extra_subtrees.push(abbrev.to_string());
        self
    }

    pub fn add_extra_field(mut self, info: FieldInfo) -> Self {
        let field = HeaderField::try_from(info).unwrap();
        self.extra_fields.push(field);
        self
    }
}

struct Dissector {
    handle: DissectorHandle,
    field_manager: HeaderFieldsManager<EventProtocol>,
}

extern "C" fn dissect(
    tvb: *mut epan::tvbuff_t,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_tree,
    data: *mut c_void,
) -> c_int {
    match G_PROTOCOL.get().unwrap().dissect(tvb, pinfo, tree, data) {
        Ok(count) => count,
        Err(err) => {
            eprintln!("Dissection error: {}", err);
            -1
        }
    }
}

struct DissectorHandle(epan::dissector_handle_t);

unsafe impl Send for DissectorHandle {}
unsafe impl Sync for DissectorHandle {}

static G_PROTOCOL: OnceLock<Protocol> = OnceLock::new();

unsafe extern "C" fn binderdump_init_routine() {
    crate::reply_correlation::clear();
    crate::follow_stream::clear();
    crate::txn_complete_tracker::clear();
}

const PROTOCOL_NAME: &'static CStr = c"Android Binderdump";
const PROTOCOL_SHORT_NAME: &'static CStr = c"Binderdump";
const PROTOCOL_FILTER: &'static CStr = c"binderdump";

pub extern "C" fn register_protoinfo() {
    G_PROTOCOL.get_or_init(|| {
        ProtocolBuilder::new(PROTOCOL_NAME, PROTOCOL_SHORT_NAME, PROTOCOL_FILTER)
            .add_custom_handler("binderdump.ioctl_data.bwr.data", dissect_bwr_data)
            .add_custom_handler(
                "binderdump.ioctl_data.bwr.transaction.code",
                handle_transaction_code,
            )
            .add_custom_handler(
                "binderdump.ioctl_data.bwr.transaction.offsets",
                dissect_flat_objects::dissect_offsets_array,
            )
            .add_extra_enum::<binder_type>(
                "Object Type",
                "binderdump.ioctl_data.bwr.transaction.offsets.entry.type",
            )
            .add_extra_type::<FlatBinder>(
                "Flat Binder",
                "binderdump.ioctl_data.bwr.transaction.offsets.entry.binder",
            )
            .add_extra_type::<FlatHandle>(
                "Flat Handle",
                "binderdump.ioctl_data.bwr.transaction.offsets.entry.handle",
            )
            .add_extra_type::<FlatFd>(
                "Flat FD",
                "binderdump.ioctl_data.bwr.transaction.offsets.entry.fd",
            )
            .add_extra_type::<FlatPtr>(
                "Flat PTR",
                "binderdump.ioctl_data.bwr.transaction.offsets.entry.ptr",
            )
            .add_extra_type::<FlatFda>(
                "Flat FDA",
                "binderdump.ioctl_data.bwr.transaction.offsets.entry.fda",
            )
            .add_extra_subtree("binderdump.ioctl_data.bwr.transaction.offsets.entry")
            .add_extra_field(FieldInfo {
                name: "Interface".into(),
                abbrev: "binderdump.ioctl_data.bwr.transaction.interface".into(),
                ftype: FtEnum::String,
                display: FieldDisplay::StrAsciis,
                strings: None,
            })
            .add_extra_field(FieldInfo {
                name: "Method".into(),
                abbrev: "binderdump.ioctl_data.bwr.transaction.method_name".into(),
                ftype: FtEnum::String,
                display: FieldDisplay::StrAsciis,
                strings: None,
            })
            .add_extra_field(FieldInfo {
                name: "Method source".into(),
                abbrev: "binderdump.ioctl_data.bwr.transaction.method_source".into(),
                ftype: FtEnum::String,
                display: FieldDisplay::StrAsciis,
                strings: None,
            })
            .add_extra_field(FieldInfo {
                name: "BC Frame".into(),
                abbrev: "binderdump.ioctl_data.bwr.transaction.bc_frame".into(),
                ftype: FtEnum::FrameNum,
                display: FieldDisplay::None,
                strings: None,
            })
            .add_extra_field(FieldInfo {
                name: "BR Frame".into(),
                abbrev: "binderdump.ioctl_data.bwr.transaction.br_frame".into(),
                ftype: FtEnum::FrameNum,
                display: FieldDisplay::None,
                strings: None,
            })
            .add_bc_types()
            .add_br_types()
            .build()
    });
    let proto_id = G_PROTOCOL.get().expect("registered").handle;
    // register_tap must be called in proto_register (not register_handoff) so
    // that find_tap_id("binderdump") succeeds when tshark sets up the -z follow
    // listener, which happens after epan_init but the tap lookup runs before
    // any packet is read.
    let tap_id = unsafe { epan::register_tap(c"binderdump".as_ptr()) };
    crate::follow_stream::store_tap_id(tap_id);
    crate::follow_stream::register(proto_id);
    crate::reply_postdissector::register();
}

fn comm_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("").to_string()
}

fn add_string_item(
    tree: *mut epan::proto_node,
    hf: c_int,
    tvb: *mut epan::tvbuff,
    offset: usize,
    length: i32,
    value: &str,
) -> anyhow::Result<()> {
    if hf < 0 {
        return Ok(());
    }
    let cs = CString::new(value).unwrap_or_else(|_| CString::new("<invalid>").unwrap());
    unsafe {
        epan::proto_tree_add_string(tree, hf, tvb, offset.try_into()?, length, cs.as_ptr());
    }
    Ok(())
}

fn handle_transaction_code(
    hf: c_int,
    _ett: c_int,
    manager: &HeaderFieldsManager<EventProtocol>,
    base: &EventProtocol,
    offset: FieldOffset,
    tvb: *mut epan::tvbuff,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_node,
) -> anyhow::Result<()> {
    // 1. Render the transaction code field as the default handler would.
    unsafe {
        epan::proto_tree_add_item(
            tree,
            hf,
            tvb,
            offset.offset.try_into()?,
            offset.size.try_into()?,
            epan::ENC_LITTLE_ENDIAN,
        );
    }

    // 2. Pull the captured transaction's data buffer + code from the event.
    let Some(ioctl) = base.ioctl_data.as_ref() else {
        return Ok(());
    };
    let Some(bwr) = ioctl.bwr.as_ref() else {
        return Ok(());
    };
    let Some(txn) = bwr.transaction.as_ref() else {
        return Ok(());
    };

    // 3. Resolve interface + method via the AIDL/HIDL registry.
    //    replies don't carry a writeInterfaceToken so we skip resolution for
    //    them; they receive an empty result.
    let r = if txn.reply == 0 {
        let code = txn.code;
        let data_buf: &[u8] = &txn.data;
        let registry = aidl_resolve::registry();
        aidl_resolve::resolve(
            registry,
            base.binder_interface(),
            code,
            base.android_sdk(),
            data_buf,
        )
    } else {
        aidl_resolve::ResolvedTransaction {
            interface: None,
            method_name: None,
            method_source: "",
            overlay_path: None,
        }
    };

    // record per-frame metadata for the reply_correlation post-dissector on
    // first pass only.
    let visited = unsafe { (*(*pinfo).fd).visited() != 0 };
    if !visited {
        let frame = unsafe { (*(*pinfo).fd).num };
        let abs_ts = unsafe { (*(*pinfo).fd).abs_ts };
        crate::reply_correlation::record_frame(
            frame,
            abs_ts,
            txn.debug_id,
            txn.in_reply_to_debug_id,
            txn.reply,
            base.pid,
            r.interface.clone(),
            r.method_name.clone(),
        );

        let td = crate::follow_stream::TapData {
            debug_id: txn.debug_id,
            in_reply_to_debug_id: txn.in_reply_to_debug_id,
            reply: txn.reply,
            code: txn.code,
            flags: txn.flags,
            interface: r.interface.clone(),
            method: r.method_name.clone(),
            src_pid: base.pid,
            src_cmdline: comm_to_string(&base.cmdline),
            dst_pid: txn.to_proc,
            dst_cmdline: comm_to_string(&txn.target_cmdline),
            data: txn.data.clone(),
            abs_ts,
            offsets: crate::follow_stream::parse_offset_summaries(txn)?,
        };
        crate::follow_stream::insert(frame, td);
    }

    // queue to the binderdump tap every pass (cheap when no listener is
    // attached). the callback looks up TapData from the pool by frame number,
    // so the data pointer is only used as a non-NULL marker.
    if let Some(tap_id) = crate::follow_stream::tap_id() {
        unsafe {
            epan::tap_queue_packet(tap_id, pinfo, crate::follow_stream::frame_marker());
        }
    }

    if txn.reply != 0 {
        return Ok(());
    }

    // 4. Add interface / method_name / method_source fields. Anchor them at
    //    the same tvb offset as the code field with length 0 so they appear
    //    alongside it in the protocol tree without claiming extra bytes.
    if let Some(iface_str) = r.interface.as_deref() {
        let h = manager
            .get_handle("binderdump.ioctl_data.bwr.transaction.interface")
            .unwrap_or(-1);
        add_string_item(tree, h, tvb, offset.offset, 0, iface_str)?;
    }
    if let Some(m) = r.method_name.as_deref() {
        let h = manager
            .get_handle("binderdump.ioctl_data.bwr.transaction.method_name")
            .unwrap_or(-1);
        add_string_item(tree, h, tvb, offset.offset, 0, m)?;
    }
    let label = match r.overlay_path.as_deref() {
        Some(p) => format!("overlay:{}", p),
        None => r.method_source.to_string(),
    };
    let h = manager
        .get_handle("binderdump.ioctl_data.bwr.transaction.method_source")
        .unwrap_or(-1);
    add_string_item(tree, h, tvb, offset.offset, 0, &label)?;

    Ok(())
}

pub extern "C" fn register_handoff() {
    unsafe {
        epan::register_init_routine(Some(binderdump_init_routine));
    }

    let table = CString::new("wtap_encap").unwrap();

    unsafe {
        epan::dissector_add_uint(
            table.as_ptr(),
            epan::WTAP_ENCAP_USER0, // TODO - configure during compilation
            G_PROTOCOL.get().unwrap().dissector.handle.0,
        )
    };

    // Wireshark has finished reading user prefs by the time handoff runs, so
    // OVERLAY_DIR / AOSP_DIR now point at either the defaults or the user's
    // overrides. Build the AIDL/HIDL Registry from both.
    let aosp = unsafe {
        if AOSP_DIR.is_null() {
            default_aosp_dir()
        } else {
            CStr::from_ptr(AOSP_DIR)
                .to_str()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| default_aosp_dir())
        }
    };
    let overlay = unsafe {
        if OVERLAY_DIR.is_null() {
            default_overlay_dir()
        } else {
            CStr::from_ptr(OVERLAY_DIR)
                .to_str()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| default_overlay_dir())
        }
    };
    aidl_resolve::init_registry(&aosp, &overlay);
    crate::reply_postdissector::register_handoff();
}

/// Storage for the `aidl_overlay_dir` Wireshark preference. Wireshark reads
/// and writes this pointer directly (it owns the buffer) so we hold it as a
/// raw `*const c_char` in a static. The initial value is leaked from a
/// CString so the pointer stays valid for the lifetime of the process.
static mut OVERLAY_DIR: *const std::os::raw::c_char = std::ptr::null();

fn default_overlay_dir() -> std::path::PathBuf {
    dirs::config_dir()
        .map(|c| c.join("wireshark").join("binderdump").join("aidl"))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

unsafe fn register_aidl_overlay_pref(module: *mut epan::module_t) {
    // Leak the strings: Wireshark stores the raw pointers and dereferences
    // them later, so they must outlive the call. They live for the lifetime
    // of the plugin / process.
    let name = CString::new("aidl_overlay_dir").unwrap().into_raw();
    let title = CString::new("AIDL/HIDL overlay directory")
        .unwrap()
        .into_raw();
    let descr = CString::new(
        "Directory scanned for user .aidl/.hal files (in addition to the bundled AOSP definitions).",
    )
    .unwrap()
    .into_raw();
    let default = CString::new(default_overlay_dir().to_string_lossy().as_ref())
        .unwrap()
        .into_raw();
    OVERLAY_DIR = default as *const _;

    epan::prefs_register_directory_preference(module, name, title, descr, &raw mut OVERLAY_DIR);
}

static mut AOSP_DIR: *const std::os::raw::c_char = std::ptr::null();

fn default_aosp_dir() -> std::path::PathBuf {
    dirs::config_dir()
        .map(|c| c.join("wireshark").join("binderdump").join("aosp"))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

unsafe fn register_aosp_dir_pref(module: *mut epan::module_t) {
    let name = CString::new("aosp_corpus_dir").unwrap().into_raw();
    let title = CString::new("AOSP AIDL/HIDL corpus directory")
        .unwrap()
        .into_raw();
    let descr = CString::new(
        "Directory containing android-<sdk>/{aidl,hal}/ subtrees of AOSP definitions, loaded lazily.",
    )
    .unwrap()
    .into_raw();
    let default = CString::new(default_aosp_dir().to_string_lossy().as_ref())
        .unwrap()
        .into_raw();
    AOSP_DIR = default as *const _;

    epan::prefs_register_directory_preference(module, name, title, descr, &raw mut AOSP_DIR);
}

fn build_col_string(event: &binderdump_structs::event_layer::EventProtocol) -> String {
    let Some(ioctl) = event.ioctl_data.as_ref() else {
        return String::new();
    };
    let Some(bwr) = ioctl.bwr.as_ref() else {
        return String::new();
    };

    let raw_names = collect_command_names(bwr.is_write(), &bwr.data);
    let raw_refs: Vec<&str> = raw_names.iter().copied().collect();

    let (has_transaction, is_reply, iface, method, code) = match bwr.transaction.as_ref() {
        Some(txn) => {
            let is_reply = txn.reply != 0;
            if is_reply {
                (true, true, None, None, 0)
            } else {
                let r = crate::aidl_resolve::resolve(
                    crate::aidl_resolve::registry(),
                    event.binder_interface(),
                    txn.code,
                    event.android_sdk(),
                    &txn.data,
                );
                (
                    true,
                    false,
                    r.interface.clone(),
                    r.method_name.clone(),
                    txn.code,
                )
            }
        }
        None => (false, false, None, None, 0),
    };

    let is_oneway = match bwr.transaction.as_ref() {
        Some(txn) => !is_reply && (txn.flags & 0x01) != 0,
        None => false,
    };

    let is_special = !is_reply
        && bwr
            .transaction
            .as_ref()
            .is_some_and(|txn| binderdump_aidl::registry::lookup_special(txn.code).is_some());

    let inputs = ColInputs {
        is_reply,
        iface: iface.as_deref(),
        method: method.as_deref(),
        code,
        raw_commands: &raw_refs,
        has_transaction,
        is_oneway,
        is_special,
    };
    col_info::format(&inputs)
}
