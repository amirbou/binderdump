use binderdump_epan_sys::epan;
use binderdump_structs;
use binderdump_structs::event_layer::EventProtocol;
use binderdump_trait::{EpanProtocol, EpanProtocolEnum};
use core::slice;
use std::collections::HashMap;
use std::ffi::{c_int, c_void, CStr, CString};
use std::ptr::null_mut;
use std::sync::OnceLock;

use crate::binderdump::dissect_bwr_data;
use crate::binderdump::AddBinderTypes;
use crate::dissect_offsets;
use crate::header_fields_manager::{
    FieldHandler, FieldHandlerFunc, HeaderField, HeaderFieldsManager,
};

pub struct Protocol {
    name: &'static CStr,
    short_name: &'static CStr,
    filter: &'static CStr,
    handle: c_int,
    exported_pdu_tap: c_int,
    dissector: Dissector,
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
        };

        proto.register_proto();
        proto.register_dissector();
        proto.register_exported_pdu_tap();
        proto.register_hf_array();
        proto.register_subtrees();

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

    fn add_exported_pdu(&self, tvb: *mut epan::tvbuff_t, pinfo: *mut epan::packet_info) {
        unsafe {
            if epan::have_tap_listener(self.exported_pdu_tap) != 0 {
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

            let source = format!(
                "{}:{}:{}",
                event.pid,
                event.tid,
                String::from_utf8(event.cmdline)?
            );
            let csource = CString::new(source)?;
            let mut ctarget = None;
            let mut switch_src_dst = false;

            if let Some(ioctl) = event.ioctl_data {
                if let Some(bwr) = ioctl.bwr {
                    // on READ transactions, we want the src to be we sending process instead
                    switch_src_dst = bwr.is_read();
                    if let Some(txn) = bwr.transaction {
                        let target = format!(
                            "{}:{}:{}",
                            txn.transaction.to_proc,
                            txn.transaction.to_thread,
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

const PROTOCOL_NAME: &'static CStr = c"Android Binderdump";
const PROTOCOL_SHORT_NAME: &'static CStr = c"Binderdump";
const PROTOCOL_FILTER: &'static CStr = c"binderdump";

pub extern "C" fn register_protoinfo() {
    G_PROTOCOL.get_or_init(|| {
        ProtocolBuilder::new(PROTOCOL_NAME, PROTOCOL_SHORT_NAME, PROTOCOL_FILTER)
            .add_custom_handler("binderdump.ioctl_data.bwr.data", dissect_bwr_data)
            .add_bc_types()
            .add_br_types()
            .build()
    });
}

pub extern "C" fn register_handoff() {
    let table = CString::new("wtap_encap").unwrap();

    unsafe {
        epan::dissector_add_uint(
            table.as_ptr(),
            epan::WTAP_ENCAP_USER0, // TODO - configure during compilation
            G_PROTOCOL.get().unwrap().dissector.handle.0,
        )
    };
}
