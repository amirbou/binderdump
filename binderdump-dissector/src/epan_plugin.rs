use binderdump_epan_sys::epan;
use binderdump_structs;
use binderdump_structs::binder_serde::FieldOffset;
use binderdump_structs::binder_types::binder_command;
use binderdump_structs::binder_types::binder_return;
use binderdump_structs::binder_types::bwr_trait::Bwr;
use binderdump_structs::event_layer::EventProtocol;
use binderdump_trait::EpanProtocol;
use core::slice;
use std::collections::HashMap;
use std::ffi::{c_int, c_void, CStr, CString};
use std::ptr::null_mut;
use std::sync::OnceLock;

use crate::dissect_offsets;
use crate::header_fields_manager::{
    FieldHandler, FieldHandlerFunc, HeaderField, HeaderFieldsManager,
};

struct Protocol {
    name: &'static CStr,
    short_name: &'static CStr,
    filter: &'static CStr,
    // TODO - this can be static
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

    // fn proto_handle(&self) -> c_int {
    //     self.handle
    // }

    // fn dissector_handle(&self) -> epan::dissector_handle_t {
    //     self.dissector.handle.0
    // }

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
                tree_item,
            )?;

            let source = format!(
                "{}:{}:{}",
                event.pid,
                event.tid,
                String::from_utf8(event.cmdline)?
            );
            let csource = CString::new(source)?;
            epan::col_add_str((*pinfo).cinfo, epan::COL_DEF_SRC as c_int, csource.as_ptr());

            if let Some(ioctl) = event.ioctl_data {
                if let Some(bwr) = ioctl.bwr {
                    if let Some(txn) = bwr.transaction {
                        let target = format!(
                            "{}:{}:{}",
                            txn.transaction.to_proc,
                            txn.transaction.to_thread,
                            String::from_utf8(txn.target_cmdline)?
                        );
                        let ctarget = CString::new(target)?;
                        epan::col_add_str(
                            (*pinfo).cinfo,
                            epan::COL_DEF_DST as c_int,
                            ctarget.as_ptr(),
                        );
                    }
                }
            }

            Ok(epan::tvb_captured_length(tvb) as c_int)
        }
    }
}

struct ProtocolBuilder {
    name: &'static CStr,
    short_name: &'static CStr,
    filter: &'static CStr,
    custom: HashMap<&'static str, FieldHandler<EventProtocol>>,
    extra_fields: Vec<HeaderField>,
}

impl ProtocolBuilder {
    pub fn new(name: &'static CStr, short_name: &'static CStr, filter: &'static CStr) -> Self {
        Self {
            name,
            short_name,
            filter,
            custom: HashMap::new(),
            extra_fields: Vec::new(),
        }
    }

    pub fn build(self) -> Protocol {
        Protocol::register(
            self.name,
            self.short_name,
            self.filter,
            self.custom,
            self.extra_fields,
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

    pub fn add_extra_type<T: EpanProtocol>(
        mut self,
        name: &'static str,
        abbrev: &'static str,
    ) -> Self {
        let info = T::get_info(name.to_string(), abbrev.to_string(), None, None);

        for field in info {
            let field = HeaderField::try_from(field).unwrap();
            self.extra_fields.push(field);
        }

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

const PROTOCOL_NAME: &'static CStr = c"Android Binderdump";
const PROTOCOL_SHORT_NAME: &'static CStr = c"Binderdump";
const PROTOCOL_FILTER: &'static CStr = c"binderdump";

// fn dissect_bwr_impl<T: Bwr>(
//     handle: c_int,
//     data: &[u8],
//     offset: FieldOffset,
//     tvb: *mut epan::tvbuff,
//     tree: *mut epan::proto_node,
// ) -> anyhow::Result<()> {
//     let mut pos = 0;
//     while pos < data.len() {
//         let result = T::from_bytes(&data[pos..])?;

//         unsafe {
//             epan::proto_tree_add_subtree(
//                 tree,
//                 handle,
//                 tvb,
//                 field.offset.try_into()?,
//                 field.size.try_into()?,
//                 epan::ENC_LITTLE_ENDIAN,
//             );
//         }

//         pos += result.size();
//     }
//     if pos != data.len() {
//         return Err(anyhow::anyhow!(
//             "Only {} out of {} bytes comsumed from bwr write command",
//             pos,
//             data.len()
//         ));
//     }
//     Ok(())
// }

fn dissect_bwr_data(
    handle: c_int,
    event: &EventProtocol,
    offset: FieldOffset,
    tvb: *mut epan::tvbuff,
    tree: *mut epan::proto_node,
) -> anyhow::Result<()> {
    let bwr = event.ioctl_data.as_ref().unwrap().bwr.as_ref().unwrap();

    // if bwr.is_read() {
    //     dissect_bwr_impl::<BinderReturn>(handle, &bwr.data, offset, tvb, tree)
    // } else {
    //     dissect_bwr_impl::<BinderCommand>(handle, &bwr.data, offset, tvb, tree)
    // }
    todo!()
}

macro_rules! bc_prefix {
    ($s:literal) => {
        concat!("binderdump.ioctl_data.bwr.commands.", $s)
    };
}

macro_rules! br_prefix {
    ($s:literal) => {
        concat!("binderdump.ioctl_data.bwr.returns.", $s)
    };
}

trait AddBinderTypes {
    fn add_bc_types(self) -> Self;
    fn add_br_types(self) -> Self;
}

impl AddBinderTypes for ProtocolBuilder {
    fn add_bc_types(self) -> Self {
        self.add_extra_type::<binder_command::DeathCommand>(
            "Death Notification Request",
            bc_prefix!("death"),
        )
        .add_extra_type::<binder_command::RefCommand>("Ref", bc_prefix!("ref"))
        .add_extra_type::<binder_command::DeathDoneCommand>(
            "Dead Binder Done",
            bc_prefix!("dead_done"),
        )
        .add_extra_type::<binder_command::RefDoneCommand>("Ref Done", bc_prefix!("ref_done"))
        .add_extra_type::<binder_command::FreeBufferCommand>("Free Buffer", bc_prefix!("free"))
        .add_extra_type::<binderdump_structs::binder_types::transaction::Transaction>(
            "Transaction",
            bc_prefix!("transaction"),
        )
        .add_extra_type::<binderdump_structs::binder_types::transaction::TransactionSg>(
            "TransactionSg",
            bc_prefix!("transaction_sg"),
        )
    }

    fn add_br_types(self) -> Self {
        self.add_extra_type::<binder_return::RefReturn>("Ref", br_prefix!("ref"))
            .add_extra_type::<binder_return::ErrorReturn>("Error", br_prefix!("error"))
            .add_extra_type::<binder_return::DeadBinder>("Dead Binder", br_prefix!("dead_binder"))
            .add_extra_type::<binder_return::ClearDeathNotificationDone>(
                "Clear Death Notification Done",
                br_prefix!("clear_death_done"),
            )
            .add_extra_type::<binder_return::TransactionSecCtx>(
                "TransactionSecCtx",
                br_prefix!("transaction_secctx"),
            )
            .add_extra_type::<binderdump_structs::binder_types::transaction::Transaction>(
                "Transaction",
                br_prefix!("transaction"),
            )
            .add_extra_type::<binderdump_structs::binder_types::transaction::TransactionSg>(
                "TransactionSg",
                br_prefix!("transaction_sg"),
            )
    }
}

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
