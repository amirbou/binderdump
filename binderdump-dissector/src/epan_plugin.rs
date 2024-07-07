use anyhow::{Context, Error};
use binderdump_epan_sys::{epan, field_display_e, ftenum, header_field_info, hf_register_info};
use binderdump_structs;
use binderdump_trait::{EpanProtocol, FieldDisplay, FieldInfo, FtEnum, StringsMap};
use core::slice;
use std::collections::HashMap;
use std::ffi::{c_int, c_void, CStr, CString};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use crate::dissect_offsets;

pub struct HeaderFieldsManager {
    fields_to_handles: HashMap<String, c_int>,
    header_fields: Vec<HeaderField>,
    subtrees: Vec<String>,
}

struct HeaderField {
    name: CString,
    abbrev: CString,
    ftype: ftenum,
    display: field_display_e,
    strings: Option<StringsMap>,
}

macro_rules! _create_raw_strings {
    ($strings:expr, $dst:ident) => {
        if $strings.len() == 0 {
            null() as *const binderdump_epan_sys::$dst
        } else {
            let mut raw_vec = Vec::with_capacity($strings.len() + 1);
            for string in $strings {
                let value_string = binderdump_epan_sys::$dst {
                    value: string.value,
                    strptr: string.string.as_ptr(),
                };
                raw_vec.push(value_string);
            }
            // add sentinal NULL struct at the end
            raw_vec.push(binderdump_epan_sys::$dst {
                value: 0,
                strptr: null_mut(),
            });

            let boxed_array = raw_vec.into_boxed_slice();
            let fat_ptr: *mut [binderdump_epan_sys::$dst] = Box::into_raw(boxed_array);
            fat_ptr as _
        }
    };
}

impl HeaderField {
    fn create_raw_strings(&self) -> *const std::ffi::c_void {
        if self.strings.is_none() {
            return null();
        }
        let strings = self.strings.as_ref().unwrap();
        match strings {
            StringsMap::U32(strings) => {
                _create_raw_strings!(strings, value_string) as *const std::ffi::c_void
            }
            StringsMap::U64(strings) => {
                _create_raw_strings!(strings, val64_string) as *const std::ffi::c_void
            }
        }
    }

    #[allow(dead_code)]
    fn destroy_raw_strings(&self, raw_strings: *mut std::ffi::c_void) {
        if raw_strings.is_null() || self.strings.is_none() {
            return;
        }
        let strings = self.strings.as_ref().unwrap();
        match strings {
            StringsMap::U32(strings) => unsafe {
                let slice: &mut [binderdump_epan_sys::value_string] =
                    slice::from_raw_parts_mut(raw_strings as *mut _, strings.len() + 1);
                let _ = Box::from_raw(slice);
            },
            StringsMap::U64(strings) => unsafe {
                let slice: &mut [binderdump_epan_sys::val64_string] =
                    slice::from_raw_parts_mut(raw_strings as *mut _, strings.len() + 1);
                let _ = Box::from_raw(slice);
            },
        }
    }

    fn to_ffi(&self, handle_ptr: &mut c_int) -> hf_register_info {
        let mut display_flag = 0;
        match &self.strings {
            Some(strings) => match strings {
                StringsMap::U32(_) => {
                    display_flag = binderdump_epan_sys::BASE_SPECIAL_VALS as c_int
                }
                StringsMap::U64(_) => {
                    display_flag = binderdump_epan_sys::BASE_SPECIAL_VALS as c_int
                        | binderdump_epan_sys::BASE_VAL64_STRING as c_int
                }
            },
            None => (),
        }
        hf_register_info {
            p_id: handle_ptr as *mut c_int,
            hfinfo: header_field_info {
                name: self.name.as_ptr(),
                abbrev: self.abbrev.as_ptr(),
                type_: self.ftype.clone(),
                display: self.display as c_int | display_flag,
                strings: self.create_raw_strings(),
                bitmask: 0,
                blurb: null(),
                // default values set by the HFILL macro
                id: -1,
                parent: 0,
                ref_type: binderdump_epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: null_mut(),
            },
        }
    }
}

fn translate_ftenum(ftype: FtEnum) -> ftenum {
    match ftype {
        FtEnum::None => ftenum::FT_NONE,
        FtEnum::Protocol => ftenum::FT_PROTOCOL,
        FtEnum::Boolean => ftenum::FT_BOOLEAN,
        FtEnum::Char => ftenum::FT_CHAR,
        FtEnum::U8 => ftenum::FT_UINT8,
        FtEnum::U16 => ftenum::FT_UINT16,
        FtEnum::U32 => ftenum::FT_UINT32,
        FtEnum::U64 => ftenum::FT_UINT64,
        FtEnum::I8 => ftenum::FT_INT8,
        FtEnum::I16 => ftenum::FT_INT16,
        FtEnum::I32 => ftenum::FT_INT32,
        FtEnum::I64 => ftenum::FT_INT64,
        FtEnum::AbsoulteTime => ftenum::FT_ABSOLUTE_TIME,
        FtEnum::RelativeTime => ftenum::FT_RELATIVE_TIME,
        FtEnum::String => ftenum::FT_STRING,
        FtEnum::StringZ => ftenum::FT_STRINGZ,
        FtEnum::Ether => ftenum::FT_ETHER,
        FtEnum::Bytes => ftenum::FT_BYTES,
        FtEnum::IPv4 => ftenum::FT_IPv4,
        FtEnum::IPv6 => ftenum::FT_IPv6,
        FtEnum::FrameNum => ftenum::FT_FRAMENUM,
        FtEnum::Guid => ftenum::FT_GUID,
    }
}

fn translate_field_display(display: FieldDisplay) -> field_display_e {
    match display {
        FieldDisplay::None => field_display_e::BASE_NONE,
        FieldDisplay::Dec => field_display_e::BASE_DEC,
        FieldDisplay::Hex => field_display_e::BASE_HEX,
        FieldDisplay::Oct => field_display_e::BASE_OCT,
        FieldDisplay::DecHex => field_display_e::BASE_DEC_HEX,
        FieldDisplay::HexDec => field_display_e::BASE_HEX_DEC,
        FieldDisplay::Custom => field_display_e::BASE_CUSTOM,
        FieldDisplay::StrAsciis => field_display_e::STR_ASCII,
        FieldDisplay::StrUnicode => field_display_e::STR_UNICODE,
        FieldDisplay::SepDot => field_display_e::SEP_DOT,
        FieldDisplay::SepDash => field_display_e::SEP_DASH,
        FieldDisplay::SepColon => field_display_e::SEP_COLON,
        FieldDisplay::SepSpace => field_display_e::SEP_SPACE,
    }
}

impl TryFrom<FieldInfo> for HeaderField {
    type Error = Error;

    fn try_from(value: FieldInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            name: CString::new(value.name).context("Invalid field name")?,
            abbrev: CString::new(value.abbrev).context("Invalid field abbrev")?,
            ftype: translate_ftenum(value.ftype),
            display: translate_field_display(value.display),
            strings: value.strings,
        })
    }
}

impl HeaderFieldsManager {
    pub fn new<T: EpanProtocol>(name: String, abbrev: String) -> anyhow::Result<Self> {
        let fields = T::get_info(name, abbrev.clone(), None, None);

        let mut header_fields = Vec::with_capacity(fields.len());

        for field in fields {
            header_fields.push(HeaderField::try_from(field)?);
        }
        Ok(Self {
            fields_to_handles: HashMap::new(),
            header_fields,
            subtrees: T::get_subtrees(abbrev),
        })
    }

    pub fn register(&mut self, proto_handle: c_int) {
        let mut handles = vec![-1 as c_int; self.header_fields.len()];

        let mut hf_array = Vec::with_capacity(self.header_fields.len());

        for (index, field) in self.header_fields.iter().enumerate() {
            hf_array.push(field.to_ffi(handles.get_mut(index).unwrap()));
        }

        // XXX leaks the hf_array, it will never be freed
        let boxed_array = hf_array.into_boxed_slice();
        let fat_ptr: *mut [hf_register_info] = Box::into_raw(boxed_array);
        let hf_ptr = fat_ptr as *mut hf_register_info;

        unsafe {
            binderdump_epan_sys::proto_register_field_array(
                proto_handle,
                hf_ptr,
                self.header_fields.len().try_into().unwrap(),
            );
        }

        // map fields to handles
        for (index, field) in self.header_fields.iter().enumerate() {
            self.fields_to_handles
                .insert(field.abbrev.to_string_lossy().into_owned(), handles[index]);
        }
    }

    pub fn register_subtrees(&mut self) {
        let mut handles = vec![-1 as c_int; self.subtrees.len()];
        let mut ett_array = Vec::with_capacity(handles.len());

        for handle in &mut handles {
            ett_array.push(handle as *mut c_int);
        }

        // looking at epan/proto.c, the ett_array is not saved anywhere so it's safe to just temporarly allocate it here.
        unsafe {
            epan::proto_register_subtree_array(
                ett_array.as_ptr(),
                handles.len().try_into().unwrap(),
            )
        };

        for (string, handle) in self.subtrees.iter().zip(handles) {
            self.fields_to_handles.insert(string.clone(), handle);
        }
    }

    pub fn get_handle(&self, field_name: &str) -> Option<c_int> {
        self.fields_to_handles.get(field_name).copied()
    }
}

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
    pub fn register(name: &'static CStr, short_name: &'static CStr, filter: &'static CStr) -> Self {
        let mut proto = Self {
            name,
            short_name,
            filter,
            handle: -1,
            exported_pdu_tap: -1,
            dissector: Dissector {
                handle: DissectorHandle(null_mut()),
                field_manager: HeaderFieldsManager::new::<
                    binderdump_structs::event_layer::EventProtocol,
                >(
                    short_name.to_string_lossy().into_owned(),
                    filter.to_string_lossy().into_owned(),
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

            let binderdump = binderdump_structs::binder_serde::from_bytes_with_offsets::<
                binderdump_structs::event_layer::EventProtocol,
            >(data)?;

            let offsets = binderdump.1?;
            dissect_offsets::dissect_offsets(
                offsets,
                &self.dissector.field_manager,
                self.filter.to_string_lossy().into_owned(),
                tvb,
                tree_item,
            )?;

            Ok(epan::tvb_captured_length(tvb) as c_int)
        }
    }
}

struct Dissector {
    handle: DissectorHandle,
    field_manager: HeaderFieldsManager,
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
    G_PROTOCOL
        .get_or_init(|| Protocol::register(PROTOCOL_NAME, PROTOCOL_SHORT_NAME, PROTOCOL_FILTER));
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
