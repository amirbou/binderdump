use anyhow::{Context, Error};
use binderdump_epan_sys::{epan, field_display_e, ftenum, header_field_info, hf_register_info};
use binderdump_structs::binder_serde::FieldOffset;
use binderdump_trait::{EpanProtocol, FieldDisplay, FieldInfo, FtEnum, StringsMap};
use core::slice;
use std::collections::HashMap;
use std::ffi::{c_int, CString};
use std::ptr::{null, null_mut};

pub type FieldHandlerFunc<T> = fn(
    c_int,
    &HeaderFieldsManager<T>,
    &T,
    FieldOffset,
    *mut epan::tvbuff,
    *mut epan::packet_info,
    *mut epan::proto_node,
) -> anyhow::Result<()>;

#[derive(Debug)]
pub struct FieldHandler<T: EpanProtocol> {
    func: FieldHandlerFunc<T>,
}

impl<T: EpanProtocol> FieldHandler<T> {
    pub fn new(func: FieldHandlerFunc<T>) -> Self {
        Self { func }
    }

    pub fn call(
        &self,
        handle: c_int,
        manager: &HeaderFieldsManager<T>,
        base: &T,
        offset: FieldOffset,
        tvb: *mut epan::tvbuff,
        pinfo: *mut epan::packet_info,
        tree: *mut epan::proto_node,
    ) -> anyhow::Result<()> {
        (self.func)(handle, manager, base, offset, tvb, pinfo, tree)
    }
}

#[derive(Debug)]
pub struct HeaderFieldsManager<T: EpanProtocol> {
    pub fields_to_handles: HashMap<String, c_int>,
    header_fields: Vec<HeaderField>,
    subtrees: Vec<String>,
    custom: HashMap<&'static str, FieldHandler<T>>,
}

#[derive(Debug)]
pub struct HeaderField {
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
    pub fn get_path(&self) -> String {
        self.abbrev.to_string_lossy().into_owned()
    }

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
        match &self.display {
            field_display_e::SEP_DOT
            | field_display_e::SEP_DASH
            | field_display_e::SEP_COLON
            | field_display_e::SEP_SPACE => {
                display_flag |= binderdump_epan_sys::BASE_SHOW_ASCII_PRINTABLE as c_int
                    | binderdump_epan_sys::BASE_ALLOW_ZERO as c_int
            }
            _ => (),
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

impl<T: EpanProtocol> HeaderFieldsManager<T> {
    pub fn new(
        name: String,
        abbrev: String,
        custom: HashMap<&'static str, FieldHandler<T>>,
        extra_fields: Vec<HeaderField>,
        extra_subtrees: Vec<String>,
    ) -> anyhow::Result<Self> {
        let fields = T::get_info(name, abbrev.clone(), None, None);

        let mut header_fields = fields
            .into_iter()
            .map(|field| HeaderField::try_from(field))
            .collect::<Result<Vec<_>, _>>()?;

        header_fields.extend(extra_fields);
        let header_fields = header_fields
            .into_iter()
            .filter(|field| !custom.contains_key(field.abbrev.to_str().unwrap()))
            .collect();

        let mut subtrees = T::get_subtrees(abbrev);
        for key in custom.keys() {
            subtrees.push(key.to_string());
        }

        subtrees.extend(extra_subtrees);

        Ok(Self {
            fields_to_handles: HashMap::new(),
            header_fields,
            subtrees: subtrees,
            custom,
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
        for (field, handle) in self.header_fields.iter().zip(handles.into_iter()) {
            self.fields_to_handles.insert(field.get_path(), handle);
        }
    }

    pub fn register_subtrees(&mut self) {
        let mut handles = vec![-1 as c_int; self.subtrees.len()];
        // let mut custom_handles = vec![-1 as c_int; self.custom.len()];
        let mut ett_array = Vec::with_capacity(handles.len() + self.custom.len());

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

    pub fn get_custom_handle(&self, name: &str) -> Option<&FieldHandler<T>> {
        self.custom.get(name)
    }
}
