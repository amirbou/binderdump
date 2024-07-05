use crate::epan;
use core::slice;
use std::{
    ffi::{c_int, CStr},
    ptr::{null, null_mut},
};

pub struct ValueString {
    pub value: u32,
    pub string: &'static CStr,
}

// bitmask::bitmask! {
//     pub mask DisplayType: u32 where flags DisplayValue {
//         BaseRangeString = epan::BASE_RANGE_STRING,
//         BaseExtString = epan::BASE_EXT_STRING,
//         BaseVal64String = epan::BASE_VAL64_STRING,
//         BaseAllowZero = epan::BASE_ALLOW_ZERO,
//         BaseUnitString = epan::BASE_UNIT_STRING,
//         BaseNoDisplayValue = epan::BASE_NO_DISPLAY_VALUE,
//         BaseSpecialVals = epan::BASE_SPECIAL_VALS,
//         BaseShowAsciiPrintable = epan::BASE_SHOW_ASCII_PRINTABLE
//     }
// }
fn default_header_field_info() -> epan::header_field_info {
    epan::header_field_info {
        name: null(),
        abbrev: null(),
        type_: epan::ftenum::FT_NONE,
        display: 0,
        strings: null(),
        bitmask: 0,
        blurb: null(),
        // default values set by the HFILL macro
        id: -1,
        parent: 0,
        ref_type: epan::hf_ref_type_HF_REF_TYPE_NONE,
        same_name_prev_id: -1,
        same_name_next: null_mut(),
    }
}

fn default_hf_register_info() -> epan::hf_register_info {
    epan::hf_register_info {
        p_id: null_mut(),
        hfinfo: default_header_field_info(),
    }
}

pub struct HeaderField {
    name: &'static CStr,
    abbrev: &'static CStr,
    ftype: epan::ftenum,
    display: epan::field_display_e,
    strings: Vec<ValueString>,
    handle: *mut c_int,
}
unsafe impl Sync for HeaderField {}

impl HeaderField {
    pub const fn new(
        name: &'static CStr,
        abbrev: &'static CStr,
        ftype: epan::ftenum,
        display: epan::field_display_e,
        strings: Vec<ValueString>,
        handle: *mut c_int,
    ) -> Self {
        Self {
            name,
            abbrev,
            ftype,
            display,
            strings,
            handle,
        }
    }
    fn create_raw_strings(&self) -> *mut epan::value_string {
        if self.strings.is_empty() {
            return null_mut();
        }
        let mut raw_vec = Vec::with_capacity(self.strings.len() + 1);
        for string in &self.strings {
            let value_string = epan::value_string {
                value: string.value,
                strptr: string.string.as_ptr(),
            };
            raw_vec.push(value_string);
        }
        // add sentinal NULL struct at the end
        raw_vec.push(epan::value_string {
            value: 0,
            strptr: null_mut(),
        });

        let boxed_array = raw_vec.into_boxed_slice();
        let fat_ptr: *mut [epan::value_string] = Box::into_raw(boxed_array);
        fat_ptr as _
    }

    pub fn populate_hf_register_info(&self, hf: &mut epan::hf_register_info) {
        *hf = default_hf_register_info();
        hf.p_id = self.handle;
        hf.hfinfo.name = self.name.as_ptr();
        hf.hfinfo.abbrev = self.abbrev.as_ptr();
        hf.hfinfo.type_ = self.ftype;
        hf.hfinfo.display = self.display as c_int;
        hf.hfinfo.strings = self.create_raw_strings() as *const _;
    }

    pub fn destroy_hf_register_info(&self, hf: &mut epan::hf_register_info) {
        // populate wasn't called
        if hf.hfinfo.strings.is_null() {
            return;
        }
        unsafe {
            let slice: &mut [epan::value_string] =
                slice::from_raw_parts_mut(hf.hfinfo.strings as *mut _, self.strings.len() + 1);
            let _ = Box::from_raw(slice);
        }
    }
}

pub struct HeaderFieldArray<const N: usize> {
    header_fields: [HeaderField; N],
    array: [epan::hf_register_info; N],
}

unsafe impl<const N: usize> Send for HeaderFieldArray<N> {}

impl<const N: usize> HeaderFieldArray<N> {
    pub const fn new(header_fields: [HeaderField; N]) -> Self {
        Self {
            header_fields,
            array: [epan::hf_register_info {
                p_id: null_mut(),
                hfinfo: epan::header_field_info {
                    name: null(),
                    abbrev: null(),
                    type_: epan::ftenum::FT_NONE,
                    display: 0,
                    strings: null(),
                    bitmask: 0,
                    blurb: null(),
                    // default values set by the HFILL macro
                    id: -1,
                    parent: 0,
                    ref_type: epan::hf_ref_type_HF_REF_TYPE_NONE,
                    same_name_prev_id: -1,
                    same_name_next: null_mut(),
                },
            }; N],
        }
    }

    pub fn register(&mut self, proto_handle: c_int) {
        for i in 0..N {
            self.header_fields[i].populate_hf_register_info(&mut self.array[i]);
        }

        unsafe { epan::proto_register_field_array(proto_handle, self.array.as_mut_ptr(), N as i32) }
    }
}

impl<const N: usize> Drop for HeaderFieldArray<N> {
    fn drop(&mut self) {
        for i in 0..N {
            self.header_fields[i].destroy_hf_register_info(&mut self.array[i]);
        }
    }
}
