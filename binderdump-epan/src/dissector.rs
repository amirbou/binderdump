use crate::dissector;
use anyhow;
use binderdump_epan_sys::epan;
use binderdump_trait::{EpanProtocol, FieldOffset};
use std::ffi::{c_void, CStr};
use std::{ffi::c_int, ptr::null_mut};

pub struct DissectorState {}
pub struct DissectorBuilder {}

pub struct EpanHandle(c_int);

pub trait Dissector {
    const PROTOCOL_NAME: &'static CStr;
    const PROTOCOL_SHORT_NAME: &'static CStr;
    const PROTOCOL_FILTER: &'static CStr;

    type Protocol: EpanProtocol;
    type Error;

    fn customize(&self, builder: DissectorBuilder) -> DissectorBuilder {
        builder
    }

    #[allow(unused_variables)]
    fn callback(
        &self,
        packet: Self::Protocol,
        handle: EpanHandle,
        path: &str,
        offset: FieldOffset,
        state: &mut DissectorState,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct DissectorHandle(epan::dissector_handle_t);

pub struct DissectorManager {
    proto_handle: c_int,
    exported_pdu_tap: c_int,
    dissector_handle: DissectorHandle,
}

static G_DISSECTOR: std::sync::OnceLock<DissectorManager> = std::sync::OnceLock::new();

extern "C" fn dissect(
    tvb: *mut epan::tvbuff_t,
    pinfo: *mut epan::packet_info,
    tree: *mut epan::proto_tree,
    data: *mut c_void,
) -> c_int {
    match G_DISSECTOR.get().unwrap().dissect(tvb, pinfo, tree, data) {
        Ok(count) => count,
        Err(err) => {
            eprintln!("Dissection error: {}", err);
            -1
        }
    }
}

impl DissectorManager {
    pub fn new<T: Dissector>() -> Self {
        let proto_handle = unsafe {
            epan::proto_register_protocol(
                T::PROTOCOL_NAME.as_ptr(),
                T::PROTOCOL_SHORT_NAME.as_ptr(),
                T::PROTOCOL_FILTER.as_ptr(),
            )
        };
        let dissector_handle = unsafe {
            epan::register_dissector(T::PROTOCOL_FILTER.as_ptr(), Some(dissect), proto_handle)
        };
        let exported_pdu_tap = unsafe { epan::register_export_pdu_tap(T::PROTOCOL_NAME.as_ptr()) };
        // Self { foo: None }
        todo!()
    }

    pub fn get_dissector_handle(&self) -> *mut epan::dissector_handle {
        self.dissector_handle.0
    }

    fn dissect(
        &self,
        tvb: *mut epan::tvbuff_t,
        pinfo: *mut epan::packet_info,
        tree: *mut epan::proto_tree,
        _data: *mut c_void,
    ) -> anyhow::Result<c_int> {
        todo!()
    }
}

unsafe impl Send for DissectorHandle {}
unsafe impl Sync for DissectorHandle {}
