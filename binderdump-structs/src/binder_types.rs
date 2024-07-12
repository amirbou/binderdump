use anyhow;
use binderdump_derive::EpanProtocolEnum;
use binderdump_sys;
pub use binderdump_sys::{binder_write_read, BINDER_CURRENT_PROTOCOL_VERSION};
use nix::{request_code_readwrite, request_code_write};
use num_derive;
use num_derive::FromPrimitive;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::mem::size_of;
use std::path::{Path, PathBuf};
pub mod binder_command;
pub mod binder_return;
pub mod bwr_trait;
pub mod transaction;

#[derive(Default, Clone, Copy, Deserialize_repr, Serialize_repr, EpanProtocolEnum, Debug)]
#[repr(u8)]
pub enum BinderInterface {
    #[default]
    BINDER = 0,
    HWBINDER = 1,
    VNDBINDER = 2,
}

impl TryFrom<PathBuf> for BinderInterface {
    type Error = anyhow::Error;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        match path {
            _ if path == Path::new("/dev/binder") || path == Path::new("/dev/binderfs/binder") => {
                Ok(BinderInterface::BINDER)
            }
            _ if path == Path::new("/dev/hwbinder")
                || path == Path::new("/dev/binderfs/hwbinder") =>
            {
                Ok(BinderInterface::HWBINDER)
            }
            _ if path == Path::new("/dev/vndbinder")
                || path == Path::new("/dev/binderfs/vndbinder") =>
            {
                Ok(BinderInterface::VNDBINDER)
            }
            _ => Err(anyhow::anyhow!("Not a binder path")),
        }
    }
}

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum binder_type {
    BINDER = binderdump_sys::BINDER_TYPE_BINDER,
    WEAK_BINDER = binderdump_sys::BINDER_TYPE_WEAK_BINDER,
    HANDLE = binderdump_sys::BINDER_TYPE_HANDLE,
    WEAK_HANDLE = binderdump_sys::BINDER_TYPE_WEAK_HANDLE,
    FD = binderdump_sys::BINDER_TYPE_FD,
    FDA = binderdump_sys::BINDER_TYPE_FDA,
    PTR = binderdump_sys::BINDER_TYPE_PTR,
}

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum flat_binder_flag {
    PRIORITY_MASK = binderdump_sys::FLAT_BINDER_FLAG_PRIORITY_MASK,
    ACCEPT_FDS = binderdump_sys::FLAT_BINDER_FLAG_ACCEPTS_FDS,
    TXN_SECURITY_CTX = binderdump_sys::FLAT_BINDER_FLAG_TXN_SECURITY_CTX,
}

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum binder_buffer_flag {
    HAS_PARENT = binderdump_sys::BINDER_BUFFER_FLAG_HAS_PARENT,
}

// nix request_code_readwrite! macro uses ioctl_num_type, which is defined as `int` when targeting Android or musl,
// and `long` otherwise. We always want `int`
macro_rules! request_code_readwrite_wrapper {
    ($nr:expr, $type_:ty) => {
        request_code_readwrite!('b', $nr, size_of::<$type_>()) as i32
    };
}

macro_rules! request_code_write_wrapper {
    ($nr:expr, $type_:ty) => {
        request_code_write!('b', $nr, size_of::<$type_>()) as i32
    };
}

#[derive(
    Debug,
    FromPrimitive,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Serialize_repr,
    Deserialize_repr,
    EpanProtocolEnum,
)]
#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum binder_ioctl {
    BINDER_WRITE_READ = request_code_readwrite_wrapper!(1, binderdump_sys::binder_write_read),
    BINDER_SET_IDLE_TIMEOUT = request_code_write_wrapper!(3, i64),
    BINDER_SET_MAX_THREADS = request_code_write_wrapper!(5, u32),
    BINDER_SET_IDLE_PRIORITY = request_code_write_wrapper!(6, i32),
    BINDER_SET_CONTEXT_MGR = request_code_write_wrapper!(7, i32),
    BINDER_THREAD_EXIT = request_code_write_wrapper!(8, i32),
    #[default]
    BINDER_VERSION = request_code_readwrite_wrapper!(9, binderdump_sys::binder_version),
    BINDER_GET_NODE_DEBUG_INFO =
        request_code_readwrite_wrapper!(11, binderdump_sys::binder_node_debug_info),
    BINDER_GET_NODE_INFO_FOR_REF =
        request_code_readwrite_wrapper!(12, binderdump_sys::binder_node_info_for_ref),
    BINDER_SET_CONTEXT_MGR_EXT =
        request_code_write_wrapper!(13, binderdump_sys::flat_binder_object),
    BINDER_FREEZE = request_code_write_wrapper!(14, binderdump_sys::binder_freeze_info),
    BINDER_GET_FROZEN_INFO =
        request_code_readwrite_wrapper!(15, binderdump_sys::binder_frozen_status_info),
    BINDER_ENABLE_ONEWAY_SPAM_DETECTION = request_code_write_wrapper!(16, u32),
}
