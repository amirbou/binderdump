//! This module parses binder transactions, taking into account which
//! interfaces, nodes, processes, threads, refs etc. are used in the transaction.

pub mod binder_command;
pub mod binder_return;
mod gen;
mod transaction;
pub use gen::{binder_write_read, BINDER_CURRENT_PROTOCOL_VERSION};
use nix::{request_code_readwrite, request_code_write};
use num_derive;
use num_derive::FromPrimitive;
use std::mem::size_of;

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum binder_type {
    BINDER = gen::BINDER_TYPE_BINDER,
    WEAK_BINDER = gen::BINDER_TYPE_WEAK_BINDER,
    HANDLE = gen::BINDER_TYPE_HANDLE,
    WEAK_HANDLE = gen::BINDER_TYPE_WEAK_HANDLE,
    FD = gen::BINDER_TYPE_FD,
    FDA = gen::BINDER_TYPE_FDA,
    PTR = gen::BINDER_TYPE_PTR,
}

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum flat_binder_flag {
    PRIORITY_MASK = gen::FLAT_BINDER_FLAG_PRIORITY_MASK,
    ACCEPT_FDS = gen::FLAT_BINDER_FLAG_ACCEPTS_FDS,
    TXN_SECURITY_CTX = gen::FLAT_BINDER_FLAG_TXN_SECURITY_CTX,
}

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum binder_buffer_flag {
    HAS_PARENT = gen::BINDER_BUFFER_FLAG_HAS_PARENT,
}

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum binder_ioctl {
    BINDER_WRITE_READ = request_code_readwrite!('b', 1, size_of::<gen::binder_write_read>()),
    BINDER_SET_IDLE_TIMEOUT = request_code_write!('b', 3, size_of::<i64>()),
    BINDER_SET_MAX_THREADS = request_code_write!('b', 5, size_of::<u32>()),
    BINDER_SET_IDLE_PRIORITY = request_code_write!('b', 6, size_of::<i32>()),
    BINDER_SET_CONTEXT_MGR = request_code_write!('b', 7, size_of::<i32>()),
    BINDER_THREAD_EXIT = request_code_write!('b', 8, size_of::<i32>()),
    BINDER_VERSION = request_code_readwrite!('b', 9, size_of::<gen::binder_version>()),
    BINDER_GET_NODE_DEBUG_INFO =
        request_code_readwrite!('b', 11, size_of::<gen::binder_node_debug_info>()),
    BINDER_GET_NODE_INFO_FOR_REF =
        request_code_readwrite!('b', 12, size_of::<gen::binder_node_info_for_ref>()),
    BINDER_SET_CONTEXT_MGR_EXT = request_code_write!('b', 13, size_of::<gen::flat_binder_object>()),
    BINDER_FREEZE = request_code_write!('b', 14, size_of::<gen::binder_freeze_info>()),
    BINDER_GET_FROZEN_INFO =
        request_code_readwrite!('b', 15, size_of::<gen::binder_frozen_status_info>()),
    BINDER_ENABLE_ONEWAY_SPAM_DETECTION = request_code_write!('b', 16, size_of::<u32>()),
}
