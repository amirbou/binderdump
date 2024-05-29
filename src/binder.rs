//! This module parses binder transactions, taking into account which
//! interfaces, nodes, processes, threads, refs etc. are used in the transaction.

mod gen;
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

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum binder_command {
    BC_TRANSACTION = gen::binder_driver_command_protocol_BC_TRANSACTION,
    BC_REPLY = gen::binder_driver_command_protocol_BC_REPLY,
    BC_ACQUIRE_RESULT = gen::binder_driver_command_protocol_BC_ACQUIRE_RESULT,
    BC_FREE_BUFFER = gen::binder_driver_command_protocol_BC_FREE_BUFFER,
    BC_INCREFS = gen::binder_driver_command_protocol_BC_INCREFS,
    BC_ACQUIRE = gen::binder_driver_command_protocol_BC_ACQUIRE,
    BC_RELEASE = gen::binder_driver_command_protocol_BC_RELEASE,
    BC_DECREFS = gen::binder_driver_command_protocol_BC_DECREFS,
    BC_INCREFS_DONE = gen::binder_driver_command_protocol_BC_INCREFS_DONE,
    BC_ACQUIRE_DONE = gen::binder_driver_command_protocol_BC_ACQUIRE_DONE,
    BC_ATTEMPT_ACQUIRE = gen::binder_driver_command_protocol_BC_ATTEMPT_ACQUIRE,
    BC_REGISTER_LOOPER = gen::binder_driver_command_protocol_BC_REGISTER_LOOPER,
    BC_ENTER_LOOPER = gen::binder_driver_command_protocol_BC_ENTER_LOOPER,
    BC_EXIT_LOOPER = gen::binder_driver_command_protocol_BC_EXIT_LOOPER,
    BC_REQUEST_DEATH_NOTIFICATION =
        gen::binder_driver_command_protocol_BC_REQUEST_DEATH_NOTIFICATION,
    BC_CLEAR_DEATH_NOTIFICATION = gen::binder_driver_command_protocol_BC_CLEAR_DEATH_NOTIFICATION,
    BC_DEAD_BINDER_DONE = gen::binder_driver_command_protocol_BC_DEAD_BINDER_DONE,
    BC_TRANSACTION_SG = gen::binder_driver_command_protocol_BC_TRANSACTION_SG,
    BC_REPLY_SG = gen::binder_driver_command_protocol_BC_REPLY_SG,
}

#[derive(Debug, FromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum binder_result {
    BR_ERROR = gen::binder_driver_return_protocol_BR_ERROR,
    BR_OK = gen::binder_driver_return_protocol_BR_OK,
    BR_TRANSACTION_SEC_CTX = gen::binder_driver_return_protocol_BR_TRANSACTION_SEC_CTX,
    BR_TRANSACTION = gen::binder_driver_return_protocol_BR_TRANSACTION,
    BR_REPLY = gen::binder_driver_return_protocol_BR_REPLY,
    BR_ACQUIRE_RESULT = gen::binder_driver_return_protocol_BR_ACQUIRE_RESULT,
    BR_DEAD_REPLY = gen::binder_driver_return_protocol_BR_DEAD_REPLY,
    BR_TRANSACTION_COMPLETE = gen::binder_driver_return_protocol_BR_TRANSACTION_COMPLETE,
    BR_INCREFS = gen::binder_driver_return_protocol_BR_INCREFS,
    BR_ACQUIRE = gen::binder_driver_return_protocol_BR_ACQUIRE,
    BR_RELEASE = gen::binder_driver_return_protocol_BR_RELEASE,
    BR_DECREFS = gen::binder_driver_return_protocol_BR_DECREFS,
    BR_ATTEMPT_ACQUIRE = gen::binder_driver_return_protocol_BR_ATTEMPT_ACQUIRE,
    BR_NOOP = gen::binder_driver_return_protocol_BR_NOOP,
    BR_SPAWN_LOOPER = gen::binder_driver_return_protocol_BR_SPAWN_LOOPER,
    BR_FINISHED = gen::binder_driver_return_protocol_BR_FINISHED,
    BR_DEAD_BINDER = gen::binder_driver_return_protocol_BR_DEAD_BINDER,
    BR_CLEAR_DEATH_NOTIFICATION_DONE =
        gen::binder_driver_return_protocol_BR_CLEAR_DEATH_NOTIFICATION_DONE,
    BR_FAILED_REPLY = gen::binder_driver_return_protocol_BR_FAILED_REPLY,
    BR_FROZEN_REPLY = gen::binder_driver_return_protocol_BR_FROZEN_REPLY,
    BR_ONEWAY_SPAM_SUSPECT = gen::binder_driver_return_protocol_BR_ONEWAY_SPAM_SUSPECT,
}
