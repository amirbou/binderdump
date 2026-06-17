//! This module captures binder transactions
//!
//! TODO create different "backends" to handle the capture (ptrace, uprobe, tracepoints etc.)

pub mod btf_probe;
mod common_types;
pub mod events;
pub mod offset_solver;
pub mod process_cache;
pub mod ringbuf;
pub mod system_property;
pub mod tracepoints;
