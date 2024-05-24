//! This module captures binder transactions
//!
//! TODO create different "backends" to handle the capture (ptrace, uprobe, tracepoints etc.)

mod common_types;
pub mod events;
pub mod ringbuf;
pub mod tracepoints;
