//! This module creates a valid pcapng file from binder data
//! captured by the `capture` module and parsed by the `binder` module

mod bwr_layer;
mod capture_info;
mod event_layer;
mod events_aggregator;
mod link_layer;
pub mod packets;
mod transaction_layer;
