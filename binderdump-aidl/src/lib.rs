// AIDL/HIDL method-name resolution for the dissector.
// Parses .aidl/.hal definitions into a model, layers AOSP built-in tables
// (baked at build time) under runtime overlays, and parses the
// writeInterfaceToken byte streams libbinder/libhidl emit so the dissector
// can map (interface, code) back to a method name.

pub mod aosp_layout;
pub mod decode;
pub mod model;
pub mod parser;
pub mod registry;
pub mod token;

pub use model::{Direction, Flavor, Interface, Method, Parameter, Prim, TypeRef};
pub use registry::{Lookup, Registry, Source};
