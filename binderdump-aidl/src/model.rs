// Shared interface/method/type model used by both parsers, the registry,
// and (eventually) the parameter decoder. Flavor tags whether an entry came
// from AIDL or HIDL because base_code semantics differ.

use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    Aidl,
    Hidl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
    InOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prim {
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    Char,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeRef {
    Primitive(Prim),
    String,
    String8,
    CString,
    IBinder,
    Array(Box<TypeRef>),
    List(Box<TypeRef>),
    Map(Box<TypeRef>, Box<TypeRef>),
    UserDefined(String),    // fqn of enum/parcelable/interface, resolved later
    Nullable(Box<TypeRef>), // `@nullable T`
}

impl TypeRef {
    // returns the inner Prim if self is Primitive, else None.
    pub fn as_ref_prim(&self) -> Option<Prim> {
        match self {
            TypeRef::Primitive(p) => Some(*p),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Parameter {
    pub name: String,
    pub ty: TypeRef,
    pub direction: Direction,
}

#[derive(Clone, Debug)]
pub struct Method {
    pub name: String,
    pub params: Vec<Parameter>,
    pub return_type: Option<TypeRef>,
    pub oneway: bool,
    // explicit transaction code from `void foo() = N;` (stable AIDL).
    // None means "derive from base_code + idx".
    pub code: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub fqn: String,
    pub flavor: Flavor,
    pub base_code: u32, // AIDL: 1 (FIRST_CALL_TRANSACTION). HIDL: 1 + parent_method_count.
    pub methods: Vec<Method>, // index 0 == base_code
    pub extends: Option<String>, // HIDL parent fqn
}

impl Interface {
    pub fn lookup(&self, code: u32) -> Option<&Method> {
        // explicit `= N` pins win first
        if let Some(m) = self.methods.iter().find(|m| m.code == Some(code)) {
            return Some(m);
        }
        // fall back to index-based, but don't double-match methods that have
        // their own explicit code (those should only be reachable above).
        let idx = code.checked_sub(self.base_code)? as usize;
        let m = self.methods.get(idx)?;
        if m.code.is_some() {
            return None;
        }
        Some(m)
    }
}

// a parcelable/union member: declared type + name. defaults/annotations are
// dropped — they never appear on the wire.
#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub ty: TypeRef,
}

#[derive(Clone, Debug)]
pub struct Parcelable {
    pub fqn: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug)]
pub struct EnumDef {
    pub fqn: String,
    pub backing: Prim,              // default I32; byte/long via @Backing
    pub consts: Vec<(String, i64)>, // declaration order
}

#[derive(Clone, Debug)]
pub struct Union {
    pub fqn: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug)]
pub struct OverlayLayer {
    pub source_path: PathBuf,
    pub interfaces: std::collections::HashMap<String, Interface>,
    pub enums: std::collections::HashMap<String, EnumDef>,
    pub parcelables: std::collections::HashMap<String, Parcelable>,
    pub unions: std::collections::HashMap<String, Union>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_method(name: &str) -> Method {
        Method {
            name: name.to_string(),
            params: vec![],
            return_type: None,
            oneway: false,
            code: None,
        }
    }

    fn aidl_iface_with_methods(fqn: &str, names: &[&str]) -> Interface {
        Interface {
            fqn: fqn.to_string(),
            flavor: Flavor::Aidl,
            base_code: 1,
            methods: names.iter().map(|n| fake_method(n)).collect(),
            extends: None,
        }
    }

    #[test]
    fn lookup_first_method_at_first_call_transaction() {
        let iface = aidl_iface_with_methods("a.b.IFoo", &["start", "stop"]);
        assert_eq!(iface.lookup(1).map(|m| m.name.as_str()), Some("start"));
    }

    #[test]
    fn lookup_second_method() {
        let iface = aidl_iface_with_methods("a.b.IFoo", &["start", "stop"]);
        assert_eq!(iface.lookup(2).map(|m| m.name.as_str()), Some("stop"));
    }

    #[test]
    fn lookup_below_base_returns_none() {
        let iface = aidl_iface_with_methods("a.b.IFoo", &["start"]);
        assert!(iface.lookup(0).is_none());
    }

    #[test]
    fn lookup_above_last_returns_none() {
        let iface = aidl_iface_with_methods("a.b.IFoo", &["start"]);
        assert!(iface.lookup(2).is_none());
    }

    #[test]
    fn lookup_with_offset_base_code() {
        // Simulates a HIDL child interface whose parent has 3 methods.
        let mut iface = aidl_iface_with_methods("a.b.IBar", &["one", "two"]);
        iface.flavor = Flavor::Hidl;
        iface.base_code = 4; // FIRST_CALL_TRANSACTION (1) + parent.methods.len() (3)
        assert_eq!(iface.lookup(4).map(|m| m.name.as_str()), Some("one"));
        assert_eq!(iface.lookup(5).map(|m| m.name.as_str()), Some("two"));
        assert!(iface.lookup(3).is_none());
        assert!(iface.lookup(6).is_none());
    }
}
