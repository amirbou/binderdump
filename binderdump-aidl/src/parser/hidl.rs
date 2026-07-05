// HIDL parser. Versioned package syntax (`package a.b@1.0;`) and
// `extends b@1.0::IBar` make this distinct from AIDL: HIDL child interfaces
// continue parent method numbering, so resolve_inheritance() must run after
// every .hal in scope is parsed before base_codes are valid.

use crate::model::{
    Direction, EnumDef, Field, Flavor, Interface, Method, Parameter, Parcelable, Prim, TypeRef,
};

pub struct HidlParsed {
    pub interfaces: Vec<Interface>,
    /// top-level `typedef <Target> <Name>;` declarations in declaration order.
    /// fqn = `<package>@<ver>::<Name>`, matching how interfaces are qualified.
    pub typedefs: Vec<(String, TypeRef)>,
    /// top-level and interface-nested `struct Name { ... };` declarations.
    /// top-level fqn = `<package>@<ver>::<Name>`.
    /// nested fqn = `<package>@<ver>::<Iface>.<Name>`.
    pub parcelables: Vec<Parcelable>,
    /// top-level and interface-nested `enum Name [: backing] { ... };` declarations.
    /// top-level fqn = `<package>@<ver>::<Name>`.
    /// nested fqn = `<package>@<ver>::<Iface>.<Name>`.
    pub enums: Vec<EnumDef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Punct(char),
    Keyword(&'static str),
    AtSymbol,
    DoubleColon,
}

fn lex(src: &str) -> Vec<Tok> {
    // Strip // and /* */ comments. Then scan.
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        if c == ':' && i + 1 < bytes.len() && bytes[i + 1] == b':' {
            out.push(Tok::DoubleColon);
            i += 2;
            continue;
        }
        if c == '@' {
            out.push(Tok::AtSymbol);
            i += 1;
            continue;
        }
        if "{}()[]<>;,.=-:".contains(c) {
            out.push(Tok::Punct(c));
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let word = &src[start..i];
            out.push(match word {
                "package" | "import" | "interface" | "extends" | "oneway" | "generates"
                | "typedef" | "enum" | "struct" | "union" | "string" | "vec" | "ref" | "bool"
                | "int8_t" | "uint8_t" | "int16_t" | "uint16_t" | "int32_t" | "uint32_t"
                | "int64_t" | "uint64_t" | "float" | "double" | "bitfield" | "fmq_sync"
                | "fmq_unsync" | "safe_union" | "handle" | "memory" => {
                    Tok::Keyword(Box::leak(word.to_string().into_boxed_str()))
                }
                _ => Tok::Ident(word.to_string()),
            });
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            // hex literal: 0x... or 0X...
            if c == '0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
                i += 2; // skip "0x"
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
            } else {
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    i += 1;
                }
            }
            out.push(Tok::Ident(src[start..i].to_string()));
            continue;
        }
        // unknown char — skip
        i += 1;
    }
    out
}

pub fn parse_hidl(source: &str) -> Result<HidlParsed, String> {
    let toks = lex(source);
    let mut pos = 0usize;
    let mut package = String::new();

    let eat_kw = |p: &mut usize, t: &[Tok], k: &str| {
        if matches!(t.get(*p), Some(Tok::Keyword(kw)) if *kw == k) {
            *p += 1;
            true
        } else {
            false
        }
    };
    let eat_punct = |p: &mut usize, t: &[Tok], c: char| {
        if matches!(t.get(*p), Some(Tok::Punct(pp)) if *pp == c) {
            *p += 1;
            true
        } else {
            false
        }
    };
    let eat_at = |p: &mut usize, t: &[Tok]| {
        if matches!(t.get(*p), Some(Tok::AtSymbol)) {
            *p += 1;
            true
        } else {
            false
        }
    };
    let take_ident = |p: &mut usize, t: &[Tok]| -> Option<String> {
        if let Some(Tok::Ident(s)) = t.get(*p) {
            let v = s.clone();
            *p += 1;
            Some(v)
        } else {
            None
        }
    };
    let parse_dot_fqn = |p: &mut usize, t: &[Tok]| -> Option<String> {
        let mut parts = vec![take_ident(p, t)?];
        while eat_punct(p, t, '.') {
            parts.push(take_ident(p, t)?);
        }
        Some(parts.join("."))
    };
    let parse_versioned_fqn = |p: &mut usize, t: &[Tok], implicit_pkg: &str| -> Option<String> {
        // Two accepted shapes:
        //   <dot.fqn> '@' <ver> ('::' <Ident>)?       full form
        //                '@' <ver> ('::' <Ident>)?    shorthand — pkg = implicit_pkg
        let pkg = if matches!(t.get(*p), Some(Tok::AtSymbol)) {
            if implicit_pkg.is_empty() {
                return None;
            }
            // implicit_pkg is the current package fqn (e.g. "a.b@2.0"); strip the
            // @version suffix so the shorthand's own @ver replaces it.
            let dot_pkg = implicit_pkg
                .split_once('@')
                .map(|(p, _)| p)
                .unwrap_or(implicit_pkg);
            dot_pkg.to_string()
        } else {
            parse_dot_fqn(p, t)?
        };
        if !eat_at(p, t) {
            // No '@' — just a dot-fqn (used for non-versioned identifiers in
            // type position).
            return Some(pkg);
        }
        let ver = take_ident(p, t)?;
        let mut s = format!("{}@{}", pkg, ver);
        if matches!(t.get(*p), Some(Tok::DoubleColon)) {
            *p += 1;
            let name = take_ident(p, t)?;
            s.push_str("::");
            s.push_str(&name);
        }
        Some(s)
    };

    // package + version
    if eat_kw(&mut pos, &toks, "package") {
        package = parse_versioned_fqn(&mut pos, &toks, "").ok_or("expected package fqn")?;
        eat_punct(&mut pos, &toks, ';');
    }
    // imports — parse each import statement for two purposes:
    //   1. named imports (import pkg@ver::IName) feed the `imports` map so that
    //      `extends IName` can resolve to the full fqn.
    //   2. every import's package fqn (pkg@ver) is recorded in `pkg_imports` so
    //      the decoder can try qualifying bare type names like `Display` against
    //      each imported package in order.
    let mut imports: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut pkg_imports: Vec<String> = Vec::new();
    while eat_kw(&mut pos, &toks, "import") {
        // parse_versioned_fqn resolves the `@ver` shorthand using `package`,
        // producing a fully-qualified fqn. this is simpler and more correct than
        // the previous raw-token concatenation approach.
        let mut p2 = pos;
        if let Some(full_fqn) = parse_versioned_fqn(&mut p2, &toks, &package) {
            if let Some((pkg_part, name)) = full_fqn.split_once("::") {
                // named import: pkg@ver::Name
                imports.insert(name.to_string(), full_fqn.clone());
                // record the package (dedup)
                if pkg_part.contains('@') {
                    let pkg = pkg_part.to_string();
                    if !pkg_imports.contains(&pkg) {
                        pkg_imports.push(pkg);
                    }
                }
            } else if full_fqn.contains('@') {
                // package-only import: pkg@ver (no :: suffix)
                if !pkg_imports.contains(&full_fqn) {
                    pkg_imports.push(full_fqn);
                }
            }
            pos = p2;
        }
        // skip to the next semicolon
        while let Some(t) = toks.get(pos) {
            pos += 1;
            if matches!(t, Tok::Punct(';')) {
                break;
            }
        }
    }

    fn parse_type(p: &mut usize, t: &[Tok], implicit_pkg: &str) -> Option<TypeRef> {
        let tok = t.get(*p)?.clone();
        let base = match tok {
            Tok::Keyword(kw) => match kw {
                "bool" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::Bool)
                }
                "int8_t" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::I8)
                }
                "uint8_t" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::U8)
                }
                "int16_t" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::I16)
                }
                "uint16_t" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::U16)
                }
                "int32_t" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::I32)
                }
                "uint32_t" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::U32)
                }
                "int64_t" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::I64)
                }
                "uint64_t" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::U64)
                }
                "float" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::F32)
                }
                "double" => {
                    *p += 1;
                    TypeRef::Primitive(Prim::F64)
                }
                "string" => {
                    *p += 1;
                    TypeRef::String
                }
                "vec" => {
                    *p += 1;
                    if !matches!(t.get(*p), Some(Tok::Punct('<'))) {
                        return None;
                    }
                    *p += 1;
                    let inner = parse_type(p, t, implicit_pkg)?;
                    if !matches!(t.get(*p), Some(Tok::Punct('>'))) {
                        return None;
                    }
                    *p += 1;
                    TypeRef::List(Box::new(inner))
                }
                "ref" => {
                    *p += 1;
                    if !matches!(t.get(*p), Some(Tok::Punct('<'))) {
                        return None;
                    }
                    *p += 1;
                    let inner = parse_type(p, t, implicit_pkg)?;
                    if !matches!(t.get(*p), Some(Tok::Punct('>'))) {
                        return None;
                    }
                    *p += 1;
                    inner
                }
                "bitfield" => {
                    *p += 1;
                    if !matches!(t.get(*p), Some(Tok::Punct('<'))) {
                        return None;
                    }
                    *p += 1;
                    let inner = parse_type(p, t, implicit_pkg)?;
                    if !matches!(t.get(*p), Some(Tok::Punct('>'))) {
                        return None;
                    }
                    *p += 1;
                    inner
                }
                "fmq_sync" | "fmq_unsync" => {
                    *p += 1;
                    if !matches!(t.get(*p), Some(Tok::Punct('<'))) {
                        return None;
                    }
                    *p += 1;
                    let inner = parse_type(p, t, implicit_pkg)?;
                    if !matches!(t.get(*p), Some(Tok::Punct('>'))) {
                        return None;
                    }
                    *p += 1;
                    inner
                }
                "handle" => {
                    *p += 1;
                    TypeRef::HidlHandle
                }
                "memory" => {
                    *p += 1;
                    TypeRef::HidlMemory
                }
                "interface" => {
                    *p += 1;
                    TypeRef::UserDefined("interface".into())
                }
                _ => return None,
            },
            Tok::Ident(_) | Tok::AtSymbol => {
                let mut p2 = *p;
                let f = parse_versioned_fqn_inner(&mut p2, t, implicit_pkg)?;
                *p = p2;
                TypeRef::UserDefined(f)
            }
            _ => return None,
        };
        // Trailing `[N]` for fixed-size arrays. Extract N so the decoder can
        // read N inline elements without a count prefix.
        let mut ty = base;
        while matches!(t.get(*p), Some(Tok::Punct('['))) {
            *p += 1;
            // leading Ident is the numeric size literal
            let n = if let Some(Tok::Ident(s)) = t.get(*p) {
                s.parse::<usize>().ok()
            } else {
                None
            };
            // consume to the closing ']'
            while let Some(tok) = t.get(*p) {
                *p += 1;
                if matches!(tok, Tok::Punct(']')) {
                    break;
                }
            }
            ty = match n {
                Some(n) => TypeRef::FixedArray(Box::new(ty), n),
                None => TypeRef::Array(Box::new(ty)), // unknown size: fall back
            };
        }
        Some(ty)
    }
    fn parse_versioned_fqn_inner(p: &mut usize, t: &[Tok], implicit_pkg: &str) -> Option<String> {
        // Shorthand: `@<ver>::<Ident>` resolves into the current package.
        if matches!(t.get(*p), Some(Tok::AtSymbol)) {
            if implicit_pkg.is_empty() {
                return None;
            }
            let dot_pkg = implicit_pkg
                .split_once('@')
                .map(|(p, _)| p)
                .unwrap_or(implicit_pkg);
            *p += 1; // consume '@'
            let ver = match t.get(*p) {
                Some(Tok::Ident(s)) => {
                    let v = s.clone();
                    *p += 1;
                    v
                }
                _ => return None,
            };
            let mut out = format!("{}@{}", dot_pkg, ver);
            if matches!(t.get(*p), Some(Tok::DoubleColon)) {
                *p += 1;
                match t.get(*p) {
                    Some(Tok::Ident(s)) => {
                        out.push_str("::");
                        out.push_str(s);
                        *p += 1;
                    }
                    _ => return None,
                }
            }
            return Some(out);
        }
        let mut parts = Vec::new();
        if let Some(Tok::Ident(s)) = t.get(*p) {
            parts.push(s.clone());
            *p += 1;
        } else {
            return None;
        }
        while matches!(t.get(*p), Some(Tok::Punct('.'))) {
            *p += 1;
            if let Some(Tok::Ident(s)) = t.get(*p) {
                parts.push(s.clone());
                *p += 1;
            } else {
                return None;
            }
        }
        let mut out = parts.join(".");
        if matches!(t.get(*p), Some(Tok::AtSymbol)) {
            *p += 1;
            if let Some(Tok::Ident(s)) = t.get(*p) {
                out.push('@');
                out.push_str(s);
                *p += 1;
            } else {
                return None;
            }
        }
        if matches!(t.get(*p), Some(Tok::DoubleColon)) {
            *p += 1;
            if let Some(Tok::Ident(s)) = t.get(*p) {
                out.push_str("::");
                out.push_str(s);
                *p += 1;
            } else {
                return None;
            }
        }
        Some(out)
    }
    fn parse_param_list(p: &mut usize, t: &[Tok], implicit_pkg: &str) -> Option<Vec<Parameter>> {
        if !matches!(t.get(*p), Some(Tok::Punct('('))) {
            return Some(vec![]);
        }
        *p += 1;
        let mut out = Vec::new();
        while !matches!(t.get(*p), Some(Tok::Punct(')'))) {
            let ty = parse_type(p, t, implicit_pkg)?;
            let name = if let Some(Tok::Ident(s)) = t.get(*p) {
                let v = s.clone();
                *p += 1;
                v
            } else {
                String::new()
            };
            out.push(Parameter {
                name,
                ty,
                direction: Direction::In,
            });
            if matches!(t.get(*p), Some(Tok::Punct(','))) {
                *p += 1;
            } else {
                break;
            }
        }
        if matches!(t.get(*p), Some(Tok::Punct(')'))) {
            *p += 1;
        }
        Some(out)
    }

    // parse the backing type after `:` in `enum Name : backing { ... }`.
    // keyword prims map directly; versioned refs (e.g. `@2.1::IFoo.Bar`) default
    // to I32 since the parent enum's backing isn't resolvable at parse time.
    fn parse_enum_backing(p: &mut usize, t: &[Tok], package: &str) -> Prim {
        match t.get(*p) {
            Some(Tok::Keyword(kw)) => match *kw {
                "bool" => {
                    *p += 1;
                    Prim::Bool
                }
                "int8_t" => {
                    *p += 1;
                    Prim::I8
                }
                "uint8_t" => {
                    *p += 1;
                    Prim::U8
                }
                "int16_t" => {
                    *p += 1;
                    Prim::I16
                }
                "uint16_t" => {
                    *p += 1;
                    Prim::U16
                }
                "int32_t" => {
                    *p += 1;
                    Prim::I32
                }
                "uint32_t" => {
                    *p += 1;
                    Prim::U32
                }
                "int64_t" => {
                    *p += 1;
                    Prim::I64
                }
                "uint64_t" => {
                    *p += 1;
                    Prim::U64
                }
                _ => Prim::I32,
            },
            // versioned ref like `@2.1::IComposerClient.PowerMode` — consume and default I32
            Some(Tok::AtSymbol) | Some(Tok::Ident(_)) => {
                let mut p2 = *p;
                let _ = parse_versioned_fqn_inner(&mut p2, t, package);
                // also consume a trailing dot-qualified suffix (IFoo.Bar)
                while matches!(t.get(p2), Some(Tok::Punct('.'))) {
                    p2 += 1;
                    if matches!(t.get(p2), Some(Tok::Ident(_))) {
                        p2 += 1;
                    }
                }
                *p = p2;
                Prim::I32
            }
            _ => Prim::I32,
        }
    }

    // parse enum const list inside `{ ... }`. returns (name, value) pairs using
    // C-enum auto-increment from 0. hex (0x...) and decimal literals supported.
    fn parse_enum_consts(p: &mut usize, t: &[Tok]) -> Vec<(String, i64)> {
        let mut consts: Vec<(String, i64)> = Vec::new();
        let mut next_val: i64 = 0;
        while !matches!(t.get(*p), Some(Tok::Punct('}')) | None) {
            let name = match t.get(*p) {
                Some(Tok::Ident(s)) => {
                    let v = s.clone();
                    *p += 1;
                    v
                }
                // skip anything that isn't an ident (stray tokens)
                _ => {
                    *p += 1;
                    continue;
                }
            };
            let val = if matches!(t.get(*p), Some(Tok::Punct('='))) {
                *p += 1;
                let negate = if matches!(t.get(*p), Some(Tok::Punct('-'))) {
                    *p += 1;
                    true
                } else {
                    false
                };
                let n = match t.get(*p) {
                    Some(Tok::Ident(s)) => {
                        let lit = s.clone();
                        *p += 1;
                        let parsed = if lit.starts_with("0x") || lit.starts_with("0X") {
                            i64::from_str_radix(&lit[2..], 16).unwrap_or(next_val)
                        } else {
                            lit.parse::<i64>().unwrap_or(next_val)
                        };
                        parsed
                    }
                    // non-literal value (expression, ref) — skip to separator, keep next_val
                    _ => {
                        while !matches!(t.get(*p), Some(Tok::Punct(',') | Tok::Punct('}')))
                            && *p < t.len()
                        {
                            *p += 1;
                        }
                        if matches!(t.get(*p), Some(Tok::Punct(','))) {
                            *p += 1;
                        }
                        consts.push((name, next_val));
                        next_val += 1;
                        continue;
                    }
                };
                let n = if negate { -n } else { n };
                next_val = n + 1;
                n
            } else {
                let n = next_val;
                next_val += 1;
                n
            };
            consts.push((name, val));
            while !matches!(t.get(*p), Some(Tok::Punct(',') | Tok::Punct('}'))) && *p < t.len() {
                *p += 1;
            }
            if matches!(t.get(*p), Some(Tok::Punct(','))) {
                *p += 1;
            }
        }
        consts
    }

    let mut interfaces: Vec<Interface> = Vec::new();
    let mut typedefs: Vec<(String, TypeRef)> = Vec::new();
    let mut parcelables: Vec<Parcelable> = Vec::new();
    let mut enums: Vec<EnumDef> = Vec::new();
    while pos < toks.len() {
        if eat_kw(&mut pos, &toks, "interface") {
            let name = take_ident(&mut pos, &toks).ok_or("expected interface name")?;
            let extends = if eat_kw(&mut pos, &toks, "extends") {
                let raw =
                    parse_versioned_fqn(&mut pos, &toks, &package).ok_or("expected parent fqn")?;
                // Bare ident (no '@') resolves either through imports
                // (`import a@1.0::IFoo;` then `extends IFoo`) or via current-
                // package shorthand (`extends IStream` inside `package x@1.0;`).
                if raw.contains('@') {
                    Some(raw)
                } else if let Some(fqn) = imports.get(&raw) {
                    Some(fqn.clone())
                } else if package.is_empty() {
                    Some(raw)
                } else {
                    Some(format!("{}::{}", package, raw))
                }
            } else {
                None
            };
            if !eat_punct(&mut pos, &toks, '{') {
                return Err("expected '{' after interface".into());
            }
            let mut methods: Vec<Method> = Vec::new();
            while !matches!(toks.get(pos), Some(Tok::Punct('}'))) {
                if pos >= toks.len() {
                    return Err("unterminated interface".into());
                }
                // nested enum: parse into enums with fqn pkg::Iface.EnumName
                if eat_kw(&mut pos, &toks, "enum") {
                    let ename = match toks.get(pos) {
                        Some(Tok::Ident(s)) => {
                            let v = s.clone();
                            pos += 1;
                            v
                        }
                        _ => String::new(),
                    };
                    let backing = if eat_punct(&mut pos, &toks, ':') {
                        parse_enum_backing(&mut pos, &toks, &package)
                    } else {
                        Prim::I32
                    };
                    if eat_punct(&mut pos, &toks, '{') {
                        let consts = parse_enum_consts(&mut pos, &toks);
                        if matches!(toks.get(pos), Some(Tok::Punct('}'))) {
                            pos += 1;
                        }
                        eat_punct(&mut pos, &toks, ';');
                        if !ename.is_empty() && !package.is_empty() {
                            let efqn = format!("{}::{}.{}", package, name, ename);
                            enums.push(EnumDef {
                                fqn: efqn,
                                backing,
                                consts,
                            });
                        }
                    } else {
                        // no '{' — skip to ';'
                        while let Some(t) = toks.get(pos) {
                            pos += 1;
                            if matches!(t, Tok::Punct(';')) {
                                break;
                            }
                        }
                    }
                    continue;
                }
                // nested struct: parse into parcelables with fqn pkg::Iface.StructName
                if eat_kw(&mut pos, &toks, "struct") {
                    let sname = match toks.get(pos) {
                        Some(Tok::Ident(s)) => {
                            let v = s.clone();
                            pos += 1;
                            v
                        }
                        _ => String::new(),
                    };
                    if eat_punct(&mut pos, &toks, '{') {
                        let mut fields: Vec<Field> = Vec::new();
                        while pos < toks.len() && !matches!(toks.get(pos), Some(Tok::Punct('}'))) {
                            let Some(ty) = parse_type(&mut pos, &toks, &package) else {
                                while let Some(t) = toks.get(pos) {
                                    pos += 1;
                                    if matches!(t, Tok::Punct(';')) {
                                        break;
                                    }
                                }
                                continue;
                            };
                            let fname = match toks.get(pos) {
                                Some(Tok::Ident(s)) => {
                                    let v = s.clone();
                                    pos += 1;
                                    v
                                }
                                _ => String::new(),
                            };
                            while let Some(t) = toks.get(pos) {
                                pos += 1;
                                if matches!(t, Tok::Punct(';')) {
                                    break;
                                }
                            }
                            fields.push(Field { name: fname, ty });
                        }
                        if matches!(toks.get(pos), Some(Tok::Punct('}'))) {
                            pos += 1;
                        }
                        eat_punct(&mut pos, &toks, ';');
                        if !sname.is_empty() && !package.is_empty() {
                            let sfqn = format!("{}::{}.{}", package, name, sname);
                            parcelables.push(Parcelable { fqn: sfqn, fields });
                        }
                    } else {
                        while let Some(t) = toks.get(pos) {
                            pos += 1;
                            if matches!(t, Tok::Punct(';')) {
                                break;
                            }
                        }
                    }
                    continue;
                }
                // union/safe_union/typedef inside interface — skip body, don't collect
                if eat_kw(&mut pos, &toks, "union")
                    || eat_kw(&mut pos, &toks, "safe_union")
                    || eat_kw(&mut pos, &toks, "typedef")
                {
                    while let Some(t) = toks.get(pos) {
                        pos += 1;
                        if matches!(t, Tok::Punct('{')) {
                            let mut d = 1;
                            while d > 0 {
                                match toks.get(pos) {
                                    Some(Tok::Punct('{')) => {
                                        d += 1;
                                        pos += 1;
                                    }
                                    Some(Tok::Punct('}')) => {
                                        d -= 1;
                                        pos += 1;
                                    }
                                    None => break,
                                    _ => pos += 1,
                                }
                            }
                            eat_punct(&mut pos, &toks, ';');
                            break;
                        }
                        if matches!(t, Tok::Punct(';')) {
                            break;
                        }
                    }
                    continue;
                }
                let oneway = eat_kw(&mut pos, &toks, "oneway");
                let mname = match toks.get(pos) {
                    Some(Tok::Ident(s)) => {
                        let v = s.clone();
                        pos += 1;
                        v
                    }
                    _ => {
                        pos += 1;
                        continue;
                    }
                };
                let params = parse_param_list(&mut pos, &toks, &package).ok_or("bad params")?;
                let return_type = if eat_kw(&mut pos, &toks, "generates") {
                    let g = parse_param_list(&mut pos, &toks, &package).ok_or("bad generates")?;
                    g.into_iter().next().map(|p| p.ty)
                } else {
                    None
                };
                while let Some(t) = toks.get(pos) {
                    pos += 1;
                    if matches!(t, Tok::Punct(';')) {
                        break;
                    }
                }
                methods.push(Method {
                    name: mname,
                    params,
                    return_type,
                    oneway,
                    code: None,
                });
            }
            if matches!(toks.get(pos), Some(Tok::Punct('}'))) {
                pos += 1;
            }
            eat_punct(&mut pos, &toks, ';');
            let fqn = format!("{}::{}", package, name);
            interfaces.push(Interface {
                fqn,
                flavor: Flavor::Hidl,
                base_code: 1,
                methods,
                extends,
                imports: pkg_imports.clone(),
            });
        } else if eat_kw(&mut pos, &toks, "typedef") {
            // `typedef <TargetType> <Name> ;` at the package top-level.
            // parse_type handles primitives, vec<>, versioned fqns, etc.
            if let Some(target) = parse_type(&mut pos, &toks, &package) {
                if let Some(name) = take_ident(&mut pos, &toks) {
                    eat_punct(&mut pos, &toks, ';');
                    if !package.is_empty() {
                        let fqn = format!("{}::{}", package, name);
                        typedefs.push((fqn, target));
                    }
                } else {
                    // no name token — skip to ';'
                    while let Some(t) = toks.get(pos) {
                        pos += 1;
                        if matches!(t, Tok::Punct(';')) {
                            break;
                        }
                    }
                }
            } else {
                // parse_type failed — skip to ';'
                while let Some(t) = toks.get(pos) {
                    pos += 1;
                    if matches!(t, Tok::Punct(';')) {
                        break;
                    }
                }
            }
        } else if eat_kw(&mut pos, &toks, "struct") {
            // top-level `struct Name { fields };` — parse fields as a Parcelable.
            // only primitive-typed fields are captured; complex fields are skipped with
            // the struct still recorded (so hidl_type_size_align can compute layout).
            let name = take_ident(&mut pos, &toks).unwrap_or_default();
            let fqn = if !package.is_empty() && !name.is_empty() {
                format!("{}::{}", package, name)
            } else {
                String::new()
            };
            if eat_punct(&mut pos, &toks, '{') {
                let mut fields: Vec<Field> = Vec::new();
                while pos < toks.len() && !matches!(toks.get(pos), Some(Tok::Punct('}'))) {
                    let field_start = pos;
                    let Some(ty) = parse_type(&mut pos, &toks, &package) else {
                        // skip to next ';'
                        while let Some(t) = toks.get(pos) {
                            pos += 1;
                            if matches!(t, Tok::Punct(';')) {
                                break;
                            }
                        }
                        continue;
                    };
                    let fname = match toks.get(pos) {
                        Some(Tok::Ident(s)) => {
                            let v = s.clone();
                            pos += 1;
                            v
                        }
                        _ => String::new(),
                    };
                    // skip optional array suffix and trailing ';'
                    while let Some(t) = toks.get(pos) {
                        pos += 1;
                        if matches!(t, Tok::Punct(';')) {
                            break;
                        }
                    }
                    let _ = field_start; // parsed, not skipped
                    fields.push(Field { name: fname, ty });
                }
                if matches!(toks.get(pos), Some(Tok::Punct('}'))) {
                    pos += 1;
                }
                eat_punct(&mut pos, &toks, ';');
                if !fqn.is_empty() {
                    parcelables.push(Parcelable { fqn, fields });
                }
            } else {
                // no '{' — skip to ';'
                while let Some(t) = toks.get(pos) {
                    pos += 1;
                    if matches!(t, Tok::Punct(';')) {
                        break;
                    }
                }
            }
        } else if eat_kw(&mut pos, &toks, "enum") {
            // top-level `enum Name [: backing] { ... };` — parse as EnumDef
            let ename = take_ident(&mut pos, &toks).unwrap_or_default();
            let backing = if eat_punct(&mut pos, &toks, ':') {
                parse_enum_backing(&mut pos, &toks, &package)
            } else {
                Prim::I32
            };
            if eat_punct(&mut pos, &toks, '{') {
                let consts = parse_enum_consts(&mut pos, &toks);
                if matches!(toks.get(pos), Some(Tok::Punct('}'))) {
                    pos += 1;
                }
                eat_punct(&mut pos, &toks, ';');
                if !ename.is_empty() && !package.is_empty() {
                    let efqn = format!("{}::{}", package, ename);
                    enums.push(EnumDef {
                        fqn: efqn,
                        backing,
                        consts,
                    });
                }
            } else {
                // no '{' — skip to ';'
                while let Some(t) = toks.get(pos) {
                    pos += 1;
                    if matches!(t, Tok::Punct(';')) {
                        break;
                    }
                }
            }
        } else if eat_kw(&mut pos, &toks, "union") {
            // skip body — balanced braces or up to ';'
            while let Some(t) = toks.get(pos) {
                pos += 1;
                if matches!(t, Tok::Punct('{')) {
                    let mut d = 1;
                    while d > 0 {
                        match toks.get(pos) {
                            Some(Tok::Punct('{')) => {
                                d += 1;
                                pos += 1;
                            }
                            Some(Tok::Punct('}')) => {
                                d -= 1;
                                pos += 1;
                            }
                            None => break,
                            _ => pos += 1,
                        }
                    }
                    break;
                }
                if matches!(t, Tok::Punct(';')) {
                    break;
                }
            }
        } else {
            pos += 1; // skip unrecognized
        }
    }
    Ok(HidlParsed {
        interfaces,
        typedefs,
        parcelables,
        enums,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn parses_package_with_version() {
        let src = "package android.hardware.foo@1.0;";
        let r = parse_hidl(src).unwrap();
        assert!(r.interfaces.is_empty());
    }

    #[test]
    fn parses_interface_with_method() {
        let src = "package a@1.0; interface IFoo { hello(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces.len(), 1);
        assert_eq!(r.interfaces[0].fqn, "a@1.0::IFoo");
        assert_eq!(r.interfaces[0].methods[0].name, "hello");
        assert_eq!(r.interfaces[0].methods[0].return_type, None);
    }

    #[test]
    fn parses_method_with_generates() {
        let src =
            "package a@1.0; interface IFoo { add(int32_t a, int32_t b) generates (int32_t r); };";
        let r = parse_hidl(src).unwrap();
        let m = &r.interfaces[0].methods[0];
        assert_eq!(m.name, "add");
        assert_eq!(m.params.len(), 2);
        assert_eq!(m.return_type, Some(TypeRef::Primitive(Prim::I32)));
    }

    #[test]
    fn parses_extends() {
        let src = "package a@1.0; interface IFoo extends b@2.0::IBar { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].extends, Some("b@2.0::IBar".into()));
    }

    #[test]
    fn parses_oneway() {
        let src = "package a@1.0; interface IFoo { oneway fire(); };";
        let r = parse_hidl(src).unwrap();
        assert!(r.interfaces[0].methods[0].oneway);
    }

    #[test]
    fn inheritance_offsets_base_code() {
        use crate::parser::hidl::resolve_inheritance;
        let parent = Interface {
            fqn: "p@1.0::IBase".into(),
            flavor: Flavor::Hidl,
            base_code: 1,
            methods: vec![
                Method {
                    name: "p1".into(),
                    params: vec![],
                    return_type: None,
                    oneway: false,
                    code: None,
                },
                Method {
                    name: "p2".into(),
                    params: vec![],
                    return_type: None,
                    oneway: false,
                    code: None,
                },
                Method {
                    name: "p3".into(),
                    params: vec![],
                    return_type: None,
                    oneway: false,
                    code: None,
                },
            ],
            extends: None,
            imports: vec![],
        };
        let child = Interface {
            fqn: "c@1.0::IChild".into(),
            flavor: Flavor::Hidl,
            base_code: 1,
            methods: vec![Method {
                name: "c1".into(),
                params: vec![],
                return_type: None,
                oneway: false,
                code: None,
            }],
            extends: Some("p@1.0::IBase".into()),
            imports: vec![],
        };
        let ifaces = resolve_inheritance(vec![parent, child]).unwrap();
        let by_fqn: std::collections::HashMap<_, _> =
            ifaces.iter().map(|i| (i.fqn.clone(), i)).collect();
        assert_eq!(by_fqn["p@1.0::IBase"].base_code, 1);
        assert_eq!(by_fqn["c@1.0::IChild"].base_code, 4); // 1 + 3 parent methods
        assert_eq!(by_fqn["c@1.0::IChild"].lookup(4).unwrap().name, "c1");
    }

    #[test]
    fn inheritance_unknown_parent_errors() {
        use crate::parser::hidl::resolve_inheritance;
        let orphan = Interface {
            fqn: "x@1.0::IOrphan".into(),
            flavor: Flavor::Hidl,
            base_code: 1,
            methods: vec![Method {
                name: "f".into(),
                params: vec![],
                return_type: None,
                oneway: false,
                code: None,
            }],
            extends: Some("missing@1.0::IGone".into()),
            imports: vec![],
        };
        let err = resolve_inheritance(vec![orphan]).unwrap_err();
        assert!(err.contains("missing@1.0::IGone"), "got: {}", err);
    }

    #[test]
    fn parses_extends_with_current_package_shorthand() {
        let src = "package a.b@2.0; \
                   interface IFoo extends @1.0::IBar { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces.len(), 1);
        assert_eq!(r.interfaces[0].fqn, "a.b@2.0::IFoo");
        // Parent must resolve into the current package.
        assert_eq!(r.interfaces[0].extends.as_deref(), Some("a.b@1.0::IBar"));
    }

    #[test]
    fn parses_extends_with_full_versioned_fqn() {
        // Regression — full form must keep working.
        let src = "package a@1.0; interface IFoo extends b@2.0::IBar { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].extends.as_deref(), Some("b@2.0::IBar"));
    }

    #[test]
    fn parses_bitfield_in_param() {
        let src = "package a@1.0; \
                   interface I { setMask(bitfield<X> mask); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 1);
        assert_eq!(r.interfaces[0].methods[0].name, "setMask");
        assert_eq!(r.interfaces[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_bitfield_in_generates_clause() {
        let src = "package a@1.0; \
                   interface I { getMask() generates (bitfield<X> mask); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods[0].name, "getMask");
    }

    #[test]
    fn parses_fmq_types() {
        let src = "package a@1.0; \
                   interface I { \
                       q1(fmq_sync<uint8_t> a); \
                       q2(fmq_unsync<uint8_t> a); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 2);
    }

    #[test]
    fn skips_nested_struct_and_enum_inside_interface() {
        let src = "package a@1.0; \
                   interface I { \
                       enum BitField : uint8_t { V0 = 1, V1 = 2 }; \
                       struct J { vec<uint32_t> j1; }; \
                       safe_union U { uint8_t a; uint16_t b; }; \
                       typedef uint32_t Foo; \
                       doStuff(uint32_t x); \
                       doMore() generates (uint32_t r); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces.len(), 1);
        let names: Vec<_> = r.interfaces[0]
            .methods
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert_eq!(names, vec!["doStuff", "doMore"]);
    }

    #[test]
    fn parses_type_with_at_version_shorthand() {
        let src = "package a@1.0; \
                   interface I { \
                       foo() generates (@2.0::Bar b); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 1);
        assert_eq!(r.interfaces[0].methods[0].name, "foo");
    }

    #[test]
    fn parses_interface_keyword_as_type() {
        // HIDL allows `interface` as a generic interface-handle type.
        let src = "package a@1.0; \
                   interface I { \
                       foo(vec<interface> ifs); \
                       bar() generates (interface i); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 2);
    }

    #[test]
    fn parses_extends_with_bare_ident_in_current_package() {
        let src = "package a.b@1.0; \
                   interface IChild extends IBase { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].extends.as_deref(), Some("a.b@1.0::IBase"));
    }

    #[test]
    fn parses_extends_via_import() {
        let src = "package a.b@1.0; \
                   import x.y@2.0::IBase; \
                   interface IChild extends IBase { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].extends.as_deref(), Some("x.y@2.0::IBase"));
    }

    #[test]
    fn parses_sized_array_type() {
        // HIDL allows fixed-size arrays, including nested inside vec<>.
        let src = "package a@1.0; \
                   interface I { \
                       foo() generates (vec<uint8_t[16]> schemes); \
                       bar(uint32_t[4] m); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 2);
    }

    #[test]
    fn parses_fixed_array_preserves_count() {
        let src = "package a@1.0; interface I { bar(uint32_t[4] m); };";
        let r = parse_hidl(src).unwrap();
        let ty = &r.interfaces[0].methods[0].params[0].ty;
        assert!(
            matches!(ty, TypeRef::FixedArray(inner, 4) if matches!(inner.as_ref(), TypeRef::Primitive(Prim::U32))),
            "expected FixedArray(U32, 4), got {ty:?}",
        );
    }

    #[test]
    fn parses_handle_and_memory_types() {
        let src = "package a@1.0; interface I { \
                   setHandle(handle h); \
                   setMemory(memory m); \
               };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 2);
        assert_eq!(r.interfaces[0].methods[0].params[0].ty, TypeRef::HidlHandle);
        assert_eq!(r.interfaces[0].methods[1].params[0].ty, TypeRef::HidlMemory);
    }

    // --- typedef tests ---

    #[test]
    fn parses_toplevel_typedef_primitive() {
        let src = "package android.hardware.graphics.composer@2.4; \
                   typedef uint64_t Display;";
        let r = parse_hidl(src).unwrap();
        assert!(r.interfaces.is_empty());
        assert_eq!(r.typedefs.len(), 1);
        assert_eq!(
            r.typedefs[0].0,
            "android.hardware.graphics.composer@2.4::Display"
        );
        assert_eq!(r.typedefs[0].1, TypeRef::Primitive(Prim::U64));
    }

    #[test]
    fn parses_multiple_toplevel_typedefs() {
        let src = "package a@1.0; \
                   typedef uint64_t Display; \
                   typedef uint32_t Config; \
                   typedef int64_t VsyncPeriodNanos;";
        let r = parse_hidl(src).unwrap();
        assert!(r.interfaces.is_empty());
        assert_eq!(r.typedefs.len(), 3);
        assert_eq!(r.typedefs[0].0, "a@1.0::Display");
        assert_eq!(r.typedefs[0].1, TypeRef::Primitive(Prim::U64));
        assert_eq!(r.typedefs[1].0, "a@1.0::Config");
        assert_eq!(r.typedefs[1].1, TypeRef::Primitive(Prim::U32));
        assert_eq!(r.typedefs[2].0, "a@1.0::VsyncPeriodNanos");
        assert_eq!(r.typedefs[2].1, TypeRef::Primitive(Prim::I64));
    }

    #[test]
    fn typedef_coexists_with_interface() {
        // typedef before interface — both must be captured
        let src = "package a@1.0; \
                   typedef uint32_t MyId; \
                   interface IFoo { void foo(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces.len(), 1);
        assert_eq!(r.interfaces[0].fqn, "a@1.0::IFoo");
        assert_eq!(r.typedefs.len(), 1);
        assert_eq!(r.typedefs[0].0, "a@1.0::MyId");
        assert_eq!(r.typedefs[0].1, TypeRef::Primitive(Prim::U32));
    }

    #[test]
    fn nested_typedef_inside_interface_body_still_skipped() {
        // typedef inside an interface body is skipped; only top-level is captured
        let src = "package a@1.0; \
                   interface I { typedef uint32_t Foo; doStuff(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces.len(), 1);
        assert_eq!(r.interfaces[0].methods.len(), 1);
        assert_eq!(r.interfaces[0].methods[0].name, "doStuff");
        // no top-level typedef captured
        assert!(r.typedefs.is_empty());
    }

    // --- enum parsing tests ---

    #[test]
    fn nested_enum_inside_interface_parsed_correctly() {
        let src = "package x@1.0; \
                   interface I { \
                       enum P : int32_t { A = 0, B = 1 }; \
                       foo(P p); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.enums.len(), 1, "expected 1 enum, got {:?}", r.enums);
        let e = &r.enums[0];
        assert_eq!(e.fqn, "x@1.0::I.P");
        assert_eq!(e.backing, Prim::I32);
        assert_eq!(
            e.consts,
            vec![("A".to_string(), 0i64), ("B".to_string(), 1i64)]
        );
        // method still parsed
        assert_eq!(r.interfaces[0].methods.len(), 1);
        assert_eq!(r.interfaces[0].methods[0].name, "foo");
    }

    #[test]
    fn top_level_enum_parsed() {
        let src = "package x@1.0; enum E : uint8_t { X = 1, Y = 2 };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.enums.len(), 1);
        let e = &r.enums[0];
        assert_eq!(e.fqn, "x@1.0::E");
        assert_eq!(e.backing, Prim::U8);
        assert_eq!(
            e.consts,
            vec![("X".to_string(), 1i64), ("Y".to_string(), 2i64)]
        );
    }

    #[test]
    fn top_level_enum_no_backing_defaults_i32() {
        let src = "package x@1.0; enum E { ZERO, ONE, TWO };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.enums.len(), 1);
        let e = &r.enums[0];
        assert_eq!(e.backing, Prim::I32);
        assert_eq!(
            e.consts,
            vec![
                ("ZERO".to_string(), 0i64),
                ("ONE".to_string(), 1i64),
                ("TWO".to_string(), 2i64)
            ]
        );
    }

    #[test]
    fn enum_extends_parent_ref_defaults_i32() {
        // backing is a versioned ref: resolve is deferred, default to I32
        let src = "package x@2.0; interface I { enum Q : @1.0::I.P { C }; };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.enums.len(), 1);
        let e = &r.enums[0];
        assert_eq!(e.fqn, "x@2.0::I.Q");
        assert_eq!(e.backing, Prim::I32);
        // C has no explicit value, gets 0 (C-enum rule from 0)
        assert_eq!(e.consts, vec![("C".to_string(), 0i64)]);
    }

    #[test]
    fn enum_hex_literal_const() {
        let src = "package a@1.0; enum Cmd : int32_t { SELECT = 0x0000, SET = 0x0100 };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.enums.len(), 1);
        let e = &r.enums[0];
        assert_eq!(
            e.consts,
            vec![("SELECT".to_string(), 0i64), ("SET".to_string(), 0x0100i64)]
        );
    }

    #[test]
    fn nested_struct_inside_interface_parsed_as_parcelable() {
        let src = "package a@1.0; \
                   interface I { \
                       struct Rect { int32_t x; int32_t y; }; \
                       doSomething(Rect r); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.parcelables.len(), 1);
        let p = &r.parcelables[0];
        assert_eq!(p.fqn, "a@1.0::I.Rect");
        assert_eq!(p.fields.len(), 2);
        assert_eq!(p.fields[0].name, "x");
        assert_eq!(p.fields[1].name, "y");
        // method still parsed
        assert_eq!(r.interfaces[0].methods.len(), 1);
    }

    #[test]
    fn nested_types_dont_disrupt_method_parsing_with_populated_caches() {
        // same scenario as the old skip test; enums and structs are now parsed,
        // but method list must still be correct.
        let src = "package a@1.0; \
                   interface I { \
                       enum BitField : uint8_t { V0 = 1, V1 = 2 }; \
                       struct J { int32_t j1; }; \
                       safe_union U { uint8_t a; uint16_t b; }; \
                       typedef uint32_t Foo; \
                       doStuff(uint32_t x); \
                       doMore() generates (uint32_t r); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.interfaces.len(), 1);
        let names: Vec<_> = r.interfaces[0]
            .methods
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert_eq!(names, vec!["doStuff", "doMore"]);
        // enums and parcelables collected
        assert_eq!(r.enums.len(), 1);
        assert_eq!(r.enums[0].fqn, "a@1.0::I.BitField");
        assert_eq!(r.enums[0].backing, Prim::U8);
        assert_eq!(r.parcelables.len(), 1);
        assert_eq!(r.parcelables[0].fqn, "a@1.0::I.J");
    }
}

// HIDL inheritance crosses .hal files, so callers must gather every interface
// they want resolvable into a single `Vec<Interface>` before calling this.
// Returns Err if any `extends` parent is not present in the input — silently
// pretending the parent has zero methods would produce wrong base_codes for
// child interfaces and silently mis-resolve transactions.
pub fn resolve_inheritance(mut interfaces: Vec<Interface>) -> Result<Vec<Interface>, String> {
    use std::collections::HashMap;
    let counts: HashMap<String, usize> = interfaces
        .iter()
        .map(|i| (i.fqn.clone(), i.methods.len()))
        .collect();

    fn ancestor_method_total(
        fqn: &str,
        edges: &HashMap<String, Option<String>>,
        counts: &HashMap<String, usize>,
        seen: &mut std::collections::HashSet<String>,
    ) -> Result<usize, String> {
        if !seen.insert(fqn.to_string()) {
            // cycle: HIDL grammar forbids this, but guard so we don't recurse forever.
            return Err(format!("inheritance cycle at {}", fqn));
        }
        match edges.get(fqn).and_then(|p| p.clone()) {
            None => Ok(0),
            Some(parent) => match counts.get(&parent) {
                Some(n) => Ok(ancestor_method_total(&parent, edges, counts, seen)? + n),
                None => Err(format!(
                    "interface {} extends unknown parent {}",
                    fqn, parent
                )),
            },
        }
    }

    let edges: HashMap<String, Option<String>> = interfaces
        .iter()
        .map(|i| (i.fqn.clone(), i.extends.clone()))
        .collect();

    for iface in interfaces.iter_mut() {
        let mut seen = std::collections::HashSet::new();
        let total = ancestor_method_total(&iface.fqn, &edges, &counts, &mut seen)?;
        iface.base_code = 1 + total as u32;
    }
    Ok(interfaces)
}
