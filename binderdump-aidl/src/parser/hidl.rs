// HIDL parser. Versioned package syntax (`package a.b@1.0;`) and
// `extends b@1.0::IBar` make this distinct from AIDL: HIDL child interfaces
// continue parent method numbering, so resolve_inheritance() must run after
// every .hal in scope is parsed before base_codes are valid.

use crate::model::{Direction, Flavor, Interface, Method, Parameter, Prim, TypeRef};

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
        if "{}()[]<>;,.=".contains(c) {
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
                | "fmq_unsync" | "safe_union" => {
                    Tok::Keyword(Box::leak(word.to_string().into_boxed_str()))
                }
                _ => Tok::Ident(word.to_string()),
            });
            continue;
        }
        if c.is_ascii_digit() {
            // skip numeric literals (versions handled specially)
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            out.push(Tok::Ident(src[start..i].to_string()));
            continue;
        }
        // unknown char — skip
        i += 1;
    }
    out
}

pub fn parse_hidl(source: &str) -> Result<Vec<Interface>, String> {
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
    // imports — skip
    // Map bare interface name -> fully-qualified import target, so
    // `extends IFoo` can resolve to `pkg@ver::IFoo` when IFoo was imported.
    let mut imports: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    while eat_kw(&mut pos, &toks, "import") {
        let start = pos;
        while let Some(t) = toks.get(pos) {
            pos += 1;
            if matches!(t, Tok::Punct(';')) {
                break;
            }
        }
        // Only `import x.y@1.0::IName;` contributes a name; package-only
        // imports (`import x.y@1.0;`) are skipped.
        let stop = pos.saturating_sub(1); // before the ';'
        let mut bracket_depth = 0i32;
        for i in start..stop {
            if matches!(toks.get(i), Some(Tok::DoubleColon)) && bracket_depth == 0 {
                if let Some(Tok::Ident(name)) = toks.get(i + 1) {
                    // Reconstruct the full fqn from `start..i+2`.
                    let mut fqn = String::new();
                    for j in start..i {
                        match toks.get(j) {
                            Some(Tok::Ident(s)) => fqn.push_str(s),
                            Some(Tok::Punct('.')) => fqn.push('.'),
                            Some(Tok::AtSymbol) => fqn.push('@'),
                            _ => {}
                        }
                    }
                    fqn.push_str("::");
                    fqn.push_str(name);
                    imports.insert(name.clone(), fqn);
                }
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
        // Trailing `[N]` for sized arrays. HIDL only allows fixed-size; the
        // size value is irrelevant for method-resolution.
        let mut ty = base;
        while matches!(t.get(*p), Some(Tok::Punct('['))) {
            *p += 1;
            // Walk past the size token (Ident with the numeric literal) and
            // the closing `]`. Multi-dim arrays repeat naturally.
            while let Some(tok) = t.get(*p) {
                *p += 1;
                if matches!(tok, Tok::Punct(']')) {
                    break;
                }
            }
            ty = TypeRef::Array(Box::new(ty));
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

    let mut interfaces: Vec<Interface> = Vec::new();
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
                // Skip nested type decls — they don't contribute to transaction codes.
                if eat_kw(&mut pos, &toks, "enum")
                    || eat_kw(&mut pos, &toks, "struct")
                    || eat_kw(&mut pos, &toks, "union")
                    || eat_kw(&mut pos, &toks, "safe_union")
                    || eat_kw(&mut pos, &toks, "typedef")
                {
                    // Walk to either the matching `};` (block decl) or trailing `;`
                    // (typedef). Track brace depth.
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
                            // Optional trailing `;` after `}`.
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
            });
        } else if eat_kw(&mut pos, &toks, "typedef")
            || eat_kw(&mut pos, &toks, "enum")
            || eat_kw(&mut pos, &toks, "struct")
            || eat_kw(&mut pos, &toks, "union")
        {
            // Skip body — balanced braces or up to ';'.
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
    Ok(interfaces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn parses_package_with_version() {
        let src = "package android.hardware.foo@1.0;";
        let r = parse_hidl(src).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn parses_interface_with_method() {
        let src = "package a@1.0; interface IFoo { hello(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].fqn, "a@1.0::IFoo");
        assert_eq!(r[0].methods[0].name, "hello");
        assert_eq!(r[0].methods[0].return_type, None);
    }

    #[test]
    fn parses_method_with_generates() {
        let src =
            "package a@1.0; interface IFoo { add(int32_t a, int32_t b) generates (int32_t r); };";
        let r = parse_hidl(src).unwrap();
        let m = &r[0].methods[0];
        assert_eq!(m.name, "add");
        assert_eq!(m.params.len(), 2);
        assert_eq!(m.return_type, Some(TypeRef::Primitive(Prim::I32)));
    }

    #[test]
    fn parses_extends() {
        let src = "package a@1.0; interface IFoo extends b@2.0::IBar { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r[0].extends, Some("b@2.0::IBar".into()));
    }

    #[test]
    fn parses_oneway() {
        let src = "package a@1.0; interface IFoo { oneway fire(); };";
        let r = parse_hidl(src).unwrap();
        assert!(r[0].methods[0].oneway);
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
        };
        let err = resolve_inheritance(vec![orphan]).unwrap_err();
        assert!(err.contains("missing@1.0::IGone"), "got: {}", err);
    }

    #[test]
    fn parses_extends_with_current_package_shorthand() {
        let src = "package a.b@2.0; \
                   interface IFoo extends @1.0::IBar { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].fqn, "a.b@2.0::IFoo");
        // Parent must resolve into the current package.
        assert_eq!(r[0].extends.as_deref(), Some("a.b@1.0::IBar"));
    }

    #[test]
    fn parses_extends_with_full_versioned_fqn() {
        // Regression — full form must keep working.
        let src = "package a@1.0; interface IFoo extends b@2.0::IBar { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r[0].extends.as_deref(), Some("b@2.0::IBar"));
    }

    #[test]
    fn parses_bitfield_in_param() {
        let src = "package a@1.0; \
                   interface I { setMask(bitfield<X> mask); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r[0].methods.len(), 1);
        assert_eq!(r[0].methods[0].name, "setMask");
        assert_eq!(r[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_bitfield_in_generates_clause() {
        let src = "package a@1.0; \
                   interface I { getMask() generates (bitfield<X> mask); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r[0].methods[0].name, "getMask");
    }

    #[test]
    fn parses_fmq_types() {
        let src = "package a@1.0; \
                   interface I { \
                       q1(fmq_sync<uint8_t> a); \
                       q2(fmq_unsync<uint8_t> a); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r[0].methods.len(), 2);
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
        assert_eq!(r.len(), 1);
        let names: Vec<_> = r[0].methods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["doStuff", "doMore"]);
    }

    #[test]
    fn parses_type_with_at_version_shorthand() {
        let src = "package a@1.0; \
                   interface I { \
                       foo() generates (@2.0::Bar b); \
                   };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r[0].methods.len(), 1);
        assert_eq!(r[0].methods[0].name, "foo");
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
        assert_eq!(r[0].methods.len(), 2);
    }

    #[test]
    fn parses_extends_with_bare_ident_in_current_package() {
        let src = "package a.b@1.0; \
                   interface IChild extends IBase { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r[0].extends.as_deref(), Some("a.b@1.0::IBase"));
    }

    #[test]
    fn parses_extends_via_import() {
        let src = "package a.b@1.0; \
                   import x.y@2.0::IBase; \
                   interface IChild extends IBase { hi(); };";
        let r = parse_hidl(src).unwrap();
        assert_eq!(r[0].extends.as_deref(), Some("x.y@2.0::IBase"));
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
        assert_eq!(r[0].methods.len(), 2);
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
