// AIDL parser: chumsky-driven lexer feeding a hand-rolled recursive-descent
// over a token cursor. Recovers interfaces (methods + codes) for transaction
// resolution, and captures parcelable/enum/union bodies for field decoding.

use chumsky::prelude::*;

#[derive(Debug, Default)]
pub struct ParsedAidl {
    pub interfaces: Vec<crate::model::Interface>,
    pub parcelables: Vec<crate::model::Parcelable>,
    pub enums: Vec<crate::model::EnumDef>,
    pub unions: Vec<crate::model::Union>,
}

pub fn parse_aidl(source: &str) -> Result<ParsedAidl, Vec<Simple<char>>> {
    use crate::model::{
        Direction, EnumDef, Field, Flavor, Interface, Method, Parameter, Parcelable, Prim, TypeRef,
        Union,
    };

    let toks = lexer().parse(source)?;

    struct Cursor<'a> {
        toks: &'a [Token],
        pos: usize,
        package: String,
        // short name -> full fqn from `import` statements
        imports: std::collections::HashMap<String, String>,
    }
    impl<'a> Cursor<'a> {
        fn peek(&self) -> Option<&Token> {
            self.toks.get(self.pos)
        }
        fn advance(&mut self) -> Option<&Token> {
            let t = self.toks.get(self.pos);
            self.pos += 1;
            t
        }
        fn eat_kw(&mut self, k: &str) -> bool {
            if matches!(self.peek(), Some(Token::Keyword(kw)) if *kw == k) {
                self.pos += 1;
                true
            } else {
                false
            }
        }
        fn eat_punct(&mut self, c: char) -> bool {
            if matches!(self.peek(), Some(Token::Punct(p)) if *p == c) {
                self.pos += 1;
                true
            } else {
                false
            }
        }
        fn ident(&mut self) -> Option<String> {
            if let Some(Token::Ident(s)) = self.peek() {
                let v = s.clone();
                self.pos += 1;
                Some(v)
            } else {
                None
            }
        }
        fn fqn(&mut self) -> Option<String> {
            let mut parts = vec![self.ident()?];
            while self.eat_punct('.') {
                parts.push(self.ident()?);
            }
            Some(parts.join("."))
        }
        fn skip_annotations(&mut self) {
            while matches!(self.peek(), Some(Token::AtSymbol)) {
                self.pos += 1;
                let _ = self.ident();
                if self.eat_punct('(') {
                    let mut depth = 1;
                    while depth > 0 {
                        match self.advance() {
                            Some(Token::Punct('(')) => depth += 1,
                            Some(Token::Punct(')')) => depth -= 1,
                            None => break,
                            _ => {}
                        }
                    }
                }
            }
        }
        fn parse_type(&mut self) -> Option<TypeRef> {
            self.skip_annotations();
            let base = match self.peek()? {
                Token::Keyword(kw) => match *kw {
                    "boolean" => {
                        self.pos += 1;
                        TypeRef::Primitive(Prim::Bool)
                    }
                    "byte" => {
                        self.pos += 1;
                        TypeRef::Primitive(Prim::I8)
                    }
                    "char" => {
                        self.pos += 1;
                        TypeRef::Primitive(Prim::Char)
                    }
                    "short" => {
                        self.pos += 1;
                        TypeRef::Primitive(Prim::I16)
                    }
                    "int" => {
                        self.pos += 1;
                        TypeRef::Primitive(Prim::I32)
                    }
                    "long" => {
                        self.pos += 1;
                        TypeRef::Primitive(Prim::I64)
                    }
                    "float" => {
                        self.pos += 1;
                        TypeRef::Primitive(Prim::F32)
                    }
                    "double" => {
                        self.pos += 1;
                        TypeRef::Primitive(Prim::F64)
                    }
                    "void" => {
                        self.pos += 1;
                        return Some(TypeRef::UserDefined("void".into()));
                    }
                    "String" => {
                        self.pos += 1;
                        TypeRef::String
                    }
                    "IBinder" => {
                        self.pos += 1;
                        TypeRef::IBinder
                    }
                    "List" => {
                        self.pos += 1;
                        if !self.eat_punct('<') {
                            return Some(TypeRef::UserDefined("List".into()));
                        }
                        let inner = self.parse_type()?;
                        if !self.eat_punct('>') {
                            return None;
                        }
                        TypeRef::List(Box::new(inner))
                    }
                    "Map" => {
                        self.pos += 1;
                        if !self.eat_punct('<') {
                            // Bare `Map` (Java raw type). Treat as a user-defined name so
                            // method-resolution still gets a sensible type label.
                            return Some(TypeRef::UserDefined("Map".into()));
                        }
                        let k = self.parse_type()?;
                        if !self.eat_punct(',') {
                            return None;
                        }
                        let v = self.parse_type()?;
                        if !self.eat_punct('>') {
                            return None;
                        }
                        TypeRef::Map(Box::new(k), Box::new(v))
                    }
                    _ => return None,
                },
                Token::Ident(_) => {
                    let name = self.fqn()?;
                    // User-defined types may carry generic args, e.g. `Foo<Bar, Baz<X>>`.
                    // The recursive descent must consume the entire balanced group so
                    // the caller (return-type or param-type slot) sees the next *real*
                    // token afterwards. Method-resolution doesn't care about the
                    // type-args, so the entire shape is collapsed back into UserDefined.
                    if self.eat_punct('<') {
                        let mut depth = 1;
                        while depth > 0 {
                            match self.advance() {
                                Some(Token::Punct('<')) => depth += 1,
                                Some(Token::Punct('>')) => depth -= 1,
                                Some(_) => {}
                                None => return None,
                            }
                        }
                    }
                    // qualify short names via the import map so the decoder can
                    // look them up by fqn (e.g. `CoolingType` → `android.hardware.thermal.CoolingType`).
                    let qualified = qualify_type_name(&name, &self.package, &self.imports);
                    TypeRef::UserDefined(qualified)
                }
                _ => return None,
            };
            // Trailing `[]` or `[N]` (fixed-size array) for array.
            let mut t = base;
            while self.eat_punct('[') {
                // consume optional numeric size (e.g. `byte[16]`)
                if matches!(self.peek(), Some(Token::NumLit(_))) {
                    self.pos += 1;
                }
                if !self.eat_punct(']') {
                    return None;
                }
                t = TypeRef::Array(Box::new(t));
            }
            Some(t)
        }
        // eat an integer literal, handling: 42, -1, 0x1F, (-1), (-1) /* -1 */
        fn eat_int_literal(&mut self) -> Option<i64> {
            // parenthesized form: (-N) or (N)
            if self.eat_punct('(') {
                let neg = self.eat_punct('-');
                let val = match self.peek() {
                    Some(Token::NumLit(_)) => {
                        let v = self.eat_num_token()?;
                        if neg {
                            -v
                        } else {
                            v
                        }
                    }
                    _ => {
                        // unrecognized inside parens — skip to closing paren
                        let mut depth = 1;
                        while depth > 0 {
                            match self.advance() {
                                Some(Token::Punct('(')) => depth += 1,
                                Some(Token::Punct(')')) => {
                                    depth -= 1;
                                }
                                None => break,
                                _ => {}
                            }
                        }
                        return None;
                    }
                };
                let _ = self.eat_punct(')');
                return Some(val);
            }
            let neg = self.eat_punct('-');
            match self.eat_num_token() {
                Some(v) => Some(if neg { -v } else { v }),
                None if neg => None, // stray '-' without number
                None => None,
            }
        }
        // consume a NumLit token, also handling hex: `0` followed by ident `x<digits>`
        fn eat_num_token(&mut self) -> Option<i64> {
            if let Some(Token::NumLit(s)) = self.peek() {
                let s = s.clone();
                self.pos += 1;
                if s == "0" {
                    // check for hex suffix: ident starting with 'x' or 'X'
                    if let Some(Token::Ident(hex)) = self.peek() {
                        if hex.starts_with('x') || hex.starts_with('X') {
                            let digits = &hex[1..];
                            let val = i64::from_str_radix(digits, 16).ok();
                            self.pos += 1;
                            return val;
                        }
                    }
                }
                s.parse::<i64>().ok()
            } else {
                None
            }
        }
        // skip tokens to and including the next ';'
        fn skip_to_semicolon(&mut self) {
            while let Some(t) = self.advance() {
                if matches!(t, Token::Punct(';')) {
                    break;
                }
            }
        }
        // skip to the next ',' or '}' without consuming it
        fn skip_to_comma_or_brace(&mut self) {
            loop {
                match self.peek() {
                    Some(Token::Punct(',')) | Some(Token::Punct('}')) | None => break,
                    _ => {
                        self.advance();
                    }
                }
            }
        }
        // skip a balanced `{...}` body, or a `;` for forward decls
        fn skip_balanced_braces_or_semi(&mut self) {
            if self.eat_punct(';') {
                return;
            }
            if self.eat_punct('{') {
                let mut depth = 1;
                while depth > 0 {
                    match self.advance() {
                        Some(Token::Punct('{')) => depth += 1,
                        Some(Token::Punct('}')) => depth -= 1,
                        None => break,
                        _ => {}
                    }
                }
            }
        }
        // skip to ';', respecting nested `{}` and `()` depth
        fn skip_to_semi_balanced(&mut self) {
            let mut depth = 0i32;
            loop {
                match self.peek() {
                    Some(Token::Punct(';')) if depth == 0 => {
                        self.pos += 1;
                        break;
                    }
                    Some(Token::Punct('{')) | Some(Token::Punct('(')) => {
                        depth += 1;
                        self.pos += 1;
                    }
                    Some(Token::Punct('}')) | Some(Token::Punct(')')) => {
                        depth -= 1;
                        if depth < 0 {
                            break;
                        } // hit the enclosing brace — don't consume
                        self.pos += 1;
                    }
                    None => break,
                    _ => {
                        self.pos += 1;
                    }
                }
            }
        }
    }

    // qualify a user-defined type name using the import map and current package.
    // single-segment names: check imports first, then fall back to package-prefix.
    // dotted names: if the first segment matches an import key, splice in the full fqn;
    // otherwise assume already fully qualified.
    fn qualify_type_name(
        name: &str,
        package: &str,
        imports: &std::collections::HashMap<String, String>,
    ) -> String {
        if let Some(dot) = name.find('.') {
            let first = &name[..dot];
            let rest = &name[dot + 1..];
            if let Some(mapped) = imports.get(first) {
                return format!("{}.{}", mapped, rest);
            }
            // already dotted and first segment not an import key — assume fqn
            return name.to_string();
        }
        // single segment: check import map
        if let Some(mapped) = imports.get(name) {
            return mapped.clone();
        }
        // fall back to same-package qualification
        if package.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", package, name)
        }
    }

    fn join_fqn(package: &str, name: &str) -> String {
        if package.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", package, name)
        }
    }

    // try to consume @Backing(type="...") and return the Prim. leaves cursor
    // just past the annotation on success, unchanged on failure.
    fn try_eat_backing(cur: &mut Cursor<'_>) -> Option<Prim> {
        if !matches!(cur.peek(), Some(Token::AtSymbol)) {
            return None;
        }
        if !matches!(cur.toks.get(cur.pos + 1), Some(Token::Ident(s)) if s == "Backing") {
            return None;
        }
        cur.pos += 2; // eat @ Backing
        if !cur.eat_punct('(') {
            return Some(Prim::I32);
        }
        let _ = cur.ident(); // "type"
        let _ = cur.eat_punct('=');
        if !cur.eat_punct('"') {
            // malformed — skip to closing ')'
            let mut depth = 1;
            while depth > 0 {
                match cur.advance() {
                    Some(Token::Punct('(')) => depth += 1,
                    Some(Token::Punct(')')) => depth -= 1,
                    None => break,
                    _ => {}
                }
            }
            return Some(Prim::I32);
        }
        // collect ident/keyword tokens until closing '"' to reconstruct the type name
        let mut backing_name = String::new();
        loop {
            match cur.peek() {
                Some(Token::Punct('"')) => {
                    cur.pos += 1;
                    break;
                }
                Some(Token::Ident(s)) => {
                    backing_name.push_str(s);
                    cur.pos += 1;
                }
                Some(Token::Keyword(k)) => {
                    backing_name.push_str(k);
                    cur.pos += 1;
                }
                None => break,
                _ => {
                    cur.pos += 1;
                }
            }
        }
        let _ = cur.eat_punct(')');
        Some(match backing_name.as_str() {
            "byte" => Prim::I8,
            "long" => Prim::I64,
            _ => Prim::I32,
        })
    }

    // consume a run of annotations, returning the @Backing primitive if one was
    // present (default I32). other annotations (with optional balanced (...)) are
    // skipped. used before both top-level and nested type declarations.
    fn eat_annotations_capturing_backing(cur: &mut Cursor<'_>) -> Prim {
        let mut backing = Prim::I32;
        while matches!(cur.peek(), Some(Token::AtSymbol)) {
            if let Some(p) = try_eat_backing(cur) {
                backing = p;
                continue;
            }
            cur.pos += 1; // eat @
            let _ = cur.ident();
            if cur.eat_punct('(') {
                let mut depth = 1;
                while depth > 0 {
                    match cur.advance() {
                        Some(Token::Punct('(')) => depth += 1,
                        Some(Token::Punct(')')) => depth -= 1,
                        None => break,
                        _ => {}
                    }
                }
            }
        }
        backing
    }

    // parse an enum body: `Name { Const [= val]? , ... }` or `Name ;`
    // backing defaults to I32 if no @Backing was seen. returns None on structural
    // failures; for unevaluable const-exprs returns an enum with empty consts so
    // the decoder can fall back to Raw.
    fn parse_enum_body(cur: &mut Cursor<'_>, package: &str, backing: Prim) -> Option<EnumDef> {
        let name = cur.ident()?;
        let fqn = join_fqn(package, &name);
        if cur.eat_punct(';') {
            return Some(EnumDef {
                fqn,
                backing,
                consts: vec![],
            });
        }
        if !cur.eat_punct('{') {
            cur.skip_balanced_braces_or_semi();
            return None;
        }
        let mut consts: Vec<(String, i64)> = Vec::new();
        let mut next: i64 = 0;
        let mut resolvable = true;
        loop {
            cur.skip_annotations();
            if cur.eat_punct('}') {
                break;
            }
            // allow trailing semicolon inside enum body (rare but present in corpus)
            if cur.eat_punct(';') {
                break;
            }
            let cname = match cur.ident() {
                Some(n) => n,
                None => {
                    cur.advance();
                    continue;
                }
            };
            let val = if cur.eat_punct('=') {
                match cur.eat_int_literal() {
                    Some(v) => {
                        next = v.wrapping_add(1);
                        v
                    }
                    None => {
                        // unevaluable const-expr — skip to separator, mark unresolvable
                        resolvable = false;
                        cur.skip_to_comma_or_brace();
                        let v = next;
                        next = next.wrapping_add(1);
                        v
                    }
                }
            } else {
                let v = next;
                next = next.wrapping_add(1);
                v
            };
            consts.push((cname, val));
            let _ = cur.eat_punct(',');
        }
        if !resolvable {
            // unresolvable const-expr → return empty consts so decoder falls back to Raw
            return Some(EnumDef {
                fqn,
                backing,
                consts: vec![],
            });
        }
        Some(EnumDef {
            fqn,
            backing,
            consts,
        })
    }

    // parse the body of a parcelable or union, collecting fields.
    // the keyword was already consumed by the caller; this starts at the name.
    // `fqn` is the outer package + name (caller builds it before calling).
    // nested enum declarations are collected into `out_enums`.
    fn parse_fields(cur: &mut Cursor<'_>, fqn: &str, out_enums: &mut Vec<EnumDef>) -> Vec<Field> {
        // eat optional generic params on the struct itself (rare)
        if cur.eat_punct('<') {
            let mut depth = 1;
            while depth > 0 {
                match cur.advance() {
                    Some(Token::Punct('<')) => depth += 1,
                    Some(Token::Punct('>')) => depth -= 1,
                    None => break,
                    _ => {}
                }
            }
        }
        // `extends FqName` before the body
        if cur.eat_kw("extends") {
            let _ = cur.fqn();
        }
        // skip forward-decl attributes (cpp_header "...", ndk_header "...", etc.)
        // until we see '{' or ';'
        loop {
            match cur.peek() {
                Some(Token::Punct(';')) => {
                    cur.pos += 1;
                    return vec![];
                }
                Some(Token::Punct('{')) => break,
                None => return vec![],
                _ => {
                    cur.pos += 1;
                }
            }
        }
        if !cur.eat_punct('{') {
            return vec![];
        }
        let mut fields: Vec<Field> = Vec::new();
        // nested types are qualified by the enclosing type's full fqn: an enum `Kind`
        // in parcelable `a.P` is `a.P.Kind`.
        let nested_pkg = fqn;
        loop {
            let nested_backing = eat_annotations_capturing_backing(cur);
            if cur.eat_punct('}') {
                break;
            }
            if cur.eat_kw("const") {
                cur.skip_to_semicolon();
                continue;
            }
            // nested enum: parse and collect; pass captured @Backing if any
            if cur.eat_kw("enum") {
                if let Some(nested) = parse_enum_body(cur, nested_pkg, nested_backing) {
                    out_enums.push(nested);
                }
                continue;
            }
            // nested parcelable/union/interface: skip body (deeper nesting not modelled)
            if cur.eat_kw("parcelable") || cur.eat_kw("union") || cur.eat_kw("interface") {
                let _ = cur.ident();
                cur.skip_balanced_braces_or_semi();
                continue;
            }
            // a field: <type> <name> [= default]? ;
            let ty = match cur.parse_type() {
                Some(t) => t,
                None => {
                    cur.advance();
                    continue;
                } // recover
            };
            let fname = match cur.ident() {
                Some(n) => n,
                None => {
                    cur.skip_to_semicolon();
                    continue;
                }
            };
            if cur.eat_punct('=') {
                cur.skip_to_semi_balanced();
            } else {
                let _ = cur.eat_punct(';');
            }
            fields.push(Field { name: fname, ty });
        }
        fields
    }

    let mut cur = Cursor {
        toks: &toks,
        pos: 0,
        package: String::new(),
        imports: std::collections::HashMap::new(),
    };

    if cur.eat_kw("package") {
        cur.package = cur
            .fqn()
            .ok_or_else(|| vec![Simple::custom(0..0, "expected package name")])?;
        if !cur.eat_punct(';') {
            return Err(vec![Simple::custom(0..0, "expected ';' after package")]);
        }
    }
    while cur.eat_kw("import") {
        if let Some(fqn) = cur.fqn() {
            // last segment is the short name used in the file's type refs
            if let Some(short) = fqn.rsplit('.').next() {
                cur.imports.insert(short.to_string(), fqn);
            }
        }
        let _ = cur.eat_punct(';');
    }

    let mut out = ParsedAidl {
        interfaces: Vec::new(),
        parcelables: Vec::new(),
        enums: Vec::new(),
        unions: Vec::new(),
    };

    while cur.peek().is_some() {
        let backing = eat_annotations_capturing_backing(&mut cur);

        if cur.eat_kw("interface") {
            let name = cur
                .ident()
                .ok_or_else(|| vec![Simple::custom(0..0, "expected interface name")])?;
            if !cur.eat_punct('{') {
                return Err(vec![Simple::custom(
                    0..0,
                    "expected '{' after interface name",
                )]);
            }
            let mut methods: Vec<Method> = Vec::new();
            loop {
                cur.skip_annotations();
                match cur.peek() {
                    Some(Token::Punct('}')) => {
                        cur.pos += 1;
                        break;
                    }
                    Some(Token::Keyword("const")) => {
                        while let Some(t) = cur.advance() {
                            if matches!(t, Token::Punct(';')) {
                                break;
                            }
                        }
                        continue;
                    }
                    Some(Token::Keyword(k))
                        if *k == "parcelable"
                            || *k == "union"
                            || *k == "enum"
                            || *k == "interface" =>
                    {
                        // Nested parcelable / union / enum / interface declarations
                        // inside an interface body. AIDL allows them but they
                        // don't contribute to transaction codes — skip the
                        // body (balanced `{...}` or trailing `;`).
                        cur.pos += 1;
                        let _ = cur.ident();
                        if cur.eat_punct(';') {
                            continue;
                        }
                        if cur.eat_punct('{') {
                            let mut depth = 1;
                            while depth > 0 {
                                match cur.advance() {
                                    Some(Token::Punct('{')) => depth += 1,
                                    Some(Token::Punct('}')) => depth -= 1,
                                    None => break,
                                    _ => {}
                                }
                            }
                        }
                        continue;
                    }
                    _ => {
                        let oneway = cur.eat_kw("oneway");
                        // `oneway interface IFoo { ... }` — nested interface after oneway.
                        // Doesn't contribute transaction codes; skip its body.
                        if oneway
                            && matches!(cur.peek(), Some(Token::Keyword(k)) if *k == "interface")
                        {
                            cur.pos += 1;
                            let _ = cur.ident();
                            if cur.eat_punct(';') {
                                continue;
                            }
                            if cur.eat_punct('{') {
                                let mut depth = 1;
                                while depth > 0 {
                                    match cur.advance() {
                                        Some(Token::Punct('{')) => depth += 1,
                                        Some(Token::Punct('}')) => depth -= 1,
                                        None => break,
                                        _ => {}
                                    }
                                }
                            }
                            continue;
                        }
                        let return_type = cur.parse_type();
                        let method_name = cur
                            .ident()
                            .ok_or_else(|| vec![Simple::custom(0..0, "expected method name")])?;
                        if !cur.eat_punct('(') {
                            return Err(vec![Simple::custom(0..0, "expected '(' in method")]);
                        }
                        let mut params = Vec::new();
                        while !matches!(cur.peek(), Some(Token::Punct(')'))) {
                            cur.skip_annotations();
                            let direction = if cur.eat_kw("in") {
                                Direction::In
                            } else if cur.eat_kw("out") {
                                Direction::Out
                            } else if cur.eat_kw("inout") {
                                Direction::InOut
                            } else {
                                Direction::In
                            };
                            let ty = cur
                                .parse_type()
                                .ok_or_else(|| vec![Simple::custom(0..0, "expected param type")])?;
                            let pname = cur.ident().unwrap_or_default();
                            params.push(Parameter {
                                name: pname,
                                ty,
                                direction,
                            });
                            if !cur.eat_punct(',') {
                                break;
                            }
                        }
                        if !cur.eat_punct(')') {
                            return Err(vec![Simple::custom(0..0, "expected ')'")]);
                        }
                        // stable AIDL pins a transaction code: `void foo() = 17;`.
                        let mut code: Option<u32> = None;
                        if cur.eat_punct('=') {
                            if let Some(Token::NumLit(s)) = cur.peek() {
                                if let Ok(n) = s.parse::<u32>() {
                                    code = Some(n);
                                }
                                cur.pos += 1;
                            }
                            while let Some(t) = cur.advance() {
                                if matches!(t, Token::Punct(';')) {
                                    break;
                                }
                            }
                        } else {
                            let _ = cur.eat_punct(';');
                        }
                        methods.push(Method {
                            name: method_name,
                            params,
                            return_type,
                            oneway,
                            code,
                        });
                    }
                }
            }
            let fqn = join_fqn(&cur.package, &name);
            out.interfaces.push(Interface {
                fqn,
                flavor: Flavor::Aidl,
                base_code: 1,
                methods,
                extends: None,
            });
        } else if cur.eat_kw("enum") {
            let pkg = cur.package.clone();
            if let Some(e) = parse_enum_body(&mut cur, &pkg, backing) {
                out.enums.push(e);
            }
        } else if cur.eat_kw("parcelable") {
            // name may be dotted (e.g. `DropBoxManager.Entry` in cpp_header decls)
            let name = match cur.ident() {
                Some(n) => n,
                None => {
                    cur.advance();
                    continue;
                }
            };
            // consume optional dotted suffix on the struct name itself
            let mut full_name = name;
            while cur.eat_punct('.') {
                if let Some(part) = cur.ident() {
                    full_name.push('.');
                    full_name.push_str(&part);
                }
            }
            let fqn = join_fqn(&cur.package, &full_name);
            let fields = parse_fields(&mut cur, &fqn, &mut out.enums);
            out.parcelables.push(Parcelable { fqn, fields });
        } else if cur.eat_kw("union") {
            let name = match cur.ident() {
                Some(n) => n,
                None => {
                    cur.advance();
                    continue;
                }
            };
            let fqn = join_fqn(&cur.package, &name);
            let fields = parse_fields(&mut cur, &fqn, &mut out.enums);
            out.unions.push(Union { fqn, fields });
        } else {
            // unknown top-level token — skip to recover
            cur.advance();
        }
    }

    Ok(out)
}

fn lexer() -> impl Parser<char, Vec<Token>, Error = Simple<char>> {
    let line_comment = just("//").then(take_until(just('\n'))).ignored();
    let block_comment = just("/*").then(take_until(just("*/"))).ignored();
    let comment = line_comment.or(block_comment);
    let ws = filter(|c: &char| c.is_whitespace()).ignored();
    let pad = ws.or(comment).repeated();

    let ident_or_kw = text::ident().map(|s: String| match s.as_str() {
        "interface" | "parcelable" | "union" | "enum" | "package" | "import" | "oneway" | "in"
        | "out" | "inout" | "const" | "extends" | "void" | "boolean" | "byte" | "char"
        | "short" | "int" | "long" | "float" | "double" | "String" | "IBinder" | "List" | "Map" => {
            Token::Keyword(Box::leak(s.into_boxed_str()))
        }
        _ => Token::Ident(s),
    });

    let punct = one_of("{}()[]<>;,.=").map(Token::Punct);
    let at = just('@').map(|_| Token::AtSymbol);

    // Numeric literals (integers)
    let number = text::digits(10).map(|s: String| Token::NumLit(s));

    // Catch-all for any other non-whitespace byte so unknown punctuation
    // (`|`, `<<`, `+`, `-`, etc. in const-expression bodies) doesn't make
    // chumsky's `repeated()` bail mid-file. The const-skip path discards
    // every token up to `;` so emitting these as opaque Punct tokens is
    // safe — the rest of the parser never inspects them.
    let other = filter(|c: &char| !c.is_whitespace()).map(Token::Punct);

    let token = ident_or_kw.or(number).or(at).or(punct).or(other);
    token.padded_by(pad).repeated()
}

// exposed only for unit tests
#[cfg(test)]
fn lex(source: &str) -> Vec<Token> {
    lexer().parse(source).expect("lexer failure")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Punct(char),
    Keyword(&'static str),
    StrLit(String),
    NumLit(String),
    AtSymbol,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Prim, TypeRef};

    #[test]
    fn lexer_skips_line_comments() {
        let src = "// hello\ninterface IFoo {}";
        let toks = lex(src);
        assert!(matches!(toks.first(), Some(Token::Keyword("interface"))));
    }

    #[test]
    fn lexer_skips_block_comments() {
        let src = "/* hello\nworld */ interface IFoo {}";
        let toks = lex(src);
        assert!(matches!(toks.first(), Some(Token::Keyword("interface"))));
    }

    #[test]
    fn lexer_emits_idents_and_keywords() {
        let toks = lex("interface IFoo extends IBar");
        assert_eq!(
            toks,
            vec![
                Token::Keyword("interface"),
                Token::Ident("IFoo".into()),
                Token::Keyword("extends"),
                Token::Ident("IBar".into()),
            ]
        );
    }

    #[test]
    fn parses_package_only() {
        let result = parse_aidl("package android.os;").unwrap();
        assert!(result.interfaces.is_empty()); // package alone declares nothing
    }

    #[test]
    fn parses_primitive_type_in_method() {
        let src = "package a; interface IFoo { int answer(); }";
        let parsed = parse_aidl(src).unwrap();
        assert_eq!(parsed.interfaces.len(), 1);
        let m = &parsed.interfaces[0].methods[0];
        assert_eq!(m.name, "answer");
        assert_eq!(m.return_type, Some(TypeRef::Primitive(Prim::I32)));
    }

    #[test]
    fn parses_array_and_list_types() {
        let src = "package a; interface IFoo { void f(in int[] xs, in List<String> ys); }";
        let parsed = parse_aidl(src).unwrap();
        let p0 = &parsed.interfaces[0].methods[0].params[0];
        assert_eq!(
            p0.ty,
            TypeRef::Array(Box::new(TypeRef::Primitive(Prim::I32)))
        );
        let p1 = &parsed.interfaces[0].methods[0].params[1];
        assert_eq!(p1.ty, TypeRef::List(Box::new(TypeRef::String)));
    }

    #[test]
    fn parses_oneway_method() {
        let src = "package a; interface IFoo { oneway void fire(); }";
        let i = parse_aidl(src).unwrap();
        assert!(i.interfaces[0].methods[0].oneway);
    }

    #[test]
    fn parses_method_with_annotation() {
        let src = r#"
            package a;
            interface IFoo {
                @nullable String maybeName();
            }
        "#;
        let i = parse_aidl(src).unwrap();
        assert_eq!(i.interfaces[0].methods[0].name, "maybeName");
    }

    #[test]
    fn ignores_const_declarations_for_codes() {
        let src = r#"
            package a;
            interface IFoo {
                const int FLAG_X = 1;
                void first();
                const int FLAG_Y = 2;
                void second();
            }
        "#;
        let i = parse_aidl(src).unwrap();
        assert_eq!(i.interfaces[0].methods.len(), 2);
        assert_eq!(i.interfaces[0].lookup(1).unwrap().name, "first");
        assert_eq!(i.interfaces[0].lookup(2).unwrap().name, "second");
    }

    #[test]
    fn skips_parcelable_and_enum_at_top_level() {
        let src = r#"
            package a;
            parcelable Bar { int x; }
            interface IFoo { void hi(); }
            enum E { A, B; }
        "#;
        let i = parse_aidl(src).unwrap();
        assert_eq!(i.interfaces.len(), 1);
        assert_eq!(i.interfaces[0].fqn, "a.IFoo");
    }

    #[test]
    fn parses_generic_user_defined_return_type() {
        let src = "package a; interface I { \
                   ParceledListSlice<TaskInfo> list(); \
                   }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 1);
        assert_eq!(r.interfaces[0].methods[0].name, "list");
    }

    #[test]
    fn parses_generic_user_defined_param_type() {
        let src = "package a; interface I { \
                   void name(in AndroidFuture<String> result); \
                   }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 1);
        assert_eq!(r.interfaces[0].methods[0].name, "name");
        assert_eq!(r.interfaces[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_nested_generics() {
        let src = "package a; interface I { \
                   void m(in Foo<Bar<Baz>> x); \
                   }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_bare_map_param() {
        let src = "package a; interface I { void onChange(in Map data); }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods[0].name, "onChange");
        assert_eq!(r.interfaces[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_typed_map_param_still_works() {
        // Regression — typed form must keep working.
        let src = "package a; interface I { void m(in Map<String, IBinder> x); }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_method_with_explicit_transaction_code() {
        let src = "package a; interface I { \
                   void first() = 1; \
                   void second() = 17; \
                   }";
        let r = parse_aidl(src).unwrap();
        let names: Vec<_> = r.interfaces[0]
            .methods
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert_eq!(names, vec!["first", "second"]);
        assert_eq!(r.interfaces[0].methods[0].code, Some(1));
        assert_eq!(r.interfaces[0].methods[1].code, Some(17));
        assert_eq!(
            r.interfaces[0].lookup(17).map(|m| m.name.as_str()),
            Some("second")
        );
        assert_eq!(
            r.interfaces[0].lookup(1).map(|m| m.name.as_str()),
            Some("first")
        );
        assert!(r.interfaces[0].lookup(2).is_none());
    }

    #[test]
    fn skips_nested_union_inside_interface() {
        // union nested in an interface body (e.g. hardware/interfaces bufferpool2)
        let src = r#"
            package a;
            interface IFoo {
                Foo[] fetch(in Foo.Info[] infos);
                void sync();
                parcelable Info { long id; }
                union Result { Foo buf; int err; }
            }
        "#;
        let r = parse_aidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 2);
        assert_eq!(r.interfaces[0].methods[0].name, "fetch");
        assert_eq!(r.interfaces[0].methods[1].name, "sync");
    }

    #[test]
    fn parses_fixed_size_array_return_type() {
        // `byte[16]` return type (used in e.g. IContextHubCallback.getUuid)
        let src = "package a; interface I { byte[16] getUuid(); String getName(); }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 2);
        assert_eq!(r.interfaces[0].methods[0].name, "getUuid");
        assert_eq!(r.interfaces[0].methods[1].name, "getName");
    }

    #[test]
    fn skips_oneway_nested_interface() {
        // `oneway interface ICallback { ... }` nested inside an outer interface
        let src = r#"
            package a;
            interface ISoundDose {
                void setRs2(float v);
                void registerCallback(in IHalSoundDoseCallback cb);
                @VintfStability
                oneway interface IHalSoundDoseCallback {
                    void onWarning(float v);
                    parcelable MelRecord { float[] vals; long ts; }
                    void onMel(in MelRecord r);
                }
            }
        "#;
        let r = parse_aidl(src).unwrap();
        assert_eq!(r.interfaces[0].methods.len(), 2);
        assert_eq!(r.interfaces[0].methods[0].name, "setRs2");
        assert_eq!(r.interfaces[0].methods[1].name, "registerCallback");
    }

    #[test]
    fn skips_top_level_union() {
        // top-level union declaration — returns union fields, no interface
        let src = r#"
            package a;
            union AudioChannelLayout {
                int none = 0;
                int layoutMask;
            }
        "#;
        let r = parse_aidl(src).unwrap();
        assert!(r.interfaces.is_empty());
    }

    // --- new tests for body capture ---

    #[test]
    fn parses_enum_explicit_and_autoincrement() {
        let src = r#"
            package a.b;
            @Backing(type="byte")
            enum E { A = 1, B, C = 10, D }
        "#;
        let p = parse_aidl(src).unwrap();
        let e = p.enums.iter().find(|e| e.fqn == "a.b.E").unwrap();
        assert_eq!(e.backing, Prim::I8);
        assert_eq!(
            e.consts,
            vec![
                ("A".into(), 1),
                ("B".into(), 2),
                ("C".into(), 10),
                ("D".into(), 11),
            ]
        );
    }

    #[test]
    fn parses_enum_default_backing_starts_at_zero() {
        let p = parse_aidl("package a; enum K { X, Y, Z }").unwrap();
        let e = p.enums.iter().find(|e| e.fqn == "a.K").unwrap();
        assert_eq!(e.backing, Prim::I32);
        assert_eq!(
            e.consts,
            vec![("X".into(), 0), ("Y".into(), 1), ("Z".into(), 2)]
        );
    }

    #[test]
    fn parses_parcelable_fields() {
        let src = "package a; parcelable P { int id; String name; int[] tags; }";
        let p = parse_aidl(src).unwrap();
        let pc = p.parcelables.iter().find(|p| p.fqn == "a.P").unwrap();
        let names: Vec<&str> = pc.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["id", "name", "tags"]);
        assert!(matches!(pc.fields[2].ty, TypeRef::Array(_)));
    }

    #[test]
    fn parses_union_fields() {
        let p = parse_aidl("package a; union U { int n; String s; }").unwrap();
        let u = p.unions.iter().find(|u| u.fqn == "a.U").unwrap();
        assert_eq!(u.fields.len(), 2);
    }

    #[test]
    fn nested_enum_captures_backing() {
        let src = r#"
            package a;
            parcelable P {
                int id;
                @Backing(type="byte")
                enum Kind { A, B }
            }
        "#;
        let p = parse_aidl(src).unwrap();
        // nested types are parent-qualified: enum `Kind` inside parcelable `a.P` is `a.P.Kind`
        let e = p
            .enums
            .iter()
            .find(|e| e.fqn == "a.P.Kind")
            .expect("nested enum collected");
        assert_eq!(e.backing, crate::model::Prim::I8);
        assert_eq!(e.consts, vec![("A".into(), 0), ("B".into(), 1)]);
    }

    #[test]
    fn interface_still_parses_alongside_bodies() {
        let src =
            "package a; interface IFoo { void go(int x); } enum E { A } parcelable P { int y; }";
        let p = parse_aidl(src).unwrap();
        assert_eq!(p.interfaces.len(), 1);
        assert_eq!(p.interfaces[0].fqn, "a.IFoo");
        assert_eq!(p.enums.len(), 1);
        assert_eq!(p.parcelables.len(), 1);
    }
}
