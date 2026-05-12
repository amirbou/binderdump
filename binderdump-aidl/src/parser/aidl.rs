// AIDL parser: chumsky-driven lexer feeding a hand-rolled recursive-descent
// over a token cursor. Recovers enough structure for code resolution
// (interfaces + methods in declaration order) and skips parcelable/enum
// bodies + const decls since those don't affect transaction codes.

use chumsky::prelude::*;

pub fn parse_aidl(source: &str) -> Result<Vec<crate::model::Interface>, Vec<Simple<char>>> {
    use crate::model::{Direction, Flavor, Interface, Method, Parameter, Prim, TypeRef};

    let toks = lexer().parse(source)?;

    // Package + zero-or-more declarations. Implement as a small hand-rolled
    // recursive-descent over the token vec; chumsky on tokens works too,
    // but a simple `Cursor` keeps this readable for the v1 scope.

    struct Cursor<'a> {
        toks: &'a [Token],
        pos: usize,
        package: String,
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
                    TypeRef::UserDefined(name)
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
    }

    let mut cur = Cursor {
        toks: &toks,
        pos: 0,
        package: String::new(),
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
        let _ = cur.fqn();
        let _ = cur.eat_punct(';');
    }

    let mut out: Vec<Interface> = Vec::new();
    while cur.peek().is_some() {
        cur.skip_annotations();
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
                        // skip const declaration up to ';'
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
                            cur.pos += 1; // eat 'interface'
                            let _ = cur.ident(); // eat name
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
                        // The AIDL compiler emits N as the actual code, so capture it.
                        let mut code: Option<u32> = None;
                        if cur.eat_punct('=') {
                            if let Some(Token::NumLit(s)) = cur.peek() {
                                if let Ok(n) = s.parse::<u32>() {
                                    code = Some(n);
                                }
                                cur.pos += 1;
                            }
                            // tolerate stray tokens up to `;` (shouldn't happen but be safe)
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
            let fqn = if cur.package.is_empty() {
                name.clone()
            } else {
                format!("{}.{}", cur.package, name)
            };
            out.push(Interface {
                fqn,
                flavor: Flavor::Aidl,
                base_code: 1,
                methods,
                extends: None,
            });
        } else if cur.eat_kw("parcelable") || cur.eat_kw("union") || cur.eat_kw("enum") {
            // Skip parcelable/union/enum body — we don't need their fields for code resolution.
            // Skip any `;` or balanced `{...}`.
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
        } else {
            // Unknown top-level token — skip to recover.
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
        assert!(result.is_empty()); // package alone declares nothing
    }

    #[test]
    fn parses_primitive_type_in_method() {
        let src = "package a; interface IFoo { int answer(); }";
        let interfaces = parse_aidl(src).unwrap();
        assert_eq!(interfaces.len(), 1);
        let m = &interfaces[0].methods[0];
        assert_eq!(m.name, "answer");
        assert_eq!(
            m.return_type,
            Some(crate::model::TypeRef::Primitive(crate::model::Prim::I32))
        );
    }

    #[test]
    fn parses_array_and_list_types() {
        let src = "package a; interface IFoo { void f(in int[] xs, in List<String> ys); }";
        let interfaces = parse_aidl(src).unwrap();
        let p0 = &interfaces[0].methods[0].params[0];
        assert_eq!(
            p0.ty,
            crate::model::TypeRef::Array(Box::new(crate::model::TypeRef::Primitive(
                crate::model::Prim::I32
            )))
        );
        let p1 = &interfaces[0].methods[0].params[1];
        assert_eq!(
            p1.ty,
            crate::model::TypeRef::List(Box::new(crate::model::TypeRef::String))
        );
    }

    #[test]
    fn parses_oneway_method() {
        let src = "package a; interface IFoo { oneway void fire(); }";
        let i = parse_aidl(src).unwrap();
        assert!(i[0].methods[0].oneway);
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
        assert_eq!(i[0].methods[0].name, "maybeName");
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
        assert_eq!(i[0].methods.len(), 2);
        assert_eq!(i[0].lookup(1).unwrap().name, "first");
        assert_eq!(i[0].lookup(2).unwrap().name, "second");
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
        assert_eq!(i.len(), 1);
        assert_eq!(i[0].fqn, "a.IFoo");
    }

    #[test]
    fn parses_generic_user_defined_return_type() {
        let src = "package a; interface I { \
                   ParceledListSlice<TaskInfo> list(); \
                   }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r[0].methods.len(), 1);
        assert_eq!(r[0].methods[0].name, "list");
    }

    #[test]
    fn parses_generic_user_defined_param_type() {
        let src = "package a; interface I { \
                   void name(in AndroidFuture<String> result); \
                   }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r[0].methods.len(), 1);
        assert_eq!(r[0].methods[0].name, "name");
        assert_eq!(r[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_nested_generics() {
        let src = "package a; interface I { \
                   void m(in Foo<Bar<Baz>> x); \
                   }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_bare_map_param() {
        let src = "package a; interface I { void onChange(in Map data); }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r[0].methods[0].name, "onChange");
        assert_eq!(r[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_typed_map_param_still_works() {
        // Regression — typed form must keep working.
        let src = "package a; interface I { void m(in Map<String, IBinder> x); }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r[0].methods[0].params.len(), 1);
    }

    #[test]
    fn parses_method_with_explicit_transaction_code() {
        let src = "package a; interface I { \
                   void first() = 1; \
                   void second() = 17; \
                   }";
        let r = parse_aidl(src).unwrap();
        let names: Vec<_> = r[0].methods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["first", "second"]);
        assert_eq!(r[0].methods[0].code, Some(1));
        assert_eq!(r[0].methods[1].code, Some(17));
        // lookup() must honor the explicit code rather than the declaration index.
        assert_eq!(r[0].lookup(17).map(|m| m.name.as_str()), Some("second"));
        assert_eq!(r[0].lookup(1).map(|m| m.name.as_str()), Some("first"));
        // index 2 (base_code + idx for "second") must NOT resolve via fallback.
        assert!(r[0].lookup(2).is_none());
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
        assert_eq!(r[0].methods.len(), 2);
        assert_eq!(r[0].methods[0].name, "fetch");
        assert_eq!(r[0].methods[1].name, "sync");
    }

    #[test]
    fn parses_fixed_size_array_return_type() {
        // `byte[16]` return type (used in e.g. IContextHubCallback.getUuid)
        let src = "package a; interface I { byte[16] getUuid(); String getName(); }";
        let r = parse_aidl(src).unwrap();
        assert_eq!(r[0].methods.len(), 2);
        assert_eq!(r[0].methods[0].name, "getUuid");
        assert_eq!(r[0].methods[1].name, "getName");
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
        assert_eq!(r[0].methods.len(), 2);
        assert_eq!(r[0].methods[0].name, "setRs2");
        assert_eq!(r[0].methods[1].name, "registerCallback");
    }

    #[test]
    fn skips_top_level_union() {
        // top-level union declaration — no interface, returns empty vec
        let src = r#"
            package a;
            union AudioChannelLayout {
                int none = 0;
                int layoutMask;
            }
        "#;
        let r = parse_aidl(src).unwrap();
        assert!(r.is_empty());
    }
}
