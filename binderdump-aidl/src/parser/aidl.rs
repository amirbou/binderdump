use chumsky::prelude::*;

pub fn parse_aidl(source: &str) -> Result<Vec<crate::model::Interface>, Vec<Simple<char>>> {
    todo!()
}

fn lexer() -> impl Parser<char, Vec<Token>, Error = Simple<char>> {
    let line_comment = just("//").then(take_until(just('\n'))).ignored();
    let block_comment = just("/*").then(take_until(just("*/"))).ignored();
    let comment = line_comment.or(block_comment);
    let ws = filter(|c: &char| c.is_whitespace()).ignored();
    let pad = ws.or(comment).repeated();

    let ident_or_kw = text::ident().map(|s: String| match s.as_str() {
        "interface" | "parcelable" | "enum" | "package" | "import" | "oneway" | "in" | "out"
        | "inout" | "const" | "extends" | "void" | "boolean" | "byte" | "char" | "short"
        | "int" | "long" | "float" | "double" | "String" | "IBinder" | "List" | "Map" => {
            Token::Keyword(Box::leak(s.into_boxed_str()))
        }
        _ => Token::Ident(s),
    });

    let punct = one_of("{}()[]<>;,.=").map(Token::Punct);
    let at = just('@').map(|_| Token::AtSymbol);

    let token = ident_or_kw.or(at).or(punct);
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
}
