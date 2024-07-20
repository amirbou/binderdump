use std::fmt::Display;

use quote::ToTokens;
use syn::meta::ParseNestedMeta;
use syn::parse::{Error, Result};
use syn::Ident;

pub fn error_spanned_by<A: ToTokens, T: Display>(obj: A, msg: T) -> Error {
    Error::new_spanned(obj.into_token_stream(), msg)
}

pub fn get_string_literal(attr_name: &str, meta: &ParseNestedMeta) -> Result<syn::LitStr> {
    let expr: syn::Expr = meta.value()?.parse()?;
    let mut value = &expr;
    while let syn::Expr::Group(e) = value {
        value = &e.expr;
    }
    if let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(lit),
        ..
    }) = value
    {
        let suffix = lit.suffix();
        if !suffix.is_empty() {
            return Err(error_spanned_by(
                lit,
                format!("unexpected suffix `{}` on string literal", suffix),
            ));
        }
        return Ok(lit.clone());
    }
    return Err(error_spanned_by(
        expr,
        format!(
            "expected epan {} attribute to be a string `{}` = \"...\"",
            attr_name, attr_name
        ),
    ));
}

pub fn get_path_ident(attr_name: &str, meta: &ParseNestedMeta) -> Result<Ident> {
    let expr: syn::Expr = meta.value()?.parse()?;
    let mut value = &expr;
    while let syn::Expr::Group(e) = value {
        value = &e.expr;
    }
    if let syn::Expr::Path(path) = value {
        if !path.attrs.is_empty() || path.qself.is_some() {
            return Err(error_spanned_by(
                value,
                format!(
                    "expected epan {} attribute to be a plain identifier `{}` = ...",
                    attr_name, attr_name
                ),
            ));
        }
        let path = &path.path;
        if path.leading_colon.is_some() {
            return Err(error_spanned_by(
                path,
                format!(
                    "expected epan {} attribute to contain no leading colon (::)",
                    attr_name
                ),
            ));
        }
        if path.segments.len() != 1 {
            return Err(error_spanned_by(
                path,
                format!(
                    "expected epan {} attribute to contain only exactly segment (no colons ::)",
                    attr_name
                ),
            ));
        }
        let segment = path.segments.first().unwrap();
        if !segment.arguments.is_none() {
            return Err(error_spanned_by(
                path,
                format!("expected epan {} attribute to have no arguemtns", attr_name),
            ));
        }
        return Ok(segment.ident.clone());
    }

    Err(error_spanned_by(
        expr,
        format!(
            "expected epan {} attribute to be an identifier `{}` = ...",
            attr_name, attr_name
        ),
    ))
}
