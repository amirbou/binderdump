use std::fmt::{Debug, Display};

use binderdump_trait::FtEnum;
use proc_macro2::{Span, TokenStream};
use quote::ToTokens;
use syn::meta::ParseNestedMeta;
use syn::parse::{Error, Parse, ParseStream, Result};
use syn::{parenthesized, token, Data, DeriveInput, Fields, Ident, Meta};

pub enum ContainerAttr {
    Name(syn::LitStr),
}

impl Debug for ContainerAttr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name(arg0) => f.debug_tuple("Name").field(&arg0.value()).finish(),
        }
    }
}

#[derive(Default)]
pub struct FieldAttrs {
    pub name: Option<syn::LitStr>,
    pub abbrev: Option<syn::LitStr>,
    pub ftype: Option<Ident>,
    pub display: Option<Ident>,
    pub skip: bool,
}

impl Debug for FieldAttrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldAttr")
            .field("name", &self.name.as_ref().map(|n| n.value()))
            .field("abbrev", &self.abbrev.as_ref().map(|n| n.value()))
            .field("ftype", &self.ftype)
            .field("display", &self.display)
            .field("skip", &self.skip)
            .finish()
    }
}

#[derive(Debug)]
pub struct ParsedField {
    pub name: Ident,
    pub attrs: FieldAttrs,
    pub ty: syn::Type,
}

impl ParsedField {
    // fn new(name: Ident, attrs: FieldAttrs, ty: syn::Type) -> Result<Self> {
    //     match &attrs.ftype {
    //         Some(ftype) => todo!(),
    //         None => todo!(),
    //     }
    //     todo!()
    // }

    // fn guess_ftype(name: &Ident, ty: &syn::Type) -> Result<FtEnum> {
    //     match ty {
    //         syn::Type::Array(arr) => {
    //             let inner_ftype = Self::guess_ftype(name, &*arr.elem)?;
    //             match inner_ftype {
    //                 FtEnum::U8 | FtEnum::I8 => Ok(FtEnum::Bytes),
    //                 _ => Ok(inner_ftype),
    //             }
    //         }
    //         syn::Type::Paren(paren) => Self::guess_ftype(name, &*paren.elem),
    //         syn::Type::Path(path) => Self::path_to_ftype(name, path),
    //         syn::Type::Reference(_) => Err(error_spanned_by(
    //             name,
    //             "references are not supported by EpanProtocol",
    //         )),
    //         // syn::Type::Slice(_) => todo!(),
    //         _ => Err(error_spanned_by(name, "unsupported type for EpanProtocol")),
    //     }
    // }
}

impl TryFrom<&syn::Field> for ParsedField {
    type Error = Error;

    fn try_from(field: &syn::Field) -> std::result::Result<Self, Self::Error> {
        let name = field.ident.as_ref().unwrap().clone();
        let ty = field.ty.clone();
        let mut attrs = FieldAttrs::default();

        for attr in &field.attrs {
            if !attr.path().is_ident("epan") {
                continue;
            }

            if let syn::Meta::List(meta) = &attr.meta {
                if meta.tokens.is_empty() {
                    continue;
                }

                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("skip") {
                        // #[epan(skip)]
                        attrs.skip = true;
                        return Ok(());
                    }
                    if meta.path.is_ident("name") {
                        // #[epan(name = "foo")]
                        let s = get_string_literal("name", &meta)?;
                        match attrs.name {
                            Some(_) => {
                                return Err(error_spanned_by(
                                    attr,
                                    "#[epan(name = \"...\")] attribute specified more than once",
                                ))
                            }
                            None => attrs.name = Some(s),
                        }
                    } else if meta.path.is_ident("abbrev") {
                        // #[epan(abbrev = "foo")]
                        let s = get_string_literal("abbrev", &meta)?;
                        match attrs.abbrev {
                            Some(_) => {
                                return Err(error_spanned_by(
                                    attr,
                                    "#[epan(abbrev = \"...\")] attribute specified more than once",
                                ))
                            }
                            None => attrs.abbrev = Some(s),
                        }
                    } else if meta.path.is_ident("ftype") {
                        // #[epan(ftype = Protocol)]
                        let ident = get_path_ident("ftype", &meta)?;
                        match attrs.ftype {
                            Some(_) => {
                                return Err(error_spanned_by(
                                    attr,
                                    "#[epan(ftype = ...)] attribute specified more than once",
                                ))
                            }
                            None => attrs.ftype = Some(ident),
                        }
                    } else if meta.path.is_ident("display") {
                        // #[epan(display = DecHex)]
                        let ident = get_path_ident("display", &meta)?;
                        match attrs.display {
                            Some(_) => {
                                return Err(error_spanned_by(
                                    attr,
                                    "#[epan(display = ...)] attribute specified more than once",
                                ))
                            }
                            None => attrs.display = Some(ident),
                        }
                    }
                    Ok(())
                })?;
            }
        }
        Ok(Self { name, attrs, ty })
    }
}

pub struct StructCtx {
    pub input: DeriveInput,
    pub container_attrs: Vec<ContainerAttr>,
    pub fields: Vec<ParsedField>,
}

impl StructCtx {
    pub fn new(input: DeriveInput) -> Result<Self> {
        if input.generics.gt_token.is_some()
            || input.generics.lt_token.is_some()
            || input.generics.where_clause.is_some()
        {
            return Err(error_spanned_by(
                input.generics,
                "Structs with generics are not supported for EpanProtocol",
            ));
        }
        Ok(Self {
            input,
            container_attrs: vec![],
            fields: vec![],
        })
    }

    pub fn parse_container(&mut self) -> Result<()> {
        for attr in &self.input.attrs {
            if !attr.path().is_ident("epan") {
                continue;
            }

            if let syn::Meta::List(meta) = &attr.meta {
                if meta.tokens.is_empty() {
                    continue;
                }
            }

            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    // #[epan(name = "foo")]
                    let s = get_string_literal("name", &meta)?;
                    if self
                        .container_attrs
                        .iter()
                        .any(|s| matches!(s, ContainerAttr::Name(_)))
                    {
                        return Err(error_spanned_by(
                            attr,
                            "#[epan(name = \"...\")] attribute specified more than once",
                        ));
                    }
                    self.container_attrs.push(ContainerAttr::Name(s))
                } else {
                    return Err(error_spanned_by(attr, "Unknown attribute"));
                }
                Ok(())
            })?;
        }

        Ok(())
    }

    pub fn parse_fields(&mut self) -> Result<()> {
        let data = match &self.input.data {
            Data::Struct(s) => s,
            _ => {
                return Err(error_spanned_by(
                    &self.input,
                    "EpanProtocol is only supported for structs",
                ))
            }
        };
        let fields = &data.fields;
        let named: &syn::punctuated::Punctuated<syn::Field, token::Comma> = match fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(error_spanned_by(
                    &self.input,
                    "EpanProtocol is only supported for named structs",
                ))
            }
        };

        self.fields.reserve(named.len());
        for field in named {
            self.fields.push(ParsedField::try_from(field)?);
        }

        Ok(())
    }
}

pub enum ReprType {
    U32,
    U64,
}

pub struct EnumInput {
    pub ident: Ident,
    pub repr_type: ReprType,
    pub ftype: FtEnum,
    pub variants: Vec<Ident>,
}

impl Parse for EnumInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let call_site = Span::call_site();
        let derive_input = DeriveInput::parse(input)?;

        let data = match derive_input.data {
            Data::Enum(data) => data,
            _ => {
                return Err(Error::new(
                    call_site,
                    "EpanProtocolEnum is only supported for enum",
                ));
            }
        };

        let variants = data
            .variants
            .into_iter()
            .map(|variant| match variant.fields {
                Fields::Unit => Ok(variant.ident),
                Fields::Named(_) | Fields::Unnamed(_) => Err(Error::new(
                    variant.ident.span(),
                    "must be a unit variant to use #[derive(EpanProtocolEnum)]",
                )),
            })
            .collect::<Result<Vec<Ident>>>()?;

        if variants.is_empty() {
            return Err(Error::new(call_site, "there must be at least one variant"));
        }

        let generics = derive_input.generics;
        if !generics.params.is_empty() || generics.where_clause.is_some() {
            return Err(Error::new(call_site, "generic enum is not supported"));
        }

        let mut repr_type = None;
        let mut ftype = None;
        for attr in derive_input.attrs {
            if attr.path().is_ident("repr") {
                if let Meta::List(meta) = &attr.meta {
                    meta.parse_nested_meta(|meta| {
                        const RECOGNIZED_32: &[&str] = &["u8", "u16", "u32", "i8", "i16", "i32"];
                        const RECOGNIZED_64: &[&str] = &["u64", "usize", "i64", "isize"];
                        const RECOGNIZED_INVALID: &[&str] = &["u128", "i128"];
                        if RECOGNIZED_32.iter().any(|int| meta.path.is_ident(int)) {
                            repr_type = Some(ReprType::U32);
                            ftype = Some(
                                FtEnum::try_from(
                                    meta.path.get_ident().unwrap().clone().to_string().as_str(),
                                )
                                .unwrap(),
                            );

                            return Ok(());
                        }
                        if RECOGNIZED_64.iter().any(|int| meta.path.is_ident(int)) {
                            repr_type = Some(ReprType::U64);
                            ftype = Some(
                                FtEnum::try_from(
                                    meta.path.get_ident().unwrap().clone().to_string().as_str(),
                                )
                                .unwrap(),
                            );
                            return Ok(());
                        }
                        if RECOGNIZED_INVALID.iter().any(|int| meta.path.is_ident(int)) {
                            return Err(meta.error("repr type is too big for EpanProtocolEnum"));
                        }
                        if meta.path.is_ident("align") || meta.path.is_ident("packed") {
                            if meta.input.peek(token::Paren) {
                                let arg;
                                parenthesized!(arg in meta.input);
                                let _ = arg.parse::<TokenStream>()?;
                            }
                            return Ok(());
                        }
                        Err(meta.error("unsupported repr for EpanProtocolEnum"))
                    })?;
                }
            }
        }
        let repr_type =
            repr_type.ok_or_else(|| Error::new(call_site, "missing #[repr(...)] attribute"))?;

        let ftype = ftype
            .ok_or_else(|| Error::new(call_site, "unexpected type in #[repr(...)] attribute"))?;

        Ok(EnumInput {
            ident: derive_input.ident,
            repr_type,
            ftype,
            variants,
        })
    }
}

fn error_spanned_by<A: ToTokens, T: Display>(obj: A, msg: T) -> Error {
    Error::new_spanned(obj.into_token_stream(), msg)
}

fn get_string_literal(attr_name: &str, meta: &ParseNestedMeta) -> Result<syn::LitStr> {
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

fn get_path_ident(attr_name: &str, meta: &ParseNestedMeta) -> Result<Ident> {
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
