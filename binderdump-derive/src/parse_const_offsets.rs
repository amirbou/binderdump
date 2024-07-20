use std::fmt::Debug;

use crate::helpers::error_spanned_by;
use syn::parse::{Error, Result};
use syn::{token, Data, DeriveInput, Fields, Ident, Meta};

#[derive(Debug)]
pub struct ParsedField {
    pub name: Ident,
    pub ty: syn::Type,
}

impl TryFrom<&syn::Field> for ParsedField {
    type Error = Error;

    fn try_from(field: &syn::Field) -> std::result::Result<Self, Self::Error> {
        let name = field.ident.as_ref().unwrap().clone();
        let ty = field.ty.clone();

        Ok(Self { name, ty })
    }
}

pub struct StructCtx {
    pub input: DeriveInput,
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
                "Structs with generics are not supported for ConstOffsets",
            ));
        }
        Ok(Self {
            input,
            fields: vec![],
        })
    }

    pub fn parse_container(&mut self) -> Result<()> {
        let mut repr_c = false;

        for attr in &self.input.attrs {
            if !attr.path().is_ident("repr") {
                continue;
            }

            if let Meta::List(meta) = &attr.meta {
                meta.parse_nested_meta(|meta| {
                    if meta.path.is_ident("C") {
                        repr_c = true;
                    }
                    Ok(())
                })?;

                if let syn::Meta::List(meta) = &attr.meta {
                    if meta.tokens.is_empty() {
                        continue;
                    }
                }
            }
        }

        if !repr_c {
            Err(error_spanned_by(
                &self.input,
                "ConstOffsets can only be derived for `repr(C)` structs",
            ))
        } else {
            Ok(())
        }
    }

    pub fn parse_fields(&mut self) -> Result<()> {
        let data = match &self.input.data {
            Data::Struct(s) => s,
            _ => {
                return Err(error_spanned_by(
                    &self.input,
                    "ConstOffsets is only supported for structs",
                ))
            }
        };
        let fields = &data.fields;
        let named: &syn::punctuated::Punctuated<syn::Field, token::Comma> = match fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(error_spanned_by(
                    &self.input,
                    "ConstOffsets is only supported for named structs",
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
