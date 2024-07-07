use std::ffi::CString;

use proc_macro::TokenStream as CompilerTokenStream;
use proc_macro2::TokenStream;
use quote;
use syn;
mod parse;

use parse::{EnumInput, StructCtx};

#[proc_macro_derive(EpanProtocol, attributes(epan))]
pub fn derive_epan_protocol(input: CompilerTokenStream) -> CompilerTokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    let mut ctx = match StructCtx::new(input) {
        Ok(ctx) => ctx,
        Err(err) => return syn::Error::into_compile_error(err).into(),
    };

    // if let Err(err) = ctx.parse_container() {
    //     return syn::Error::into_compile_error(err).into();
    // }

    if let Err(err) = ctx.parse_fields() {
        return syn::Error::into_compile_error(err).into();
    }

    let mut items = Vec::<TokenStream>::with_capacity(ctx.fields.len());
    let mut subtrees_items = Vec::<TokenStream>::new();

    for field in ctx.fields {
        if field.attrs.skip {
            continue;
        }
        let display = match field.attrs.display {
            Some(display) => quote::quote! { Some(binderdump_trait::FieldDisplay::#display) },
            None => quote::quote! { None },
        };
        let ftype = match field.attrs.ftype {
            Some(ftype) => quote::quote! { Some(binderdump_trait::FtEnum::#ftype) },
            None => quote::quote! { None },
        };
        let name = match field.attrs.name {
            Some(name) => name,
            None => syn::LitStr::new(&field.name.to_string(), field.name.span()),
        };
        let abbrev = match field.attrs.abbrev {
            Some(abbrev) => abbrev,
            None => syn::LitStr::new(&field.name.to_string(), field.name.span()),
        };
        let ty = field.ty;
        items.push(quote::quote! {
            {
                let mut current_abbrev = abbrev.clone();
                current_abbrev.push_str(concat!(".", #abbrev));

                let mut current = <#ty as binderdump_trait::EpanProtocol>::get_info(String::from(#name), current_abbrev, #ftype, #display);
                info.append(&mut current);
            }
        });
        subtrees_items.push(quote::quote! {
            {
                let mut current_abbrev = abbrev.clone();
                current_abbrev.push_str(concat!(".", #abbrev));

                let mut current = <#ty as binderdump_trait::EpanProtocol>::get_subtrees(current_abbrev);
                subtrees.append(&mut current);
            }
        });
    }

    let struct_name = ctx.input.ident;

    quote::quote! {
        impl binderdump_trait::EpanProtocol for #struct_name {
            fn get_info(
                name: String,
                abbrev: String,
                ftype: Option<binderdump_trait::FtEnum>,
                display: Option<binderdump_trait::FieldDisplay>
            ) -> Vec<binderdump_trait::FieldInfo> {
                let mut info = vec![];
                #(#items)*
                info
            }

            fn get_subtrees(
                abbrev: String
            ) -> Vec<String> {
                let mut subtrees = vec![abbrev.clone()];
                #(#subtrees_items)*
                subtrees
            }

        }
    }
    .into()
}

#[proc_macro_derive(EpanProtocolEnum)]
pub fn derive_epan_protocol_enum(input: CompilerTokenStream) -> CompilerTokenStream {
    let EnumInput {
        ident,
        repr_type,
        ftype,
        variants,
    } = syn::parse_macro_input!(input as EnumInput);

    let items = variants.iter().map(|variant| {
        let string = syn::LitCStr::new(&CString::new(variant.to_string()).unwrap(), variant.span());
        match repr_type {
            parse::ReprType::U32 => quote::quote! {
                binderdump_trait::StringMapping {
                    value: #ident::#variant as u32,
                    string: #string
                },
            },
            parse::ReprType::U64 => quote::quote! {
                binderdump_trait::StringMapping64 {
                    value: #ident::#variant as u64,
                    string: #string
                },
            },
        }
    });

    let ftype_str = format!("binderdump_trait::FtEnum::{}", Into::<&str>::into(ftype));
    let ftype_token: proc_macro2::TokenStream = ftype_str.parse().unwrap();

    let map_variant = match &repr_type {
        parse::ReprType::U32 => quote::quote! {
            binderdump_trait::StringsMap::U32
        },
        parse::ReprType::U64 => quote::quote! {
            binderdump_trait::StringsMap::U64
        },
    };

    quote::quote! {
        impl binderdump_trait::EpanProtocolEnum for #ident {
            fn get_strings_map() -> binderdump_trait::StringsMap {
                #map_variant (
                    vec![
                        #(#items)*
                    ]
                )
            }

            fn get_repr() -> binderdump_trait::FtEnum {
                #ftype_token
            }
        }
    }
    .into()
}
