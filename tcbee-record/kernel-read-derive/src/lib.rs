extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use std::collections::BTreeMap;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Attribute, Data, DeriveInput, Error, Fields, Ident, LitStr, Result, Token,
    Type,
};

/// ===== Attribute parsing =====
///
/// Example:
///   #[kernel_read(ctx(sk: *const sock, bbr: *const bbr), default_src = "bbr")]
///
/// And field overrides:
///   #[kr(expr = "...")] -> e.g. "obj.function()?" /
///   #[kr(src = "tcp", path = "foo.bar")]
///
/// Header fields (if present) are auto-filled from `sk`:
///   time, addr_v4, src_v6, dst_v6, ports, family
///

#[proc_macro_derive(KernelRead, attributes(kernel_read, kr))]
pub fn derive_kernel_read(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_kernel_read(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_kernel_read(input: &DeriveInput) -> Result<TokenStream2> {
    let struct_name = &input.ident;

    let kr_cfg = KernelReadCfg::from_attrs(&input.attrs)?;

    // Require `sk` in ctx (for the header)
    let (sk_ident, sk_ty) = kr_cfg
        .ctx_args
        .iter()
        .find(|(id, _)| id == "sk")
        .cloned()
        .ok_or_else(|| Error::new_spanned(
            struct_name,
            "KernelRead: #[kernel_read(ctx(...))] must include `sk: *const sock` (used for the shared header fields)",
        ))?;

    // Choose default source ident (must exist in ctx, and cannot be `sk`)
    let default_src_name = kr_cfg
        .default_src
        .clone()
        .unwrap_or_else(|| "sk".to_string());
    if default_src_name == "sk" {
        return Err(Error::new_spanned(
            struct_name,
            "KernelRead: default_src cannot be \"sk\" (sk is reserved for the shared header fields)",
        ));
    }

    // Build lookup map for ctx idents/types
    let mut ctx_map: BTreeMap<String, (Ident, Type)> = BTreeMap::new();
    for (id, ty) in kr_cfg.ctx_args.iter() {
        ctx_map.insert(id.to_string(), (id.clone(), ty.clone()));
    }

    let (default_ident, _default_ty) =
        ctx_map.get(&default_src_name).cloned().ok_or_else(|| {
            Error::new_spanned(
                struct_name,
                format!(
                    "KernelRead: default_src=\"{}\" not found in ctx(...)",
                    default_src_name
                ),
            )
        })?;

    // Generate read_from(...) params in the same order as user wrote in ctx(...)
    let fn_params = kr_cfg.ctx_args.iter().map(|(id, ty)| quote! { #id: #ty });

    // Collect struct fields and generate initializers
    let fields_named = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(n) => &n.named,
            _ => {
                return Err(Error::new_spanned(
                    struct_name,
                    "KernelRead only supports structs with named fields",
                ))
            }
        },
        _ => {
            return Err(Error::new_spanned(
                struct_name,
                "KernelRead only supports structs",
            ))
        }
    };

    let mut inits: Vec<TokenStream2> = Vec::new();

    for f in fields_named.iter() {
        let field_ident = f
            .ident
            .clone()
            .ok_or_else(|| Error::new_spanned(&f, "KernelRead: expected named field"))?;
        let field_name = field_ident.to_string();

        // Field-level override: #[kr(expr="...")]
        if let Some(expr) = kr_field_expr(&f.attrs)? {
            let expr_ts: TokenStream2 = expr.parse().map_err(|_| {
                Error::new_spanned(
                    LitStr::new(&expr, proc_macro2::Span::call_site()),
                    "kr(expr=\"...\") must contain valid Rust tokens",
                )
            })?;
            inits.push(quote! { #field_ident: { #expr_ts } });
            continue;
        }

        // Field-level override: #[kr(src="tcp", path="foo.bar")]
        if let Some((src_name, path)) = kr_field_src_path(&f.attrs)? {
            let (src_ident, _src_ty) = ctx_map.get(&src_name).cloned().ok_or_else(|| {
                Error::new_spanned(
                    &field_ident,
                    format!(
                        "KernelRead: kr(src=\"{}\", ...) not found in ctx(...)",
                        src_name
                    ),
                )
            })?;

            let access_ts: TokenStream2 = path.parse().map_err(|_| {
                Error::new_spanned(
                    LitStr::new(&path, proc_macro2::Span::call_site()),
                    "kr(path=\"...\") must be valid Rust tokens like `foo` or `foo.bar.baz`",
                )
            })?;

            inits.push(quote! {
                #field_ident: {
                    let p = core::ptr::addr_of!((*#src_ident).#access_ts);
                    read_kernel(p as *const _)?
                }
            });
            continue;
        }

        // Shared header (auto-filled from sk) if present
        match field_name.as_str() {
            "time" => {
                inits.push(quote! { time: bpf_ktime_get_ns() });
                continue;
            }
            "addr_v4" => {
                inits.push(quote! {
                    addr_v4: {
                        let p = core::ptr::addr_of!((*#sk_ident).__sk_common.__bindgen_anon_1.skc_addrpair);
                        read_kernel(p as *const _)?
                    }
                });
                continue;
            }
            "src_v6" => {
                inits.push(quote! {
                    src_v6: {
                        let p = core::ptr::addr_of!((*#sk_ident).__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
                        read_kernel(p as *const _)?
                    }
                });
                continue;
            }
            "dst_v6" => {
                inits.push(quote! {
                    dst_v6: {
                        let p = core::ptr::addr_of!((*#sk_ident).__sk_common.skc_v6_daddr.in6_u.u6_addr8);
                        read_kernel(p as *const _)?
                    }
                });
                continue;
            }
            "sport" => {
                inits.push(quote! {
                    sport: {
                        let p = core::ptr::addr_of!((*#sk_ident).__sk_common.__bindgen_anon_3.skc_portpair);
                        let portpair: u32 = read_kernel(p as *const _)?;
                        (portpair >> 16) as u16
                    }
                });
                continue;
            }
            "dport" => {
                inits.push(quote! {
                    dport: {
                        let p = core::ptr::addr_of!((*#sk_ident).__sk_common.__bindgen_anon_3.skc_portpair);
                        let portpair: u32 = read_kernel(p as *const _)?;
                        ((portpair & 0xFFFF) as u16).swap_bytes()
                    }
                });
                continue;
            }
            "family" => {
                inits.push(quote! {
                    family: {
                        let p = core::ptr::addr_of!((*#sk_ident).__sk_common.skc_family);
                        read_kernel(p as *const _)?
                    }
                });
                continue;
            }
            _ => {}
        }

        // Default behavior: same-name field from default_src pointer
        inits.push(quote! {
            #field_ident: {
                let p = core::ptr::addr_of!((*#default_ident).#field_ident);
                read_kernel(p as *const _)?
            }
        });
    }

    // Ensure we used `sk_ty` (avoids unused warning in some builds if header fields absent)
    let _ = sk_ty;

    Ok(quote! {
        impl #struct_name {
            #[inline(always)]
            pub unsafe fn read_from(#(#fn_params),*) -> Result<Self, u32> {
                Ok(Self {
                    #(#inits,)*
                })
            }
        }
    })
}

/// ===== Parse #[kernel_read(...)] =====

#[derive(Debug, Clone)]
struct KernelReadCfg {
    ctx_args: Vec<(Ident, Type)>,
    default_src: Option<String>,
}

impl KernelReadCfg {
    fn from_attrs(attrs: &[Attribute]) -> Result<Self> {
        for a in attrs {
            if a.path().is_ident("kernel_read") {
                let parsed = a.parse_args::<KernelReadArgs>()?;
                return Ok(parsed.into_cfg()?);
            }
        }
        Err(Error::new(
            proc_macro2::Span::call_site(),
            "KernelRead: missing #[kernel_read(...)] attribute",
        ))
    }
}

struct KernelReadArgs {
    items: Vec<KernelReadItem>,
}

enum KernelReadItem {
    Ctx(Vec<(Ident, Type)>),
    DefaultSrc(String),
}

impl Parse for KernelReadArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut items = Vec::new();

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            let key_s = key.to_string();

            if key_s == "ctx" {
                let content;
                syn::parenthesized!(content in input);

                let mut args = Vec::new();
                while !content.is_empty() {
                    let name: Ident = content.parse()?;
                    content.parse::<Token![:]>()?;
                    let ty: Type = content.parse()?;
                    args.push((name, ty));

                    if content.peek(Token![,]) {
                        content.parse::<Token![,]>()?;
                    } else {
                        break;
                    }
                }
                items.push(KernelReadItem::Ctx(args));
            } else if key_s == "default_src" {
                input.parse::<Token![=]>()?;
                let s: LitStr = input.parse()?;
                items.push(KernelReadItem::DefaultSrc(s.value()));
            } else {
                return Err(Error::new_spanned(
                    key,
                    "KernelRead: expected `ctx(...)` or `default_src = \"...\"`",
                ));
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }

        Ok(Self { items })
    }
}

impl KernelReadArgs {
    fn into_cfg(self) -> Result<KernelReadCfg> {
        let mut ctx_args: Option<Vec<(Ident, Type)>> = None;
        let mut default_src: Option<String> = None;

        for it in self.items {
            match it {
                KernelReadItem::Ctx(v) => ctx_args = Some(v),
                KernelReadItem::DefaultSrc(s) => default_src = Some(s),
            }
        }

        let ctx_args = ctx_args.ok_or_else(|| {
            Error::new(
                proc_macro2::Span::call_site(),
                "KernelRead: missing ctx(...). Example: #[kernel_read(ctx(sk: *const sock, bbr: *const bbr), default_src=\"bbr\")]",
            )
        })?;

        Ok(KernelReadCfg {
            ctx_args,
            default_src,
        })
    }
}

/// ===== Parse #[kr(...)] on fields =====

fn kr_field_expr(attrs: &[Attribute]) -> Result<Option<String>> {
    for a in attrs {
        if !a.path().is_ident("kr") {
            continue;
        }
        let args = a.parse_args::<KrArgs>()?;
        if let Some(expr) = args.expr {
            return Ok(Some(expr));
        }
    }
    Ok(None)
}

fn kr_field_src_path(attrs: &[Attribute]) -> Result<Option<(String, String)>> {
    for a in attrs {
        if !a.path().is_ident("kr") {
            continue;
        }
        let args = a.parse_args::<KrArgs>()?;
        if let (Some(src), Some(path)) = (args.src, args.path) {
            return Ok(Some((src, path)));
        }
    }
    Ok(None)
}

struct KrArgs {
    expr: Option<String>,
    src: Option<String>,
    path: Option<String>,
}

impl Parse for KrArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut expr: Option<String> = None;
        let mut src: Option<String> = None;
        let mut path: Option<String> = None;

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let val: LitStr = input.parse()?;

            match key.to_string().as_str() {
                "expr" => expr = Some(val.value()),
                "src" => src = Some(val.value()),
                "path" => path = Some(val.value()),
                _ => {
                    return Err(Error::new_spanned(
                        key,
                        "kr(...): supported keys are expr, src, path",
                    ))
                }
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else {
                break;
            }
        }

        Ok(Self { expr, src, path })
    }
}
