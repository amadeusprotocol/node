use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemImpl, ItemFn, ImplItem, FnArg, ReturnType, Type, ItemStruct, Fields};

#[proc_macro_attribute]
pub fn contract_state(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemStruct);
    let name = &input.ident;
    let vis = &input.vis;
    let attrs = &input.attrs;

    let Fields::Named(ref fields) = input.fields else {
        return TokenStream::from(quote! { #input });
    };

    let is_flat = |f: &syn::Field| -> bool {
        f.attrs.iter().any(|attr| attr.path().is_ident("flat"))
    };

    let transformed_fields = fields.named.iter().map(|f| {
        let field_name = &f.ident;
        let field_vis = &f.vis;
        let field_ty = &f.ty;
        let filtered_attrs: Vec<_> = f.attrs.iter()
            .filter(|attr| !attr.path().is_ident("flat"))
            .collect();

        if is_flat(f) {
            quote! {
                #(#filtered_attrs)*
                #field_vis #field_name: LazyCell<#field_ty>
            }
        } else {
            quote! {
                #(#filtered_attrs)*
                #field_vis #field_name: #field_ty
            }
        }
    });

    let init_fields = fields.named.iter().map(|f| {
        let field = f.ident.as_ref().unwrap();
        let field_ty = &f.ty;
        let key = field.to_string();

        if is_flat(f) {
            quote! {
                #field: {
                    let mut key = prefix.clone();
                    key.extend_from_slice(#key.as_bytes());
                    LazyCell::with_prefix(key)
                }
            }
        } else {
            quote! {
                #field: {
                    let mut key = prefix.clone();
                    key.extend_from_slice(#key.as_bytes());
                    key.push(b':');
                    #field_ty::with_prefix(key)
                }
            }
        }
    });

    let flush_calls = fields.named.iter().map(|f| {
        let field = f.ident.as_ref().unwrap();
        quote! { self.#field.flush(); }
    });

    TokenStream::from(quote! {
        #(#attrs)*
        #vis struct #name {
            #(#transformed_fields),*
        }

        impl ContractState for #name {
            fn with_prefix(prefix: alloc::vec::Vec<u8>) -> Self {
                Self {
                    #(#init_fields),*
                }
            }

            fn flush(&self) {
                #(#flush_calls)*
            }
        }
    })
}

#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    if let Ok(impl_block) = syn::parse::<ItemImpl>(item.clone()) {
        return handle_impl_block(impl_block);
    }
    if let Ok(function) = syn::parse::<ItemFn>(item.clone()) {
        return handle_function(function);
    }
    item
}

fn is_integer_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.first() {
            let ident = &segment.ident;
            return matches!(
                ident.to_string().as_str(),
                "i8" | "i16" | "i32" | "i64" | "i128" |
                "u8" | "u16" | "u32" | "u64" | "u128" |
                "isize" | "usize"
            );
        }
    }
    false
}

fn handle_impl_block(impl_block: ItemImpl) -> TokenStream {
    let self_ty = &impl_block.self_ty;
    let mut methods = Vec::new();
    let mut wrappers = Vec::new();

    for item in impl_block.items.iter() {
        let ImplItem::Fn(method) = item else { continue };
        if !matches!(method.vis, syn::Visibility::Public(_)) { continue };

        let name = &method.sig.ident;
        let has_return = !matches!(method.sig.output, ReturnType::Default);
        let has_self = method.sig.inputs.iter().any(|arg| matches!(arg, FnArg::Receiver(_)));

        if !has_self {
            methods.push(method);
            continue;
        }

        let args: Vec<_> = method.sig.inputs.iter()
            .filter_map(|arg| match arg {
                FnArg::Typed(pat_type) => {
                    let param = &pat_type.pat;
                    let ty = &pat_type.ty;
                    let ptr = syn::Ident::new(&format!("{}_ptr", quote!(#param)), name.span());

                    let deser = if let Type::Path(tp) = &**ty {
                        if quote!(#tp).to_string().contains("String") {
                            quote!(read_string(#ptr))
                        } else if is_integer_type(ty) {
                            quote!(#ty::from_bytes(read_bytes(#ptr)))
                        } else {
                            quote!(read_bytes(#ptr))
                        }
                    } else {
                        quote!(read_bytes(#ptr))
                    };

                    Some((quote!(#ptr: i32), quote!(let #param = #deser;), quote!(#param)))
                }
                _ => None,
            })
            .collect();

        let params: Vec<_> = args.iter().map(|(p, _, _)| p).collect();
        let deserializations: Vec<_> = args.iter().map(|(_, d, _)| d).collect();
        let call_args: Vec<_> = args.iter().map(|(_, _, c)| c).collect();

        let sig = if params.is_empty() {
            quote!(#[no_mangle] pub extern "C" fn #name())
        } else {
            quote!(#[no_mangle] pub extern "C" fn #name(#(#params),*))
        };

        let call = if call_args.is_empty() {
            quote!(#name())
        } else {
            quote!(#name(#(#call_args),*))
        };

        let return_wrapper = if has_return {
            if let syn::ReturnType::Type(_, ret_type) = &method.sig.output {
                if is_integer_type(ret_type) {
                    quote! { ret(result.to_string().into_bytes()); }
                } else {
                    quote! { ret(result); }
                }
            } else {
                quote! { ret(result); }
            }
        } else {
            quote! {}
        };

        let body = if has_return {
            quote! {
                #(#deserializations)*
                let mut state = <#self_ty as ContractState>::with_prefix(alloc::vec::Vec::new());
                let result = state.#call;
                state.flush();
                #return_wrapper
            }
        } else {
            quote! {
                #(#deserializations)*
                let mut state = <#self_ty as ContractState>::with_prefix(alloc::vec::Vec::new());
                state.#call;
                state.flush();
            }
        };

        wrappers.push(quote! { #sig { #body } });
        methods.push(method);
    }

    TokenStream::from(quote! {
        impl #self_ty { #(#methods)* }
        #(#wrappers)*
    })
}

fn handle_function(input: ItemFn) -> TokenStream {
    let vis = &input.vis;
    let name = &input.sig.ident;
    let impl_name = syn::Ident::new(&format!("{}_impl", name), name.span());
    let inputs = &input.sig.inputs;
    let output = &input.sig.output;
    let block = &input.block;
    let attrs = &input.attrs;
    let has_return = !matches!(output, ReturnType::Default);

    let mut idx = 0;
    let mut params = quote!{};
    let mut deserializations = quote!{};
    let mut call_args = quote!{};

    for arg in inputs.iter() {
        if let FnArg::Typed(pat_type) = arg {
            let param = &pat_type.pat;
            let ty = &pat_type.ty;
            let ptr = syn::Ident::new(&format!("arg{}_ptr", idx), name.span());

            let deser = if let Type::Path(tp) = &**ty {
                if quote!(#tp).to_string().contains("String") {
                    quote!(read_string(#ptr))
                } else if is_integer_type(ty) {
                    quote!(#ty::from_bytes(read_bytes(#ptr)))
                } else {
                    quote!(read_bytes(#ptr))
                }
            } else {
                quote!(read_bytes(#ptr))
            };

            if idx > 0 {
                params.extend(quote!(, #ptr: i32));
                call_args.extend(quote!(, #param));
            } else {
                params.extend(quote!(#ptr: i32));
                call_args.extend(quote!(#param));
            }

            deserializations.extend(quote! { let #param = #deser; });
            idx += 1;
        }
    }

    let sig = if idx == 0 {
        quote!(#[no_mangle] pub extern "C" fn #name())
    } else {
        quote!(#[no_mangle] pub extern "C" fn #name(#params))
    };

    let call = if has_return {
        quote!(ret(#impl_name(#call_args));)
    } else {
        quote!(#impl_name(#call_args);)
    };

    TokenStream::from(quote! {
        #sig { #deserializations #call }
        #(#attrs)* #vis fn #impl_name(#inputs) #output #block
    })
}
