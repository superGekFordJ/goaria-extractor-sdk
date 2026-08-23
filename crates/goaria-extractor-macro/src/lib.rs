use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemStruct};

fn expand_extractor(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item_struct = parse_macro_input!(item as ItemStruct);
    let struct_ident = &item_struct.ident;

    let expanded = quote! {
        #item_struct

        #[no_mangle]
        pub extern "C" fn goaria_abi_version() -> i32 {
            ::goaria_extractor_sdk::abi::CURRENT_ABI_VERSION as i32
        }

        #[no_mangle]
        #[allow(clippy::missing_safety_doc)]
        pub unsafe extern "C" fn goaria_alloc(len: i32) -> i32 {
            ::goaria_extractor_sdk::alloc::alloc(len)
        }

        #[no_mangle]
        #[allow(clippy::missing_safety_doc)]
        pub unsafe extern "C" fn goaria_free(ptr: i32, len: i32) {
            ::goaria_extractor_sdk::alloc::free(ptr, len)
        }

        #[no_mangle]
        #[allow(clippy::missing_safety_doc)]
        pub unsafe extern "C" fn goaria_match(ptr: i32, len: i32) -> i64 {
            ::goaria_extractor_sdk::abi::dispatch_match::<#struct_ident>(ptr, len)
        }

        #[no_mangle]
        #[allow(clippy::missing_safety_doc)]
        pub unsafe extern "C" fn goaria_extract(ptr: i32, len: i32) -> i64 {
            ::goaria_extractor_sdk::abi::dispatch_extract::<#struct_ident>(ptr, len)
        }
    };

    TokenStream::from(expanded)
}

/// Declarative macro annotating an extractor struct to generate the 5 mandatory GoAria C-ABI exports:
/// - `goaria_abi_version() -> i32`
/// - `goaria_alloc(len: i32) -> i32`
/// - `goaria_free(ptr: i32, len: i32)`
/// - `goaria_match(ptr: i32, len: i32) -> i64`
/// - `goaria_extract(ptr: i32, len: i32) -> i64`
#[proc_macro_attribute]
pub fn goaria_extractor(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand_extractor(attr, item)
}

/// Compatibility alias for `#[goaria_extractor]`.
#[proc_macro_attribute]
pub fn goaria_pack(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand_extractor(attr, item)
}
