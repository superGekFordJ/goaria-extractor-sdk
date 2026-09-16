//! Procedural macros that generate the five GoAria ABI v1 guest exports for a
//! Rust extractor struct.
//!
//! Apply `#[goaria_extractor]` (or the compatibility alias `#[goaria_pack]`) to
//! a struct implementing `goaria_extractor_sdk::Extractor` to emit
//! `goaria_abi_version`, `goaria_alloc`, `goaria_free`, `goaria_match`, and
//! `goaria_extract` as `extern "C"` symbols.

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

/// Generates the five mandatory GoAria ABI v1 guest exports for the
/// annotated extractor struct:
///
/// - `goaria_abi_version() -> i32` — reports the SDK's ABI version (`1`).
/// - `goaria_alloc(len: i32) -> i32` — guest allocator the host calls to
///   reserve guest memory for input and host-import response buffers.
/// - `goaria_free(ptr: i32, len: i32)` — guest deallocator for those buffers.
/// - `goaria_match(ptr: i32, len: i32) -> i64` — decodes `MatchInput`, runs
///   `Extractor::match_url`, returns packed `MatchOutput` JSON.
/// - `goaria_extract(ptr: i32, len: i32) -> i64` — decodes `ExtractInput`,
///   runs `Extractor::extract`, returns packed `ExtractOutput` JSON.
///
/// The annotated struct must implement `goaria_extractor_sdk::Extractor`.
/// Because the dispatch shims instantiate it via `Default::default()` on
/// every invocation, the type must be constructible without arguments; any
/// state has to be initialized inside `Default`.
#[proc_macro_attribute]
pub fn goaria_extractor(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand_extractor(attr, item)
}

/// Compatibility alias for `#[goaria_extractor]` with identical expansion;
/// retained so existing packs keep building.
#[proc_macro_attribute]
pub fn goaria_pack(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand_extractor(attr, item)
}
