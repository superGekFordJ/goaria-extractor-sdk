//! Guest-side SDK for building GoAria extractor packs in Rust.
//!
//! Implement [`Extractor`] on a `Default` struct,
//! annotate it with `#[goaria_extractor]`, and compile to
//! `wasm32-unknown-unknown`. The generated entrypoints exchange UTF-8 JSON
//! with the host through guest-memory buffers using the packed
//! `ptr << 32 | len` convention defined by ABI v1.

/// ABI v1 constants, result packing, and macro-dispatch entrypoints.
pub mod abi;
/// Guest-memory allocator backing `goaria_alloc`/`goaria_free`.
pub mod alloc;
/// High-level [`HostBroker`] client for the `goaria_host` imports.
pub mod broker;
/// Error type shared across SDK operations.
pub mod error;
/// Low-level wrappers over the `goaria_host` Wasm imports.
pub mod host;
/// Commonly used types and macros re-exported in one place.
pub mod prelude;
/// The [`Extractor`] trait packs implement.
pub mod traits;
/// Serde DTOs matching the ABI v1 wire schema.
pub mod types;

pub use goaria_extractor_macro::{goaria_extractor, goaria_pack};
pub use prelude::*;
