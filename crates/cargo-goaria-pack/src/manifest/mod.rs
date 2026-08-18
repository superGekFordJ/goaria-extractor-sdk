pub mod schema;

pub use schema::{
    Capability, DomainRule, Manifest, ManifestError, ResourceLimits, CAPABILITY_AUTH_PROFILE,
    CAPABILITY_HTTP_FETCH, CAPABILITY_PARSE_WASM, CURRENT_ABI_VERSION,
};
