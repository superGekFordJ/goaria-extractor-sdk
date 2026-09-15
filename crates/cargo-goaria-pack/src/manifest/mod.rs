pub mod schema;

pub use schema::{
    validate_opaque_policy_ref, Capability, DomainRule, Manifest, ManifestError, ResourceLimits,
    CAPABILITY_AUTH_PROFILE, CAPABILITY_DOWNLOAD_AUTH, CAPABILITY_HTTP_FETCH,
    CAPABILITY_HTTP_FETCH_EXTENDED, CAPABILITY_PARSE_WASM, CURRENT_ABI_VERSION,
};
