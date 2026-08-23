use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use url::Url;

pub const CURRENT_ABI_VERSION: u32 = 1;

pub const CAPABILITY_PARSE_WASM: &str = "cap.parse.wasm";
pub const CAPABILITY_HTTP_FETCH: &str = "cap.http.fetch";
pub const CAPABILITY_AUTH_PROFILE: &str = "cap.auth.profile";

pub const MAX_TIMEOUT_MILLIS: u64 = 10_000;
pub const MAX_MEMORY_PAGES: u32 = 256;
pub const MAX_HOST_CALLS: u32 = 128;
pub const MAX_RESPONSE_BYTES: i64 = 10 * 1024 * 1024;
pub const MAX_OUTPUT_ITEMS: u32 = 1_000;
pub const MAX_OUTPUT_BYTES: i64 = 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("pack abi_version {actual} does not match host abi_version {expected}")]
    AbiVersionMismatch { expected: u32, actual: u32 },
    #[error("invalid pack_id: {0}")]
    InvalidPackId(String),
    #[error("pack_id cannot be empty")]
    EmptyPackId,
    #[error("invalid pack_version: {0}")]
    InvalidPackVersion(String),
    #[error("invalid payload_sha256: {0}")]
    InvalidPayloadSha256(String),
    #[error("pack does not declare parse wasm capability (cap.parse.wasm)")]
    MissingParseWasmCapability,
    #[error("manifest must declare at least one capability")]
    EmptyCapabilities,
    #[error("duplicate capability '{0}'")]
    DuplicateCapability(String),
    #[error("capability '{0}' is not allowed")]
    DisallowedCapability(String),
    #[error("pack missing required capability: {0}")]
    MissingCapability(String),
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("URL '{0}' is not allowed by manifest domain rules")]
    DomainNotAllowed(String),
    #[error("domain rule error: {0}")]
    InvalidDomainRule(String),
    #[error("policy ref error: {0}")]
    InvalidPolicyRef(String),
    #[error("domain policy mode error: {0}")]
    InvalidDomainPolicyMode(String),
    #[error("resource limit '{field}' must be positive")]
    InvalidLimit { field: &'static str },
    #[error("resource limit '{field}' exceeds host trust policy maximum")]
    LimitExceeded { field: &'static str },
    #[error("max_memory_pages ({0}) exceeds host trust policy maximum (256)")]
    MemoryPagesExceeded(u32),
}

/// Capability identifier string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Capability(pub String);

impl Capability {
    pub fn parse_wasm() -> Self {
        Self(CAPABILITY_PARSE_WASM.to_string())
    }

    pub fn http_fetch() -> Self {
        Self(CAPABILITY_HTTP_FETCH.to_string())
    }

    pub fn auth_profile() -> Self {
        Self(CAPABILITY_AUTH_PROFILE.to_string())
    }
}

/// Domain matching rule defined in manifest.json.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainRule {
    pub host: String,
    #[serde(default)]
    pub include_subdomains: bool,
}

impl DomainRule {
    pub fn matches_host(&self, query_host: &str) -> bool {
        let pattern = self.host.trim().to_lowercase();
        let target = query_host.trim().to_lowercase();

        if pattern == target {
            return true;
        }

        if self.include_subdomains {
            let dot_pattern = format!(".{}", pattern);
            if target.ends_with(&dot_pattern) {
                return true;
            }
        }

        false
    }
}

/// Resource limits applied to extractor execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub timeout_millis: u64,
    pub max_memory_pages: u32,
    pub max_host_calls: u32,
    pub max_response_bytes: i64,
    pub max_output_items: u32,
    pub max_output_bytes: i64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_millis: 5000,
            max_memory_pages: 32,
            max_host_calls: 50,
            max_response_bytes: 1024 * 1024,
            max_output_items: 50,
            max_output_bytes: 1024 * 1024,
        }
    }
}

/// Full manifest structure representing `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub pack_id: String,
    pub pack_version: String,
    pub abi_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub capabilities: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<DomainRule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_policy_refs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_policy_refs: Option<Vec<String>>,
    pub resource_limits: ResourceLimits,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
}

fn is_lower_slug_edge(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

fn is_lower_slug_char(c: u8) -> bool {
    is_lower_slug_edge(c) || c == b'.' || c == b'_' || c == b'-'
}

pub fn validate_pack_id(id: &str) -> Result<(), ManifestError> {
    if id.is_empty() {
        return Err(ManifestError::EmptyPackId);
    }
    if id.len() < 3 || id.len() > 64 {
        return Err(ManifestError::InvalidPackId(
            "pack_id length must be between 3 and 64 characters".to_string(),
        ));
    }
    let bytes = id.as_bytes();
    if !is_lower_slug_edge(bytes[0]) || !is_lower_slug_edge(bytes[bytes.len() - 1]) {
        return Err(ManifestError::InvalidPackId(
            "pack_id must start and end with a lowercase letter or digit".to_string(),
        ));
    }
    for &b in &bytes[1..bytes.len() - 1] {
        if !is_lower_slug_char(b) {
            return Err(ManifestError::InvalidPackId(format!(
                "pack_id contains invalid character '{}'",
                b as char
            )));
        }
    }
    Ok(())
}

pub fn validate_pack_version(version: &str) -> Result<(), ManifestError> {
    if version.is_empty() || version != version.trim() {
        return Err(ManifestError::InvalidPackVersion(
            "pack_version must be non-empty and trimmed".to_string(),
        ));
    }
    for c in version.chars() {
        if c == '/' || c == '\\' || c == '\0' || c.is_ascii_whitespace() {
            return Err(ManifestError::InvalidPackVersion(
                "pack_version must not contain whitespace or path separators".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_payload_sha256(hash: &str) -> Result<(), ManifestError> {
    if hash.len() != 64 {
        return Err(ManifestError::InvalidPayloadSha256(
            "payload_sha256 must be 64 lowercase hex characters".to_string(),
        ));
    }
    for c in hash.chars() {
        if !c.is_ascii_digit() && !('a'..='f').contains(&c) {
            return Err(ManifestError::InvalidPayloadSha256(format!(
                "payload_sha256 contains invalid character '{}'",
                c
            )));
        }
    }
    Ok(())
}

fn is_opaque_policy_ref_edge(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

fn is_opaque_policy_ref_char(c: u8) -> bool {
    is_opaque_policy_ref_edge(c) || c == b'-'
}

pub fn validate_opaque_policy_ref(field: &str, ref_str: &str) -> Result<(), ManifestError> {
    if ref_str.len() < 3 || ref_str.len() > 64 {
        return Err(ManifestError::InvalidPolicyRef(format!(
            "{} ref length must be between 3 and 64 bytes",
            field
        )));
    }
    let bytes = ref_str.as_bytes();
    if !is_opaque_policy_ref_edge(bytes[0]) || !is_opaque_policy_ref_edge(bytes[bytes.len() - 1]) {
        return Err(ManifestError::InvalidPolicyRef(format!(
            "{} ref must start and end with a lowercase letter or digit",
            field
        )));
    }
    for &b in &bytes[1..bytes.len() - 1] {
        if !is_opaque_policy_ref_char(b) {
            return Err(ManifestError::InvalidPolicyRef(format!(
                "{} ref contains invalid character '{}'",
                field, b as char
            )));
        }
    }
    Ok(())
}

pub fn validate_opaque_policy_refs(field: &str, refs: &[String]) -> Result<(), ManifestError> {
    let mut seen = HashSet::with_capacity(refs.len());
    for r in refs {
        validate_opaque_policy_ref(field, r)?;
        if !seen.insert(r) {
            return Err(ManifestError::InvalidPolicyRef(format!(
                "{} contains duplicate ref '{}'",
                field, r
            )));
        }
    }
    Ok(())
}

pub fn validate_domain_label(label: &str) -> Result<(), ManifestError> {
    if label.is_empty() {
        return Err(ManifestError::InvalidDomainRule(
            "domain label must be non-empty".to_string(),
        ));
    }
    if label.len() > 63 {
        return Err(ManifestError::InvalidDomainRule(
            "domain label is too long".to_string(),
        ));
    }
    let bytes = label.as_bytes();
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return Err(ManifestError::InvalidDomainRule(
            "domain label must not start or end with hyphen".to_string(),
        ));
    }
    for &b in bytes {
        if !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'-' {
            return Err(ManifestError::InvalidDomainRule(format!(
                "domain label contains invalid character '{}'",
                b as char
            )));
        }
    }
    Ok(())
}

pub fn validate_domain_rule(rule: &DomainRule) -> Result<(), ManifestError> {
    let host = &rule.host;
    if host.is_empty() {
        return Err(ManifestError::InvalidDomainRule(
            "domain host must be non-empty".to_string(),
        ));
    }
    if host != host.trim() || host.as_str() != host.to_lowercase().as_str() {
        return Err(ManifestError::InvalidDomainRule(format!(
            "domain host '{}' must be lowercase and trimmed",
            host
        )));
    }
    if host.contains("://")
        || host.contains('/')
        || host.contains('\\')
        || host.contains('?')
        || host.contains('#')
        || host.contains('@')
        || host.contains(':')
    {
        return Err(ManifestError::InvalidDomainRule(format!(
            "domain host '{}' must not contain scheme, path, port, credentials, query, or fragment",
            host
        )));
    }
    if host.contains('*') {
        return Err(ManifestError::InvalidDomainRule(format!(
            "domain host '{}' must not contain wildcard syntax",
            host
        )));
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(ManifestError::InvalidDomainRule(format!(
            "domain host '{}' contains invalid label boundaries",
            host
        )));
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err(ManifestError::InvalidDomainRule(format!(
            "domain host '{}' must include at least two labels",
            host
        )));
    }
    for label in labels {
        validate_domain_label(label)?;
    }
    Ok(())
}

pub fn validate_domain_policy_mode(manifest: &Manifest) -> Result<(), ManifestError> {
    let has_domains = manifest.domains.as_ref().is_some_and(|d| !d.is_empty());
    let has_domain_refs = manifest
        .domain_policy_refs
        .as_ref()
        .is_some_and(|r| !r.is_empty());
    let has_broker_refs = manifest
        .broker_policy_refs
        .as_ref()
        .is_some_and(|r| !r.is_empty());
    let requires_broker_refs = manifest.has_capability(CAPABILITY_HTTP_FETCH)
        || manifest.has_capability(CAPABILITY_AUTH_PROFILE);

    if has_domains {
        if has_domain_refs || has_broker_refs {
            return Err(ManifestError::InvalidDomainPolicyMode(
                "manifest must not mix concrete domains with alias policy refs".to_string(),
            ));
        }
        if let Some(domains) = &manifest.domains {
            for rule in domains {
                validate_domain_rule(rule)?;
            }
        }
        return Ok(());
    }

    if manifest.domains.is_none() {
        return Err(ManifestError::InvalidDomainPolicyMode(
            "manifest domains must be explicit and non-empty for legacy mode or an explicit empty array for alias mode".to_string(),
        ));
    }

    if !has_domain_refs {
        return Err(ManifestError::InvalidDomainPolicyMode(
            "alias manifest must declare at least one domain_policy_ref".to_string(),
        ));
    }
    if requires_broker_refs && !has_broker_refs {
        return Err(ManifestError::InvalidDomainPolicyMode(
            "alias manifest with http or auth capability must declare at least one broker_policy_ref".to_string(),
        ));
    }
    if !requires_broker_refs && has_broker_refs {
        return Err(ManifestError::InvalidDomainPolicyMode(
            "broker_policy_refs require http or auth capability".to_string(),
        ));
    }
    if let Some(refs) = &manifest.domain_policy_refs {
        validate_opaque_policy_refs("domain_policy_refs", refs)?;
    }
    if let Some(refs) = &manifest.broker_policy_refs {
        validate_opaque_policy_refs("broker_policy_refs", refs)?;
    }

    Ok(())
}

pub fn validate_capabilities(capabilities: &[Capability]) -> Result<(), ManifestError> {
    if capabilities.is_empty() {
        return Err(ManifestError::EmptyCapabilities);
    }
    let mut seen = HashSet::with_capacity(capabilities.len());
    let mut has_parse_wasm = false;
    for cap in capabilities {
        if cap.0.is_empty() {
            return Err(ManifestError::DisallowedCapability(
                "capability must be non-empty".to_string(),
            ));
        }
        if !seen.insert(&cap.0) {
            return Err(ManifestError::DuplicateCapability(cap.0.clone()));
        }
        match cap.0.as_str() {
            CAPABILITY_PARSE_WASM => {
                has_parse_wasm = true;
            }
            CAPABILITY_HTTP_FETCH | CAPABILITY_AUTH_PROFILE => {}
            _ => {
                return Err(ManifestError::DisallowedCapability(cap.0.clone()));
            }
        }
    }
    if !has_parse_wasm {
        return Err(ManifestError::MissingParseWasmCapability);
    }
    Ok(())
}

pub fn validate_resource_limits(limits: &ResourceLimits) -> Result<(), ManifestError> {
    if limits.timeout_millis == 0 {
        return Err(ManifestError::InvalidLimit {
            field: "timeout_millis",
        });
    }
    if limits.timeout_millis > MAX_TIMEOUT_MILLIS {
        return Err(ManifestError::LimitExceeded {
            field: "timeout_millis",
        });
    }

    if limits.max_memory_pages == 0 {
        return Err(ManifestError::InvalidLimit {
            field: "max_memory_pages",
        });
    }
    if limits.max_memory_pages > MAX_MEMORY_PAGES {
        return Err(ManifestError::MemoryPagesExceeded(limits.max_memory_pages));
    }

    if limits.max_host_calls == 0 {
        return Err(ManifestError::InvalidLimit {
            field: "max_host_calls",
        });
    }
    if limits.max_host_calls > MAX_HOST_CALLS {
        return Err(ManifestError::LimitExceeded {
            field: "max_host_calls",
        });
    }

    if limits.max_response_bytes <= 0 {
        return Err(ManifestError::InvalidLimit {
            field: "max_response_bytes",
        });
    }
    if limits.max_response_bytes > MAX_RESPONSE_BYTES {
        return Err(ManifestError::LimitExceeded {
            field: "max_response_bytes",
        });
    }

    if limits.max_output_items == 0 {
        return Err(ManifestError::InvalidLimit {
            field: "max_output_items",
        });
    }
    if limits.max_output_items > MAX_OUTPUT_ITEMS {
        return Err(ManifestError::LimitExceeded {
            field: "max_output_items",
        });
    }

    if limits.max_output_bytes <= 0 {
        return Err(ManifestError::InvalidLimit {
            field: "max_output_bytes",
        });
    }
    if limits.max_output_bytes > MAX_OUTPUT_BYTES {
        return Err(ManifestError::LimitExceeded {
            field: "max_output_bytes",
        });
    }

    Ok(())
}

impl Manifest {
    pub fn validate_runnable(&self) -> Result<(), ManifestError> {
        validate_pack_id(&self.pack_id)?;
        validate_pack_version(&self.pack_version)?;

        if self.abi_version != CURRENT_ABI_VERSION {
            return Err(ManifestError::AbiVersionMismatch {
                expected: CURRENT_ABI_VERSION,
                actual: self.abi_version,
            });
        }

        if let Some(hash) = &self.payload_sha256 {
            validate_payload_sha256(hash)?;
        }

        validate_capabilities(&self.capabilities)?;
        validate_domain_policy_mode(self)?;
        validate_resource_limits(&self.resource_limits)?;

        Ok(())
    }

    pub fn has_capability(&self, cap_name: &str) -> bool {
        self.capabilities.iter().any(|c| c.0 == cap_name)
    }

    pub fn allows_url(&self, raw_url: &str) -> Result<bool, ManifestError> {
        let parsed = Url::parse(raw_url).map_err(|e| ManifestError::InvalidUrl(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| ManifestError::InvalidUrl("missing host".to_string()))?;

        Ok(self.allows_host(host))
    }

    pub fn allows_host(&self, host: &str) -> bool {
        if let Some(domains) = &manifest_domains(&self.domains) {
            domains.iter().any(|rule| rule.matches_host(host))
        } else {
            false
        }
    }
}

fn manifest_domains(domains: &Option<Vec<DomainRule>>) -> Option<&Vec<DomainRule>> {
    domains.as_ref()
}
