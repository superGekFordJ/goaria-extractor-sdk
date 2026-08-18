use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub const CURRENT_ABI_VERSION: u32 = 1;

pub const CAPABILITY_PARSE_WASM: &str = "cap.parse.wasm";
pub const CAPABILITY_HTTP_FETCH: &str = "cap.http.fetch";
pub const CAPABILITY_AUTH_PROFILE: &str = "cap.auth.profile";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("pack abi_version {actual} does not match host abi_version {expected}")]
    AbiVersionMismatch { expected: u32, actual: u32 },
    #[error("pack does not declare parse wasm capability (cap.parse.wasm)")]
    MissingParseWasmCapability,
    #[error("pack missing required capability: {0}")]
    MissingCapability(String),
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("URL '{0}' is not allowed by manifest domain rules")]
    DomainNotAllowed(String),
    #[error("resource limit '{field}' must be positive")]
    InvalidLimit { field: &'static str },
    #[error("max_memory_pages ({0}) exceeds wasm limit (65536)")]
    MemoryPagesExceeded(u32),
    #[error("pack_id cannot be empty")]
    EmptyPackId,
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
pub struct ResourceLimits {
    #[serde(default = "default_timeout_millis")]
    pub timeout_millis: u64,
    #[serde(default = "default_max_memory_pages")]
    pub max_memory_pages: u32,
    #[serde(default = "default_max_host_calls")]
    pub max_host_calls: u32,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: i64,
    #[serde(default = "default_max_output_items")]
    pub max_output_items: u32,
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: i64,
}

fn default_timeout_millis() -> u64 {
    5000
}
fn default_max_memory_pages() -> u32 {
    32
}
fn default_max_host_calls() -> u32 {
    50
}
fn default_max_response_bytes() -> i64 {
    1024 * 1024
}
fn default_max_output_items() -> u32 {
    50
}
fn default_max_output_bytes() -> i64 {
    1024 * 1024
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_millis: default_timeout_millis(),
            max_memory_pages: default_max_memory_pages(),
            max_host_calls: default_max_host_calls(),
            max_response_bytes: default_max_response_bytes(),
            max_output_items: default_max_output_items(),
            max_output_bytes: default_max_output_bytes(),
        }
    }
}

/// Full manifest structure representing `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub pack_id: String,
    pub pack_version: String,
    pub abi_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub domains: Vec<DomainRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_policy_refs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_policy_refs: Option<Vec<String>>,
    #[serde(default)]
    pub resource_limits: ResourceLimits,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
}

impl Manifest {
    pub fn validate_runnable(&self) -> Result<(), ManifestError> {
        if self.pack_id.trim().is_empty() {
            return Err(ManifestError::EmptyPackId);
        }
        if self.abi_version != CURRENT_ABI_VERSION {
            return Err(ManifestError::AbiVersionMismatch {
                expected: CURRENT_ABI_VERSION,
                actual: self.abi_version,
            });
        }
        if !self.has_capability(CAPABILITY_PARSE_WASM) {
            return Err(ManifestError::MissingParseWasmCapability);
        }
        if self.resource_limits.timeout_millis == 0 {
            return Err(ManifestError::InvalidLimit {
                field: "timeout_millis",
            });
        }
        if self.resource_limits.max_memory_pages == 0 {
            return Err(ManifestError::InvalidLimit {
                field: "max_memory_pages",
            });
        }
        if self.resource_limits.max_memory_pages > 65_536 {
            return Err(ManifestError::MemoryPagesExceeded(
                self.resource_limits.max_memory_pages,
            ));
        }
        if self.resource_limits.max_host_calls == 0 {
            return Err(ManifestError::InvalidLimit {
                field: "max_host_calls",
            });
        }
        if self.resource_limits.max_response_bytes <= 0 {
            return Err(ManifestError::InvalidLimit {
                field: "max_response_bytes",
            });
        }
        if self.resource_limits.max_output_items == 0 {
            return Err(ManifestError::InvalidLimit {
                field: "max_output_items",
            });
        }
        if self.resource_limits.max_output_bytes <= 0 {
            return Err(ManifestError::InvalidLimit {
                field: "max_output_bytes",
            });
        }

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
        self.domains.iter().any(|rule| rule.matches_host(host))
    }
}
