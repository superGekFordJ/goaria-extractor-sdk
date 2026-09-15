use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Manifest capability: compile and instantiate the WebAssembly payload.
pub const CAPABILITY_PARSE_WASM: &str = "cap.parse.wasm";
/// Manifest capability: invoke goaria_host.http_fetch (GET/HEAD, safe headers).
pub const CAPABILITY_HTTP_FETCH: &str = "cap.http.fetch";
/// Manifest capability: extended fetch features (POST, request body,
/// pack-owned Authorization or X-* headers). Requires cap.http.fetch.
pub const CAPABILITY_HTTP_FETCH_EXTENDED: &str = "cap.http.fetch.extended";
/// Manifest capability: use host-custody auth profiles.
pub const CAPABILITY_AUTH_PROFILE: &str = "cap.auth.profile";
/// Manifest capability: register a self-minted bearer credential for the
/// materialized download Authorization header.
pub const CAPABILITY_DOWNLOAD_AUTH: &str = "cap.download.auth";

/// Input payload passed to goaria_match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchInput {
    pub url: String,
}

/// Output payload returned by goaria_match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct MatchOutput {
    pub matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MatchOutput {
    pub fn matched() -> Self {
        Self {
            matched: true,
            confidence: Some(100),
            reason: None,
        }
    }

    pub fn unmatched() -> Self {
        Self {
            matched: false,
            confidence: None,
            reason: None,
        }
    }

    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = Some(confidence);
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Input payload passed to goaria_extract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractInput {
    pub url: String,
}

/// Output payload returned by goaria_extract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractOutput {
    pub items: Vec<ExtractedItemRef>,
}

impl ExtractOutput {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn single(item: ExtractedItemRef) -> Self {
        Self { items: vec![item] }
    }

    pub fn with_item(mut self, item: ExtractedItemRef) -> Self {
        self.items.push(item);
        self
    }
}

/// Reference to a single extracted resource item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractedItemRef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_profile_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_profile_ref: Option<String>,
    /// Opaque host-registered download-auth reference (`dar-` + 32 lowercase
    /// hex). Mutually exclusive with auth_profile_ref / header_profile_ref.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_auth_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

/// Kind of credential secret stored in an auth profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSecretKind {
    Bearer,
    Cookie,
    #[serde(other)]
    Unknown,
}

/// Request payload sent to host import goaria_host.http_fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct HostHTTPFetchRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_policy_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_profile_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_millis: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<i64>,
    /// Opt this self-authenticated fetch out of browser grant/cookie
    /// matching and typed browser fields. Must not combine with
    /// auth_profile_ref.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omit_browser_context: Option<bool>,
}

/// Response payload received from host import goaria_host.http_fetch.
/// Unknown fields are tolerated so newer hosts stay decodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HostHTTPFetchResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Request payload sent to host import goaria_host.auth_profile_status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct HostAuthProfileStatusRequest {
    pub auth_profile_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_policy_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, String>>,
}

/// Response payload received from host import goaria_host.auth_profile_status.
/// Unknown fields are tolerated so newer hosts stay decodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HostAuthProfileStatusResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<AuthSecretKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Request payload sent to host import goaria_host.register_download_auth.
/// Only `kind = "bearer"` exists; the token never leaves the host except as
/// the materialized Authorization header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRegisterDownloadAuthRequest {
    pub kind: String,
    pub token: String,
}

/// Response payload received from goaria_host.register_download_auth.
/// Unknown fields are tolerated so newer hosts stay decodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HostRegisterDownloadAuthResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_auth_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Request payload sent to host import goaria_host.host_time. The wire shape
/// is intentionally empty: any field is an invalid_request on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HostTimeRequest {}

/// Response payload received from goaria_host.host_time.
/// Unknown fields are tolerated so newer hosts stay decodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HostTimeResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unix_secs: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
