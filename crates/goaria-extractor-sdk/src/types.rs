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
    /// Candidate URL the host asks the pack to evaluate.
    pub url: String,
}

/// Output payload returned by goaria_match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct MatchOutput {
    /// Whether the pack supports the candidate URL. The host only invokes
    /// `goaria_extract` on a pack that reports `true` here.
    pub matched: bool,
    /// Match confidence, 0–100; omitted from the wire when `None`.
    ///
    /// An omitted field decodes host-side as `0` — there is no wire default.
    /// Emitting `100` for a confident match (as [`MatchOutput::matched`]
    /// does) is an SDK convention, not part of the ABI contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    /// Optional human-readable explanation. The host rejects reasons longer
    /// than 512 bytes or containing control characters. The SDK dispatcher
    /// also uses this field to surface the text of a `match_url` `Err`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MatchOutput {
    /// Confident match result (`matched: true`, `confidence: 100`).
    ///
    /// The `100` is an SDK convention for a definite match; the ABI assigns
    /// no meaning to any particular confidence value.
    pub fn matched() -> Self {
        Self {
            matched: true,
            confidence: Some(100),
            reason: None,
        }
    }

    /// Negative match result (`matched: false`, no confidence or reason).
    pub fn unmatched() -> Self {
        Self {
            matched: false,
            confidence: None,
            reason: None,
        }
    }

    /// Override the confidence value (0–100).
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Attach a human-readable explanation (see [`MatchOutput::reason`] for
    /// the host-side size and character limits).
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Input payload passed to goaria_extract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractInput {
    /// URL the host asks the pack to extract downloadable items from.
    pub url: String,
}

/// Output payload returned by goaria_extract.
///
/// An `extract` error or a guest trap surfaces to the host as the empty
/// output (`{"items":[]}`); ABI v1 defines no error channel for extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractOutput {
    /// Extracted downloadable items handed to the host. Bounded by the
    /// manifest `resource_limits.max_output_items` / `max_output_bytes`.
    pub items: Vec<ExtractedItemRef>,
}

impl ExtractOutput {
    /// Empty extraction result.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Extraction result containing exactly one item.
    pub fn single(item: ExtractedItemRef) -> Self {
        Self { items: vec![item] }
    }

    /// Append an item to the output.
    pub fn with_item(mut self, item: ExtractedItemRef) -> Self {
        self.items.push(item);
        self
    }
}

/// Reference to a single extracted resource item.
///
/// The host validates every emitted item: `url` must be a trimmed http(s)
/// URL of at most 2048 bytes without embedded credentials; the string fields
/// are limited to 1024 bytes of valid UTF-8 without control characters; and
/// `metadata` accepts at most 16 entries (keys non-empty and at most 64
/// bytes, values at most 512 bytes, and no credential-shaped key names such
/// as `authorization`, `cookie`, `token`, or `api_key`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractedItemRef {
    /// Optional pack-assigned identifier for the item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Direct downloadable URL (http/https only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Suggested destination filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Known artifact size in bytes; the host rejects negative values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,
    /// Content MIME type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Opaque reference to an authentication profile held in host custody;
    /// the host injects the credential when running the download. Mutually
    /// exclusive with `download_auth_ref`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_profile_ref: Option<String>,
    /// Opaque host header profile reference. Mutually exclusive with
    /// `download_auth_ref`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_profile_ref: Option<String>,
    /// Opaque `dar-` + 32 lowercase hex reference obtained from
    /// [`HostBroker::register_download_auth`](crate::broker::HostBroker::register_download_auth)
    /// during the same invocation. A raw token must never cross the ABI in
    /// this or any other field; the host rejects refs not registered during
    /// this invocation, refs belonging to another pack, and any value equal
    /// to a registered raw token. Mutually exclusive with
    /// `auth_profile_ref` / `header_profile_ref`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_auth_ref: Option<String>,
    /// Key-value contextual metadata forwarded to the host (limits above;
    /// credential-shaped keys are rejected).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

/// Kind of credential secret stored in an auth profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSecretKind {
    /// Bearer-token credential materialized as `Authorization: Bearer <token>`.
    Bearer,
    /// Cookie-based credential.
    Cookie,
    /// Unrecognized kind from a newer host; treated as opaque.
    #[serde(other)]
    Unknown,
}

/// Request payload sent to host import goaria_host.http_fetch.
///
/// A request uses exactly one addressing mode: raw mode sets `url`, while
/// ref mode sets `broker_policy_ref` + `endpoint_ref` (plus optional
/// `params`) under an alias manifest. Mixing modes is rejected as
/// `invalid_request`.
///
/// Requires `cap.http.fetch`. Extended features — `POST`, `body_base64`,
/// pack-owned `Authorization` or `X-*` headers — additionally require
/// `cap.http.fetch.extended`, must target HTTPS, and fail closed on any
/// redirect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct HostHTTPFetchRequest {
    /// HTTP method: `GET` (default), `HEAD`, or `POST`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Raw-mode target URL; mutually exclusive with the ref-mode fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Ref-mode broker policy reference; only valid paired with `endpoint_ref`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_policy_ref: Option<String>,
    /// Ref-mode endpoint reference; only valid paired with `broker_policy_ref`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<String>,
    /// Ref-mode path/query substitution parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, String>>,
    /// Request headers. Under `cap.http.fetch` only the safe names `Accept`,
    /// `Accept-Language`, `Content-Type`, `Referer`, and `User-Agent` pass;
    /// pack-owned `Authorization` and business `X-*` names additionally
    /// require `cap.http.fetch.extended`. `Cookie`, `Set-Cookie`, `Host`,
    /// `Content-Length`, `Transfer-Encoding`, `Connection`, and
    /// `Proxy-Authorization` are always rejected. At most 16 headers with
    /// values of at most 1024 bytes each.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    /// Strict padded standard base64 request body, decoded cap 16 KiB.
    /// Requires `method: "POST"`, `cap.http.fetch.extended`, and exactly one
    /// `Content-Type` of `application/json` or
    /// `application/x-www-form-urlencoded`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    /// Host auth profile reference; mutually exclusive with extended-fetch
    /// features and with `omit_browser_context`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_profile_ref: Option<String>,
    /// Per-request timeout in milliseconds; `0`/absent means unset. The
    /// effective deadline is the smallest positive of request, manifest, and
    /// broker policy maximum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_millis: Option<i32>,
    /// Per-request response byte cap; `0`/absent means unset. The effective
    /// cap is the smallest positive of request, manifest, and broker policy
    /// maximum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_response_bytes: Option<i64>,
    /// When `true`, the request is treated as self-authenticated: the host
    /// suppresses all browser-owned context (browser credential grants,
    /// cookies, `User-Agent`, `Accept-Language`, `Referer`) for this request.
    /// Combining it with `auth_profile_ref` is rejected as `invalid_request`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omit_browser_context: Option<bool>,
}

/// Response payload received from host import goaria_host.http_fetch.
/// Unknown fields are tolerated so newer hosts stay decodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HostHTTPFetchResponse {
    /// Whether the HTTP call succeeded and was permitted by policy.
    pub ok: bool,
    /// HTTP status code (e.g. `200`, `404`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
    /// URL after redirects; secret-shaped values are redacted by the host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    /// Response headers, restricted to the host's safe allowlist
    /// (`Content-Length`, `Content-Type`, `Etag`, `Last-Modified`) under
    /// canonical `Title-Case` names with secret-shaped values redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, Vec<String>>>,
    /// Base64-encoded response payload bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    /// Stable machine-readable error code when `ok` is `false`.
    ///
    /// Host categories: `invalid_request`, `policy_denied`, `fetch_failed` /
    /// `authenticated_fetch_failed`, `budget_exhausted`, `not_configured`,
    /// `response_too_large`, `internal_error`. The local CLI additionally
    /// emits `no_mock_match`, `broker_disabled`, and
    /// `ref_mode_not_supported_in_live_runner`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable error detail when `ok` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Request payload sent to host import goaria_host.auth_profile_status.
///
/// Like the fetch request, exactly one addressing mode applies: `url` for
/// raw mode or `broker_policy_ref` + `endpoint_ref` (+ `params`) for ref
/// mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct HostAuthProfileStatusRequest {
    /// Opaque host authentication profile reference to query.
    pub auth_profile_ref: String,
    /// Raw-mode URL the profile would be used for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Ref-mode broker policy reference; only valid paired with `endpoint_ref`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_policy_ref: Option<String>,
    /// Ref-mode endpoint reference; only valid paired with `broker_policy_ref`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<String>,
    /// Ref-mode path/query substitution parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, String>>,
}

/// Response payload received from host import goaria_host.auth_profile_status.
/// Unknown fields are tolerated so newer hosts stay decodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HostAuthProfileStatusResponse {
    /// Whether status resolution succeeded.
    pub ok: bool,
    /// Whether credentials exist in host custody for the profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    /// Credential kind (`bearer` or `cookie`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<AuthSecretKind>,
    /// Safe masked representation of the credential for UI display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_display: Option<String>,
    /// Stable machine-readable error code when `ok` is `false`.
    ///
    /// Host categories: `invalid_request`, `policy_denied`,
    /// `budget_exhausted`, `not_configured`, `auth_unavailable`,
    /// `response_too_large`, `internal_error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable error detail when `ok` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Request payload sent to host import goaria_host.register_download_auth.
/// Only `kind = "bearer"` exists; the token never leaves the host except as
/// the materialized Authorization header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRegisterDownloadAuthRequest {
    /// Registration kind; only `"bearer"` is defined.
    pub kind: String,
    /// Raw bearer token: 1–8170 bytes of valid UTF-8 without CR/LF, and it
    /// must not already carry a `Bearer ` scheme prefix (case-insensitive).
    /// The cap reserves the 22-byte `Authorization: Bearer ` prefix inside
    /// the 8192-byte download header-line limit so a registered token can
    /// always materialize.
    pub token: String,
}

/// Response payload received from goaria_host.register_download_auth.
/// Unknown fields are tolerated so newer hosts stay decodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HostRegisterDownloadAuthResponse {
    /// Whether registration succeeded.
    pub ok: bool,
    /// Opaque `dar-` + 32 lowercase hex reference bound to the registering
    /// pack identity and the current invocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_auth_ref: Option<String>,
    /// Stable machine-readable error code when `ok` is `false`.
    ///
    /// Host categories: `invalid_request`, `policy_denied`,
    /// `budget_exhausted`, `not_configured` (registry not wired; the local
    /// CLI also emits this when the broker is disabled), `registry_full`,
    /// `response_too_large`, `internal_error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable error detail when `ok` is `false`.
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
    /// Whether the call succeeded.
    pub ok: bool,
    /// Unix timestamp (seconds) frozen for the duration of one invocation;
    /// repeated calls inside the same `goaria_extract` return the same value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unix_secs: Option<i64>,
    /// Stable machine-readable error code when `ok` is `false`.
    ///
    /// Host categories: `invalid_request`, `budget_exhausted`,
    /// `response_too_large`, `internal_error`. The local CLI answers
    /// `host_time` even when the broker is disabled — `not_configured` is
    /// never emitted for this import.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable error detail when `ok` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
