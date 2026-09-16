use crate::manifest::{
    schema::MAX_RESPONSE_BYTES, validate_opaque_policy_ref, Manifest, CAPABILITY_AUTH_PROFILE,
    CAPABILITY_DOWNLOAD_AUTH, CAPABILITY_HTTP_FETCH, CAPABILITY_HTTP_FETCH_EXTENDED,
};
use crate::runner::auth_provider::AuthProvider;
use crate::runner::limits::HostCallBudget;
use base64::Engine;
use goaria_extractor_sdk::types::{
    HostHTTPFetchRequest, HostHTTPFetchResponse, HostRegisterDownloadAuthRequest,
    HostRegisterDownloadAuthResponse, HostTimeResponse,
};
use regex::Regex;
use std::collections::{BTreeMap, HashSet};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use url::{Host, Url};

/// Request headers a pack may set without the extended fetch capability
/// (canonical-lower names; mirrors the host broker allowlist).
pub const SAFE_REQUEST_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "content-type",
    "referer",
    "user-agent",
];

/// Header names a pack must never set directly (canonical-lower).
pub const FORBIDDEN_PACK_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
];

/// Response headers exposed to the guest (canonical-lower names).
pub const SAFE_RESPONSE_HEADERS: &[&str] =
    &["content-length", "content-type", "etag", "last-modified"];

// Extended pack-owned header deny list; keep in sync with the host's
// deniedBrowserGrantHeaderExact/deniedBrowserGrantHeaderPrefixes. Prefixes
// deliberately include or omit the trailing dash: bare x-client-cert,
// x-client-dn, x-auth-user and x-ms-client-principal are themselves denied
// names, so those prefixes cover the bare form plus every suffixed variant.
// Broad vendor namespaces (x-amzn-*, x-goog-*, x-azure-*) stay open on
// purpose; only their identity-asserting sub-families are denied.
const DENIED_EXTENDED_HEADER_EXACT: &[&str] = &[
    "x-real-ip",
    "x-real-host",
    "x-client-ip",
    "x-client-hostname",
    "x-cluster-client-ip",
    "x-originating-ip",
    "x-scheme",
    "x-forwarded",
    "x-host",
    "x-true-client-ip",
    "x-scope-orgid",
    "x-credential-identifier",
];

const DENIED_EXTENDED_HEADER_PREFIXES: &[&str] = &[
    "x-forwarded-",
    "x-http-method",
    "x-method-override",
    "x-original-",
    "x-rewrite-",
    "x-remote-",
    "x-ssl-client-",
    "x-client-cert",
    "x-client-dn",
    "x-auth-request-",
    "x-authenticated-",
    "x-auth-user",
    "x-ms-client-principal",
    "x-envoy-",
    "x-arr-",
    "x-middleware-",
    "x-amzn-oidc-",
    "x-goog-authenticated-",
    "x-goog-iap-",
    "x-authentik-",
    "x-pomerium-",
    "x-vercel-",
    "x-webauth-",
    "x-consumer-",
    "x-proxy-",
    "x-goaria-",
    "x-override-",
];

const MAX_EXTENDED_FETCH_BODY_BYTES: usize = 16 * 1024;
const MAX_HEADER_COUNT: usize = 16;
const MAX_HEADER_VALUE_BYTES: usize = 1024;
const REDIRECT_LIMIT: u32 = 5;
const MAX_FETCH_TIMEOUT_MILLIS: u64 = 10_000;
const DEFAULT_FETCH_TIMEOUT_MILLIS: u64 = 5_000;
const REDACTED_MARKER: &str = "[REDACTED]";
const MAX_REF_PARAMS: usize = 16;
const MAX_REF_PARAM_KEY_BYTES: usize = 32;
const MAX_REF_PARAM_VALUE_BYTES: usize = 512;

/// Query keys whose values are always treated as secret-shaped when a URL is
/// exposed back to the guest (mirrors the host's tokenLikeQueryKeys).
const TOKEN_LIKE_QUERY_KEYS: &[&str] = &[
    "access_token",
    "api_key",
    "auth",
    "credential",
    "key",
    "policy",
    "secret",
    "sig",
    "signature",
    "token",
    "x-api-key",
];

fn sensitive_header_start_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(authorization|cookie|set-cookie|proxy-authorization|x-[a-z0-9-]*(?:api[-_]?key|auth|token|secret)[a-z0-9-]*)\s*[:=]\s*",
        )
        .expect("sensitive header pattern")
    })
}

/// Replace every occurrence of a known secret plus token-like `?key=` query
/// values and `Name: value` credential spans inside a value that will be
/// exposed to the guest (mirrors the host's RedactSensitive).
pub(crate) fn redact_sensitive(input: &str, known_secrets: &[String]) -> String {
    let mut redacted = input.to_string();
    for secret in known_secrets {
        if !secret.is_empty() {
            redacted = redacted.replace(secret.as_str(), REDACTED_MARKER);
        }
    }
    let redacted = redact_query_secrets(&redacted);
    redact_sensitive_header_values(&redacted)
}

fn redact_query_secrets(input: &str) -> String {
    let mut out = input.to_string();
    for key in TOKEN_LIKE_QUERY_KEYS {
        let pattern = format!(r"(?i)([?&;]{}=)([^&#;\s]+)", regex::escape(key));
        if let Ok(re) = Regex::new(&pattern) {
            out = re
                .replace_all(&out, format!("${{1}}{REDACTED_MARKER}"))
                .into_owned();
        }
    }
    out
}

fn redact_sensitive_header_values(input: &str) -> String {
    let re = sensitive_header_start_pattern();
    let mut out = String::with_capacity(input.len());
    let mut offset = 0;
    while offset < input.len() {
        let Some(loc) = re.find_at(input, offset) else {
            break;
        };
        out.push_str(&input[offset..loc.start()]);
        let prefix = input[loc.start()..loc.end()].trim_end_matches([' ', '\t']);
        out.push_str(prefix);
        out.push(' ');
        out.push_str(REDACTED_MARKER);

        let mut value_end = input[loc.end()..]
            .find(['\r', '\n'])
            .map(|i| loc.end() + i)
            .unwrap_or(input.len());
        if let Some(next) = re.find_at(input, loc.end()) {
            if next.start() < value_end {
                value_end = next.start();
            }
        }
        offset = value_end;
    }
    out.push_str(&input[offset..]);
    out
}

/// Internal fetch rejection: wire error category plus diagnostic detail.
/// Broker-layer categories (fetch_failed/authenticated_fetch_failed) emit a
/// fixed static wire message; `message` is only surfaced for detail-carrying
/// categories like invalid_request/policy_denied.
#[derive(Debug)]
pub(crate) struct FetchDeny {
    pub(crate) error_code: &'static str,
    pub(crate) message: String,
}

impl FetchDeny {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            error_code: "invalid_request",
            message: message.into(),
        }
    }

    fn fetch_failed(message: impl Into<String>) -> Self {
        Self {
            error_code: "fetch_failed",
            message: message.into(),
        }
    }

    fn policy_denied(message: impl Into<String>) -> Self {
        Self {
            error_code: "policy_denied",
            message: message.into(),
        }
    }

    fn into_response(self) -> HostHTTPFetchResponse {
        let message = match self.error_code {
            "fetch_failed" => "fetch failed".to_string(),
            "authenticated_fetch_failed" => "authenticated fetch failed".to_string(),
            _ => self.message,
        };
        HostHTTPFetchResponse {
            ok: false,
            error_code: Some(self.error_code.to_string()),
            message: Some(message),
            ..Default::default()
        }
    }
}

/// Normalized request shape produced by the pre-dispatch validation stages.
#[derive(Debug, Clone, Default)]
pub struct ValidatedFetchShape {
    /// Normalized uppercase method (empty input defaults to GET).
    pub method: String,
    /// Decoded request body bytes (empty when absent).
    pub body: Vec<u8>,
    /// Whether the request uses extended fetch features.
    pub wants_extended: bool,
    /// Policy-checked request headers keyed by canonical-lower name.
    pub validated_headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestMode {
    Raw,
    Ref,
}

fn invalid_request_response(detail: impl Into<String>) -> HostHTTPFetchResponse {
    HostHTTPFetchResponse {
        ok: false,
        error_code: Some("invalid_request".to_string()),
        message: Some(detail.into()),
        ..Default::default()
    }
}

fn policy_denied_response(detail: impl Into<String>) -> HostHTTPFetchResponse {
    HostHTTPFetchResponse {
        ok: false,
        error_code: Some("policy_denied".to_string()),
        message: Some(detail.into()),
        ..Default::default()
    }
}

fn broker_failed_response(code: &'static str) -> HostHTTPFetchResponse {
    FetchDeny {
        error_code: code,
        message: String::new(),
    }
    .into_response()
}

/// True when the manifest is in alias policy-ref mode: an explicit empty
/// `domains` array plus at least one domain policy ref.
pub(crate) fn is_alias_manifest(manifest: &Manifest) -> bool {
    manifest.domains.as_ref().is_some_and(|d| d.is_empty())
        && manifest
            .domain_policy_refs
            .as_ref()
            .is_some_and(|r| !r.is_empty())
}

/// HTTP token characters (RFC 7230 tchar): visible ASCII minus separators.
fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| {
            (33..=126).contains(&b)
                && !matches!(
                    b,
                    b'(' | b')'
                        | b'<'
                        | b'>'
                        | b'@'
                        | b','
                        | b';'
                        | b':'
                        | b'\\'
                        | b'"'
                        | b'/'
                        | b'['
                        | b']'
                        | b'?'
                        | b'='
                        | b'{'
                        | b'}'
                )
        })
}

/// MIME-style canonical header name: first letter of each '-'-separated
/// segment uppercased, the rest lowercased (Go CanonicalHeaderKey equivalent).
fn canonical_header_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for c in name.chars() {
        if upper && c.is_ascii_lowercase() {
            out.push(c.to_ascii_uppercase());
        } else if !upper && c.is_ascii_uppercase() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
        upper = c == '-';
    }
    out
}

/// Whether a canonical-lower header name belongs to the extended channel's
/// privileged set: Authorization or any x-* business header.
fn pack_header_needs_extended(lower: &str) -> bool {
    lower == "authorization" || lower.starts_with("x-")
}

fn is_denied_extended_name(lower: &str) -> bool {
    DENIED_EXTENDED_HEADER_EXACT.contains(&lower)
        || DENIED_EXTENDED_HEADER_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

fn is_secret_header_name(lower: &str) -> bool {
    matches!(
        lower,
        "authorization" | "cookie" | "set-cookie" | "proxy-authorization"
    ) || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("api-key")
        || lower.contains("apikey")
}

fn is_forbidden_pack_header(lower: &str) -> bool {
    FORBIDDEN_PACK_HEADERS.contains(&lower)
}

/// Any character < 0x20 or DEL (0x7f); tab is rejected here on purpose.
pub(crate) fn string_contains_control(value: &str) -> bool {
    value.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}')
}

/// Pack-owned Authorization must be `<scheme><SP><credentials>`: a token
/// scheme, no consecutive spaces, edge-trimmed credentials.
fn is_valid_pack_owned_authorization(value: &str) -> bool {
    let Some((scheme, credentials)) = value.split_once(' ') else {
        return false;
    };
    !scheme.is_empty()
        && is_http_token(scheme)
        && !credentials.is_empty()
        && !value.contains("  ")
        && credentials == credentials.trim()
}

fn is_lower_slug_edge(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// Lower-slug predicate shared with the auth profile status handler.
pub(crate) fn is_valid_profile_slug(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !is_lower_slug_edge(bytes[0]) || !is_lower_slug_edge(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.len() < 3
        || bytes[1..bytes.len() - 1]
            .iter()
            .all(|&b| is_lower_slug_edge(b) || b == b'-')
}

/// `Some("")` on optional string fields is treated as absent, matching the
/// host's `omitempty`-style handling of empty optional values.
fn opt_nonempty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

fn validate_auth_profile_ref(id: &str) -> Result<(), FetchDeny> {
    if !is_valid_profile_slug(id) {
        return Err(FetchDeny::invalid_request(
            "auth profile_id must be a lowercase slug of 1-64 characters",
        ));
    }
    Ok(())
}

/// Host-policy placeholder key shape: lower-slug edges with interior '-'.
fn is_ref_param_placeholder_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if !is_lower_slug_edge(bytes[0]) || !is_lower_slug_edge(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.len() < 3
        || bytes[1..bytes.len() - 1]
            .iter()
            .all(|&b| is_lower_slug_edge(b) || b == b'-')
}

fn is_sensitive_ref_param_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    if matches!(lower.as_str(), "key" | "api-key" | "apikey") {
        return true;
    }
    [
        "token",
        "secret",
        "auth",
        "cookie",
        "header",
        "credential",
        "password",
        "passwd",
        "bearer",
        "session",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

/// Ref-mode params gate (mirrors the host's
/// validateHostPolicyEndpointParams): bounded count/length, trimmed UTF-8
/// control-free text, placeholder-shaped non-sensitive keys, and values that
/// carry no URL or credential syntax.
pub(crate) fn validate_ref_params(params: &BTreeMap<String, String>) -> Result<(), FetchDeny> {
    if params.len() > MAX_REF_PARAMS {
        return Err(FetchDeny::invalid_request(format!(
            "params must contain at most {MAX_REF_PARAMS} entries"
        )));
    }
    for (key, value) in params {
        if key.is_empty() || key.len() > MAX_REF_PARAM_KEY_BYTES {
            return Err(FetchDeny::invalid_request(format!(
                "param key length must be between 1 and {MAX_REF_PARAM_KEY_BYTES} bytes"
            )));
        }
        if key.trim() != key || string_contains_control(key) {
            return Err(FetchDeny::invalid_request(
                "param key must be trimmed and control-free",
            ));
        }
        if !is_ref_param_placeholder_key(key) {
            return Err(FetchDeny::invalid_request(format!(
                "param key {key:?} is invalid"
            )));
        }
        if is_sensitive_ref_param_key(key) {
            return Err(FetchDeny::invalid_request(format!(
                "param key {key:?} is reserved"
            )));
        }
        if value.is_empty() || value.len() > MAX_REF_PARAM_VALUE_BYTES {
            return Err(FetchDeny::invalid_request(format!(
                "param value length must be between 1 and {MAX_REF_PARAM_VALUE_BYTES} bytes"
            )));
        }
        if value.trim() != value || string_contains_control(value) {
            return Err(FetchDeny::invalid_request(
                "param value must be trimmed and control-free",
            ));
        }
        if value.contains("://")
            || value.chars().any(|c| {
                matches!(
                    c,
                    '/' | '\\' | '?' | '#' | '@' | '%' | '&' | '=' | ';' | ':'
                )
            })
        {
            return Err(FetchDeny::invalid_request(
                "param value contains reserved URL syntax",
            ));
        }
        let lower = value.to_lowercase();
        if lower.starts_with("bearer ")
            || lower.starts_with("basic ")
            || lower.contains("authorization:")
            || lower.contains("cookie:")
        {
            return Err(FetchDeny::invalid_request(
                "param value contains credential-looking syntax",
            ));
        }
    }
    Ok(())
}

/// Normalize the wire method: empty defaults to GET, otherwise trim+upper;
/// interior whitespace or an empty result is malformed.
fn normalize_fetch_method(raw: &str) -> Result<String, FetchDeny> {
    if raw.is_empty() {
        return Ok("GET".to_string());
    }
    let normalized = raw.trim().to_uppercase();
    if normalized.is_empty()
        || normalized
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
    {
        return Err(FetchDeny::invalid_request(format!(
            "unsupported http method {raw:?}"
        )));
    }
    Ok(normalized)
}

/// Strict padded-base64 body decode with the 16 KiB decoded cap. The
/// whitespace pre-check is intentional: base64 decoders may silently skip
/// CR/LF even in strict mode.
fn decode_extended_body(encoded: &str) -> Result<Vec<u8>, FetchDeny> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    if encoded
        .chars()
        .any(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
    {
        return Err(FetchDeny::invalid_request(
            "body_base64 is not valid padded base64",
        ));
    }
    let body = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| FetchDeny::invalid_request("body_base64 is not valid padded base64"))?;
    if body.len() > MAX_EXTENDED_FETCH_BODY_BYTES {
        return Err(FetchDeny::invalid_request(format!(
            "body_base64 exceeds the {MAX_EXTENDED_FETCH_BODY_BYTES} byte decoded cap"
        )));
    }
    Ok(body)
}

/// Media type must parse as `type/subtype` plus optional `;`-separated
/// parameters and be one of the two allowed extended body content types.
fn is_extended_body_content_type_allowed(value: &str) -> bool {
    let mut parts = value.split(';');
    let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    if !matches!(
        media.as_str(),
        "application/json" | "application/x-www-form-urlencoded"
    ) {
        return false;
    }
    for param in parts {
        let param = param.trim();
        // A bare/trailing `;` leaves an empty parameter, which is malformed.
        let Some((key, val)) = param.split_once('=') else {
            return false;
        };
        let key = key.trim();
        let val = val.trim();
        let val_ok =
            is_http_token(val) || (val.len() >= 2 && val.starts_with('"') && val.ends_with('"'));
        if !is_http_token(key) || !val_ok {
            return false;
        }
    }
    true
}

/// Counted on the raw header map: exactly one canonical Content-Type entry
/// with an allowed media type.
fn extended_body_content_type_ok(headers: Option<&BTreeMap<String, String>>) -> bool {
    let Some(headers) = headers else {
        return false;
    };
    let mut found = 0;
    let mut value = "";
    for (name, header_value) in headers {
        if name.trim().eq_ignore_ascii_case("content-type") {
            found += 1;
            value = header_value;
        }
    }
    found == 1 && is_extended_body_content_type_allowed(value)
}

/// POST, a body, or a canonical Authorization / X-* header mark the request
/// as using extended fetch features.
fn request_uses_extended_fetch(
    method: &str,
    headers: Option<&BTreeMap<String, String>>,
    has_body: bool,
) -> bool {
    if method == "POST" || has_body {
        return true;
    }
    headers.is_some_and(|headers| {
        headers
            .keys()
            .any(|name| pack_header_needs_extended(&name.trim().to_lowercase()))
    })
}

/// Local-only checks that must happen before mode dispatch: auth slug shape,
/// method normalization, strict body decoding, body rules, and the
/// extended/auth-profile exclusion.
fn validate_extended_fetch_shape(
    req: &HostHTTPFetchRequest,
) -> Result<ValidatedFetchShape, FetchDeny> {
    if let Some(id) = opt_nonempty(&req.auth_profile_ref) {
        validate_auth_profile_ref(id)?;
    }
    let method = normalize_fetch_method(req.method.as_deref().unwrap_or(""))?;
    let body = decode_extended_body(req.body_base64.as_deref().unwrap_or(""))?;
    if !body.is_empty() {
        if method != "POST" {
            return Err(FetchDeny::invalid_request(
                "request body requires the POST method",
            ));
        }
        if !extended_body_content_type_ok(req.headers.as_ref()) {
            return Err(FetchDeny::invalid_request(
                "request body requires a single application/json or application/x-www-form-urlencoded content type",
            ));
        }
    }
    let wants_extended =
        request_uses_extended_fetch(&method, req.headers.as_ref(), !body.is_empty());
    if wants_extended && opt_nonempty(&req.auth_profile_ref).is_some() {
        return Err(FetchDeny::invalid_request(
            "extended fetch request must not use an auth profile",
        ));
    }
    if req.omit_browser_context.unwrap_or(false) && opt_nonempty(&req.auth_profile_ref).is_some() {
        return Err(FetchDeny::invalid_request(
            "omit_browser_context forbids auth_profile_ref",
        ));
    }
    Ok(ValidatedFetchShape {
        method,
        body,
        wants_extended,
        validated_headers: BTreeMap::new(),
    })
}

/// Validate pack-owned request headers against the host header rules.
/// Returns canonical-lower name -> value on success.
fn validate_pack_headers(
    headers: Option<&BTreeMap<String, String>>,
    extended_capable: bool,
) -> Result<BTreeMap<String, String>, FetchDeny> {
    let Some(headers) = headers else {
        return Ok(BTreeMap::new());
    };
    if headers.len() > MAX_HEADER_COUNT {
        return Err(FetchDeny::fetch_failed("too many request headers"));
    }

    let mut validated = BTreeMap::new();
    let mut seen = HashSet::with_capacity(headers.len());
    for (name, value) in headers {
        let trimmed = name.trim();
        let canonical = canonical_header_name(trimmed);
        let lower = trimmed.to_lowercase();
        if canonical.is_empty() || !is_http_token(trimmed) {
            return Err(FetchDeny::fetch_failed("invalid request header name"));
        }
        if !seen.insert(lower.clone()) {
            return Err(FetchDeny::fetch_failed(
                "request header names must be unique after canonicalization",
            ));
        }
        if pack_header_needs_extended(&lower) {
            // Privileged names bypass the name-level secret heuristic:
            // business x-* token headers are the legitimate use of the
            // extended channel, narrowed only by the deny list.
            if is_denied_extended_name(&lower) {
                return Err(FetchDeny::fetch_failed(format!(
                    "request header {canonical:?} is not allowed"
                )));
            }
            if !extended_capable {
                return Err(FetchDeny::fetch_failed(format!(
                    "request header {canonical:?} requires the extended fetch capability"
                )));
            }
            if value.len() > MAX_HEADER_VALUE_BYTES {
                return Err(FetchDeny::fetch_failed(format!(
                    "request header {canonical:?} value is too large"
                )));
            }
            if string_contains_control(value) {
                return Err(FetchDeny::fetch_failed(format!(
                    "request header {canonical:?} value contains control bytes"
                )));
            }
            if lower == "authorization" && !is_valid_pack_owned_authorization(value) {
                return Err(FetchDeny::fetch_failed(
                    "request header \"Authorization\" value must be a scheme followed by credentials",
                ));
            }
        } else {
            if is_secret_header_name(&lower) || is_forbidden_pack_header(&lower) {
                return Err(FetchDeny::fetch_failed(format!(
                    "request header {canonical:?} is not allowed"
                )));
            }
            if !SAFE_REQUEST_HEADERS.contains(&lower.as_str()) {
                return Err(FetchDeny::fetch_failed(format!(
                    "request header {canonical:?} is not allowed"
                )));
            }
            if value.len() > MAX_HEADER_VALUE_BYTES {
                return Err(FetchDeny::fetch_failed(format!(
                    "request header {canonical:?} value is too large"
                )));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(FetchDeny::fetch_failed(format!(
                    "request header {canonical:?} value contains CR/LF"
                )));
            }
        }
        validated.insert(lower, value.clone());
    }

    Ok(validated)
}

/// Mirror of the host raw/ref mode determination: a url never combines with
/// ref-mode fields; refs must come as a validated pair under an alias
/// manifest; everything else is malformed.
fn determine_request_mode(
    manifest: &Manifest,
    req: &HostHTTPFetchRequest,
) -> Result<RequestMode, FetchDeny> {
    let has_url = req.url.as_deref().is_some_and(|u| !u.is_empty());
    let has_broker_ref = req
        .broker_policy_ref
        .as_deref()
        .is_some_and(|r| !r.is_empty());
    let has_endpoint_ref = req.endpoint_ref.as_deref().is_some_and(|r| !r.is_empty());
    let has_params = req.params.as_ref().is_some_and(|p| !p.is_empty());
    let has_any_ref_field = has_broker_ref || has_endpoint_ref || has_params;
    let alias = is_alias_manifest(manifest);

    if has_url && has_any_ref_field {
        return Err(FetchDeny::invalid_request(
            "raw url must not be combined with ref-mode fields",
        ));
    }
    if has_url {
        if alias {
            return Err(FetchDeny::invalid_request(
                "alias manifest host imports must use broker_policy_ref and endpoint_ref",
            ));
        }
        return Ok(RequestMode::Raw);
    }
    if has_broker_ref && has_endpoint_ref {
        if !alias {
            return Err(FetchDeny::invalid_request(
                "ref-mode host imports require an alias manifest",
            ));
        }
        if let Err(e) = validate_opaque_policy_ref(
            "broker_policy_ref",
            req.broker_policy_ref.as_deref().unwrap_or_default(),
        ) {
            return Err(FetchDeny::invalid_request(e.to_string()));
        }
        if let Err(e) = validate_opaque_policy_ref(
            "endpoint_ref",
            req.endpoint_ref.as_deref().unwrap_or_default(),
        ) {
            return Err(FetchDeny::invalid_request(e.to_string()));
        }
        if let Some(params) = req.params.as_ref().filter(|p| !p.is_empty()) {
            validate_ref_params(params)?;
        }
        // The declared broker policy refs are the closest local analog of the
        // host-side policy resolution: unknown refs are denied, not malformed.
        let declared = manifest.broker_policy_refs.as_deref().unwrap_or(&[]);
        if !declared
            .iter()
            .any(|r| r == req.broker_policy_ref.as_deref().unwrap_or_default())
        {
            return Err(FetchDeny::policy_denied(
                "host policy endpoint is not available",
            ));
        }
        return Ok(RequestMode::Ref);
    }

    Err(FetchDeny::invalid_request(
        "host import request must provide either legacy url or broker_policy_ref with endpoint_ref",
    ))
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Redirect decision for a single hop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HopAction {
    Deliver,
    Follow(Url),
    Deny,
}

/// Classify a received response: non-redirect statuses deliver; extended
/// requests are single-hop and deny any redirect; basic requests follow at
/// most REDIRECT_LIMIT hops and require a resolvable Location.
fn classify_response(
    status: u16,
    location: Option<&str>,
    base: &Url,
    wants_extended: bool,
    redirects: u32,
) -> HopAction {
    if !is_redirect_status(status) {
        return HopAction::Deliver;
    }
    if wants_extended {
        return HopAction::Deny;
    }
    if redirects >= REDIRECT_LIMIT {
        return HopAction::Deny;
    }
    let location = location.unwrap_or_default();
    if location.is_empty() {
        return HopAction::Deny;
    }
    match base.join(location) {
        Ok(next) => HopAction::Follow(next),
        Err(_) => HopAction::Deny,
    }
}

/// Shared egress gate for the initial request and every redirect hop, in both
/// mock and live dispatch: HTTP(S)-only, no userinfo (including the empty
/// `http://@host/` form), a present domain host (no IP literals, trailing
/// dots, or escapes), the manifest domain allowlist, plus HTTPS whenever the
/// hop is extended or carries injected credentials. All failures collapse to
/// a broker-layer fetch denial.
pub(crate) fn check_hop_target(
    raw_url: &str,
    manifest: &Manifest,
    wants_extended: bool,
    has_auth: bool,
) -> Result<Url, FetchDeny> {
    let deny = || FetchDeny::fetch_failed("request target is not allowed by manifest policy");
    // Require an explicit `://` separator: the url crate normalizes
    // `https:example.com` into a host-bearing URL the Go gate would reject.
    let Some((_, after_scheme)) = raw_url.split_once("://") else {
        return Err(deny());
    };
    let parsed = Url::parse(raw_url).map_err(|_| deny())?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(deny());
    }
    // Reject userinfo and escaped-authority forms the parser normalizes away
    // (e.g. `http://@host/`, `https://%65xample.com/`). The authority ends at
    // the first path/query/fragment delimiter so `?q=a@b` is not misread.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || authority.contains('@')
        || authority.contains('%')
    {
        return Err(deny());
    }
    let host = parsed.host_str().unwrap_or_default();
    if host.is_empty() || host.ends_with('.') {
        return Err(deny());
    }
    if matches!(parsed.host(), Some(Host::Ipv4(_)) | Some(Host::Ipv6(_))) {
        return Err(deny());
    }
    match manifest.allows_url(raw_url) {
        Ok(true) => {}
        _ => return Err(deny()),
    }
    if wants_extended && scheme != "https" {
        return Err(deny());
    }
    if has_auth && scheme != "https" {
        return Err(deny());
    }
    Ok(parsed)
}

/// Effective per-fetch timeout: smallest positive of request, manifest, and
/// the 10s policy maximum; falls back to the 5s default.
fn effective_timeout(req: &HostHTTPFetchRequest, manifest: &Manifest) -> Duration {
    let millis = [
        req.timeout_millis.filter(|v| *v > 0).map(|v| v as u64),
        (manifest.resource_limits.timeout_millis > 0)
            .then_some(manifest.resource_limits.timeout_millis),
        Some(MAX_FETCH_TIMEOUT_MILLIS),
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(DEFAULT_FETCH_TIMEOUT_MILLIS);
    Duration::from_millis(millis)
}

/// Effective response body cap: smallest positive of request, manifest, and
/// the 10MiB policy maximum. Bodies beyond the wire cap surface as
/// `response_too_large` at encode time, not a transport failure.
fn effective_max_response_bytes(req: &HostHTTPFetchRequest, manifest: &Manifest) -> usize {
    [
        req.max_response_bytes.filter(|v| *v > 0),
        (manifest.resource_limits.max_response_bytes > 0)
            .then_some(manifest.resource_limits.max_response_bytes),
        Some(MAX_RESPONSE_BYTES),
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(MAX_RESPONSE_BYTES) as usize
}

/// Values that must never be reflected back to the guest: pack-owned
/// privileged header values (plus Authorization credentials segment) and
/// host-injected auth secrets (plus their name=value form).
fn collect_known_secrets(
    shape: &ValidatedFetchShape,
    auth_header: Option<(&str, &str)>,
) -> Vec<String> {
    let mut secrets = Vec::new();
    for (name, value) in &shape.validated_headers {
        if !pack_header_needs_extended(name) {
            continue;
        }
        if !value.is_empty() {
            secrets.push(value.clone());
        }
        if name == "authorization" {
            if let Some((_, credentials)) = value.split_once(' ') {
                let credentials = credentials.trim();
                if !credentials.is_empty() {
                    secrets.push(credentials.to_string());
                }
            }
        }
    }
    if let Some((name, value)) = auth_header {
        if !value.is_empty() {
            secrets.push(value.to_string());
            secrets.push(format!("{name}={value}"));
        }
    }
    secrets
}

/// Whether any tracked secret (>= 8 bytes) appears in the response body or
/// in the safe response headers exposed to the guest.
fn contains_secret_reflection(
    body: &[u8],
    headers: &BTreeMap<String, Vec<String>>,
    secrets: &[&str],
) -> bool {
    for secret in secrets {
        if body
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
        {
            return true;
        }
        for values in headers.values() {
            if values.iter().any(|value| value.contains(secret)) {
                return true;
            }
        }
    }
    false
}

/// IP restriction / SSRF prevention checker.
pub fn is_restricted_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_restricted_ipv4(ipv4),
        IpAddr::V6(ipv6) => {
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                is_restricted_ipv4(ipv4)
            } else {
                is_restricted_ipv6(ipv6)
            }
        }
    }
}

fn is_restricted_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_loopback() // 127.0.0.0/8
        || ip.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local() // 169.254.0.0/16
        || ip.is_multicast() // 224.0.0.0/4
        || ip.is_broadcast() // 255.255.255.255
        || octets[0] == 0 // Current network (0.0.0.0/8)
        // Carrier-grade NAT (100.64.0.0/10)
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)
        // IETF protocol assignments (192.0.0.0/24)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        // Documentation TEST-NET-1 (192.0.2.0/24)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        // 6to4 relay anycast (192.88.99.0/24)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        // Benchmark (198.18.0.0/15)
        || (octets[0] == 198 && (octets[1] & 0xFE) == 18)
        // Documentation TEST-NET-2 (198.51.100.0/24)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        // Documentation TEST-NET-3 (203.0.113.0/24)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        // Reserved (240.0.0.0/4)
        || (octets[0] >= 240)
}

fn is_restricted_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback() // ::1
        || ip.is_unspecified() // ::
        || ip.is_multicast() // ff00::/8
        // IPv4-IPv6 translation (64:ff9b::/96)
        || (segments[0] == 0x0064
            && segments[1] == 0xff9b
            && segments[2..6].iter().all(|segment| *segment == 0))
        // Local-use IPv4-IPv6 translation (64:ff9b:1::/48)
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
        // Discard-only prefix (100::/64)
        || (segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0))
        // IETF protocol assignments (2001::/23)
        || (segments[0] == 0x2001 && (segments[1] & 0xfe00) == 0)
        // Benchmarking (2001:2::/48)
        || (segments[0] == 0x2001 && segments[1] == 0x0002)
        // Documentation (2001:db8::/32)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        // 6to4 (2002::/16)
        || segments[0] == 0x2002
        // Unique Local (fc00::/7)
        || ((segments[0] & 0xfe00) == 0xfc00)
        // Link-Local Unicast (fe80::/10)
        || ((segments[0] & 0xffc0) == 0xfe80)
}

const SSRF_BLOCKED_MARKER: &str = "goaria_ssrf_blocked";

#[derive(Debug, Clone, Copy, Default)]
struct PublicOnlyResolver;

impl ureq::Resolver for PublicOnlyResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        let addresses: Vec<_> = netloc.to_socket_addrs()?.collect();
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("host '{netloc}' resolved to no IP addresses"),
            ));
        }
        if let Some(restricted) = addresses
            .iter()
            .find(|address| is_restricted_ip(address.ip()))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{SSRF_BLOCKED_MARKER}: resolved IP '{}' is not public",
                    restricted.ip()
                ),
            ));
        }

        Ok(addresses)
    }
}

/// Pattern for matching requested URLs against mock rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlPattern {
    Exact(String),
    Prefix(String),
}

impl UrlPattern {
    pub fn matches(&self, url: &str) -> bool {
        match self {
            Self::Exact(target) => url == target,
            Self::Prefix(prefix) => url.starts_with(prefix),
        }
    }
}

/// Request-side assertions attached to a mock rule. Every declared field
/// must match the incoming request (subset matching); undeclared fields are
/// not asserted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MockRequestExpectation {
    /// Case-insensitive method match against the normalized request method.
    pub method: Option<String>,
    /// Canonical-lower header name -> exact required value.
    pub headers: BTreeMap<String, String>,
    /// Decoded byte equality against the request body.
    pub body_base64: Option<String>,
    /// Exact broker_policy_ref match (ref-mode requests).
    pub broker_policy_ref: Option<String>,
    /// Exact endpoint_ref match (ref-mode requests).
    pub endpoint_ref: Option<String>,
    /// Exact omit_browser_context flag match (absent request field reads as false).
    pub omit_browser_context: Option<bool>,
}

/// Mock rule for simulating broker responses during tests.
#[derive(Debug, Clone)]
pub struct MockBrokerRule {
    pub pattern: UrlPattern,
    pub status_code: i32,
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: Vec<u8>,
    pub expect: Option<MockRequestExpectation>,
}

impl MockBrokerRule {
    fn matches_request(&self, req: &HostHTTPFetchRequest, shape: &ValidatedFetchShape) -> bool {
        match &req.url {
            Some(url) => {
                if !self.pattern.matches(url) {
                    return false;
                }
            }
            None => {
                // URL-less ref-mode requests can only match a rule that
                // declares at least one ref expectation.
                match &self.expect {
                    Some(expect)
                        if expect.broker_policy_ref.is_some() || expect.endpoint_ref.is_some() => {}
                    _ => return false,
                }
            }
        }
        let Some(expect) = &self.expect else {
            return true;
        };
        if let Some(method) = &expect.method {
            if !method.trim().eq_ignore_ascii_case(&shape.method) {
                return false;
            }
        }
        for (name, expected) in &expect.headers {
            let lower = name.trim().to_lowercase();
            match shape.validated_headers.get(&lower) {
                Some(actual) if actual == expected => {}
                _ => return false,
            }
        }
        if let Some(body_base64) = &expect.body_base64 {
            match base64::engine::general_purpose::STANDARD.decode(body_base64) {
                Ok(expected) if expected == shape.body => {}
                _ => return false,
            }
        }
        if let Some(broker_policy_ref) = &expect.broker_policy_ref {
            if req.broker_policy_ref.as_deref() != Some(broker_policy_ref.as_str()) {
                return false;
            }
        }
        if let Some(endpoint_ref) = &expect.endpoint_ref {
            if req.endpoint_ref.as_deref() != Some(endpoint_ref.as_str()) {
                return false;
            }
        }
        if let Some(expected) = expect.omit_browser_context {
            if req.omit_browser_context.unwrap_or(false) != expected {
                return false;
            }
        }
        true
    }
}

/// In-memory mock broker for deterministic testing and unit test suites.
#[derive(Debug, Clone, Default)]
pub struct MockBroker {
    rules: Vec<MockBrokerRule>,
}

impl MockBroker {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: MockBrokerRule) {
        self.rules.push(rule);
    }

    pub fn resolve(
        &self,
        req: &HostHTTPFetchRequest,
        shape: &ValidatedFetchShape,
        auth_header: Option<(&str, &str)>,
        manifest: &Manifest,
    ) -> Option<HostHTTPFetchResponse> {
        let known_secrets = collect_known_secrets(shape, auth_header);
        let tracked: Vec<&str> = known_secrets.iter().map(String::as_str).collect();
        for rule in &self.rules {
            if rule.matches_request(req, shape) {
                // The fixture body obeys the same transport cap a live
                // response would hit.
                if rule.body.len() > effective_max_response_bytes(req, manifest) {
                    return Some(broker_failed_response("fetch_failed"));
                }
                // Only the safe response-header allowlist reaches the guest,
                // under canonical names, with secrets redacted — same egress
                // contract as a live response. Raw values feed the
                // reflection gate below.
                let mut headers = BTreeMap::new();
                for (name, values) in &rule.headers {
                    let lower = name.trim().to_lowercase();
                    if !SAFE_RESPONSE_HEADERS.contains(&lower.as_str())
                        || is_secret_header_name(&lower)
                    {
                        continue;
                    }
                    headers.insert(canonical_header_name(&lower), values.clone());
                }
                // A fixture echoing a tracked secret is denied whole, like a
                // live response tripping the reflection gate.
                if contains_secret_reflection(&rule.body, &headers, &tracked) {
                    return Some(broker_failed_response("fetch_failed"));
                }
                for values in headers.values_mut() {
                    for value in values.iter_mut() {
                        *value = redact_sensitive(value, &known_secrets);
                    }
                }
                let final_url = req
                    .url
                    .as_deref()
                    .map(|url| redact_sensitive(url, &known_secrets));
                // The wire contract reports ok:true for any delivered status;
                // ref-mode hits carry no final_url.
                return Some(HostHTTPFetchResponse {
                    ok: true,
                    status_code: Some(rule.status_code),
                    final_url,
                    headers: (!headers.is_empty()).then_some(headers),
                    body_base64: (!rule.body.is_empty())
                        .then(|| base64::engine::general_purpose::STANDARD.encode(&rule.body)),
                    error_code: None,
                    message: None,
                });
            }
        }

        None
    }
}

/// Live HTTP network broker using ureq for interactive `run` and live integration testing.
#[derive(Debug, Clone)]
pub struct LiveBroker {
    agent: ureq::Agent,
}

impl Default for LiveBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveBroker {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .resolver(PublicOnlyResolver)
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10))
            .redirects(0) // Prevent blind redirection and redirect-based SSRF
            .build();
        Self { agent }
    }

    /// Executes the request, enforcing per-hop URL/SSRF/https checks, the
    /// response byte cap, injected auth, and secret-reflection guards.
    /// `manifest` is needed per hop so redirect targets re-run domain policy.
    ///
    /// Callers must route requests through `HostBroker::handle_fetch` so the
    /// capability, shape, header, and mode gates run first; calling this
    /// directly with a caller-built shape bypasses those checks.
    pub fn fetch(
        &self,
        req: &HostHTTPFetchRequest,
        shape: &ValidatedFetchShape,
        auth_header: Option<(&str, &str)>,
        manifest: &Manifest,
    ) -> HostHTTPFetchResponse {
        let deny_code: &'static str = if opt_nonempty(&req.auth_profile_ref).is_some() {
            "authenticated_fetch_failed"
        } else {
            "fetch_failed"
        };

        let Some(raw_url) = req.url.as_deref() else {
            return HostHTTPFetchResponse {
                ok: false,
                error_code: Some("ref_mode_not_supported_in_live_runner".to_string()),
                message: Some(
                    "Policy/Endpoint ref mode requires MockBroker in local tests or external broker gateway in production host"
                        .to_string(),
                ),
                ..Default::default()
            };
        };

        let deadline = Instant::now() + effective_timeout(req, manifest);
        let max_bytes = effective_max_response_bytes(req, manifest);
        let known_secrets = collect_known_secrets(shape, auth_header);

        let mut current_url = raw_url.to_string();
        let mut redirects: u32 = 0;
        loop {
            // Per-hop egress gate: scheme/userinfo/host/manifest/https checks
            // re-run on every redirect target (injected credentials require
            // HTTPS on the hop they are attached to).
            let parsed = match check_hop_target(
                &current_url,
                manifest,
                shape.wants_extended,
                auth_header.is_some(),
            ) {
                Ok(parsed) => parsed,
                Err(_) => return broker_failed_response(deny_code),
            };

            let mut request = self.agent.request(&shape.method, &current_url);
            // Host-controlled: ask for identity so bodies stay inspectable;
            // a non-identity response is denied after read regardless.
            request = request.set("Accept-Encoding", "identity");
            for (name, value) in &shape.validated_headers {
                request = request.set(&canonical_header_name(name), value);
            }
            if let Some((name, value)) = auth_header {
                request = request.set(name, value);
            }
            match deadline.checked_duration_since(Instant::now()) {
                Some(remaining) if !remaining.is_zero() => {
                    request = request.timeout(remaining);
                }
                _ => return broker_failed_response(deny_code),
            }

            let result = if shape.body.is_empty() {
                request.call()
            } else {
                request.send_bytes(&shape.body)
            };
            let response = match result {
                Ok(response) => response,
                // 4xx/5xx are delivered responses, not fetch failures.
                Err(ureq::Error::Status(_, response)) => response,
                Err(ureq::Error::Transport(_)) => return broker_failed_response(deny_code),
            };

            match classify_response(
                response.status(),
                response.header("location"),
                &parsed,
                shape.wants_extended,
                redirects,
            ) {
                HopAction::Deny => return broker_failed_response(deny_code),
                HopAction::Follow(next) => {
                    redirects += 1;
                    current_url = next.to_string();
                }
                HopAction::Deliver => {
                    return process_response(
                        response,
                        &current_url,
                        max_bytes,
                        &known_secrets,
                        deny_code,
                    );
                }
            }
        }
    }
}

/// Content-Encoding is opaque when, after trim+case folding, it is neither
/// absent/empty nor `identity`; secret-carrying bodies then fail closed.
fn content_encoding_is_opaque(raw: Option<&str>) -> bool {
    raw.map(|v| v.trim().to_lowercase())
        .is_some_and(|enc| !enc.is_empty() && enc != "identity")
}

/// Shared response materialization for a delivered hop: expose only safe
/// non-secret response headers, stream the body under the byte cap, report
/// `ok:true` for any status, and fail closed when a tracked secret would be
/// reflected back to the guest.
fn process_response(
    response: ureq::Response,
    hop_url: &str,
    max_bytes: usize,
    known_secrets: &[String],
    deny_code: &'static str,
) -> HostHTTPFetchResponse {
    let status = response.status() as i32;
    // Report the URL spelling we requested, not the transport's normalized form.
    let final_url = redact_sensitive(hop_url, known_secrets);

    // Raw values first: the reflection gate must see what the server
    // actually echoed, not the already-redacted egress form.
    let mut resp_headers = BTreeMap::new();
    for safe_header in SAFE_RESPONSE_HEADERS {
        if is_secret_header_name(safe_header) {
            continue;
        }
        if let Some(val) = response.header(safe_header) {
            resp_headers.insert(canonical_header_name(safe_header), vec![val.to_string()]);
        }
    }

    let tracked: Vec<&str> = known_secrets.iter().map(String::as_str).collect();
    let opaque_encoding = content_encoding_is_opaque(response.header("content-encoding"));

    let mut reader = response.into_reader();
    let mut body_bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if body_bytes.len() + n > max_bytes {
                    // A capped body is a broker fetch failure; the
                    // response_too_large category is reserved for the
                    // encoded host-import response exceeding its wire cap.
                    return broker_failed_response(deny_code);
                }
                body_bytes.extend_from_slice(&chunk[..n]);
            }
            Err(_) => return broker_failed_response(deny_code),
        }
    }

    // The runner cannot decode opaque encodings; delivering compressed
    // bytes to the guest is worse than a clean denial.
    if !body_bytes.is_empty() && opaque_encoding {
        return broker_failed_response(deny_code);
    }
    if !tracked.is_empty() && contains_secret_reflection(&body_bytes, &resp_headers, &tracked) {
        return broker_failed_response(deny_code);
    }
    for values in resp_headers.values_mut() {
        for value in values.iter_mut() {
            *value = redact_sensitive(value, known_secrets);
        }
    }

    HostHTTPFetchResponse {
        ok: true,
        status_code: Some(status),
        final_url: Some(final_url),
        headers: (!resp_headers.is_empty()).then_some(resp_headers),
        body_base64: (!body_bytes.is_empty())
            .then(|| base64::engine::general_purpose::STANDARD.encode(&body_bytes)),
        error_code: None,
        message: None,
    }
}

/// Deterministic host-time value served to mock runs; keeps fixtures and
/// pack logic (e.g. website-token derivation) reproducible.
pub const MOCK_HOST_TIME_SECS: i64 = 1_800_000_000;

/// Run-local record of pack-registered bearer tokens keyed by the opaque
/// refs handed back to the guest. Refs are minted deterministically
/// (`dar-` + 32-hex counter) so mock runs stay reproducible; the token
/// values never leave the host side except as materialized headers.
#[derive(Debug, Clone, Default)]
pub struct DownloadAuthRegistry {
    counter: u64,
    entries: BTreeMap<String, String>,
}

/// Host-mirrored limits: at most 8 registrations per invocation and 256
/// entries registry-wide. The run-local registry is invocation-scoped, so
/// its entry count is also the per-invocation count.
const DOWNLOAD_AUTH_MAX_PER_INVOCATION: usize = 8;
const DOWNLOAD_AUTH_REGISTRY_CAPACITY: usize = 256;

impl DownloadAuthRegistry {
    fn register(&mut self, token: &str) -> Result<String, &'static str> {
        if self.entries.len() >= DOWNLOAD_AUTH_MAX_PER_INVOCATION
            || self.entries.len() >= DOWNLOAD_AUTH_REGISTRY_CAPACITY
        {
            return Err("download auth registry is full");
        }
        self.counter += 1;
        let reference = format!("dar-{:032x}", self.counter);
        self.entries.insert(reference.clone(), token.to_string());
        Ok(reference)
    }

    /// True when `reference` was minted during this run.
    pub fn contains_ref(&self, reference: &str) -> bool {
        self.entries.contains_key(reference)
    }

    /// True when `value` is one of the raw tokens stored this run — used to
    /// catch a guest echoing the token itself back as an item ref.
    pub fn is_registered_token(&self, value: &str) -> bool {
        self.entries.values().any(|token| token == value)
    }

    /// All refs minted during this run, in registration order.
    pub fn registered_refs(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

/// Mirror of the host token contract: the materialized
/// "Authorization: Bearer <token>" line must fit the 8192-byte aria2
/// header-line cap, so the 22-byte prefix is reserved from the token budget.
const DOWNLOAD_AUTH_TOKEN_MAX_BYTES: usize = 8192 - "Authorization: Bearer ".len();

/// 1..=8170 bytes, no CR/LF, and never already prefixed with a bearer
/// scheme (which would double-prefix the materialized header).
fn validate_download_auth_token(token: &str) -> Result<(), &'static str> {
    if token.is_empty() || token.len() > DOWNLOAD_AUTH_TOKEN_MAX_BYTES {
        return Err("token length must be between 1 and 8170 bytes");
    }
    if token.contains('\r') || token.contains('\n') {
        return Err("token must not contain CR/LF");
    }
    if token.len() >= "bearer ".len() && token[.."bearer ".len()].eq_ignore_ascii_case("bearer ") {
        return Err("token must not include a bearer scheme prefix");
    }
    Ok(())
}

/// Top-level broker dispatch enum.
#[derive(Debug, Clone)]
pub enum HostBroker {
    Mock(MockBroker),
    Live(LiveBroker),
    Disabled,
}

impl HostBroker {
    pub fn handle_fetch(
        &self,
        manifest: &Manifest,
        budget: &mut HostCallBudget,
        req: HostHTTPFetchRequest,
        auth_provider: &AuthProvider,
    ) -> HostHTTPFetchResponse {
        // 1. Consume budget
        if let Err(e) = budget.consume() {
            return HostHTTPFetchResponse {
                ok: false,
                error_code: Some("budget_exhausted".to_string()),
                message: Some(e.to_string()),
                ..Default::default()
            };
        }

        // 2. Request JSON decode happens in the wasm engine before dispatch;
        //    a decode failure there produces an invalid_request response.

        // 3. Negative limits are malformed input.
        if req.timeout_millis.is_some_and(|v| v < 0) {
            return invalid_request_response("timeout_millis must not be negative");
        }
        if req.max_response_bytes.is_some_and(|v| v < 0) {
            return invalid_request_response("max_response_bytes must not be negative");
        }

        // 4. Local shape checks (auth slug, method, body, extended+auth exclusion)
        let mut shape = match validate_extended_fetch_shape(&req) {
            Ok(shape) => shape,
            Err(deny) => return deny.into_response(),
        };

        // 5. Raw/ref mode determination
        let mode = match determine_request_mode(manifest, &req) {
            Ok(mode) => mode,
            Err(deny) => return deny.into_response(),
        };

        // 6. Per-request capability recheck (manifest preflight is the primary gate)
        if !manifest.has_capability(CAPABILITY_HTTP_FETCH) {
            return policy_denied_response("pack does not have capability 'cap.http.fetch'");
        }

        // 7. Extended fetch features require the extended capability in both modes
        let extended_capable = manifest.has_capability(CAPABILITY_HTTP_FETCH_EXTENDED);
        if shape.wants_extended && !extended_capable {
            return policy_denied_response(
                "extended fetch features require the extended fetch capability",
            );
        }

        // 8. Auth profile requests fail inside the broker when the capability
        //    is absent, classifying as an authenticated fetch failure.
        if opt_nonempty(&req.auth_profile_ref).is_some()
            && !manifest.has_capability(CAPABILITY_AUTH_PROFILE)
        {
            return broker_failed_response("authenticated_fetch_failed");
        }

        // Broker-layer failures classify as authenticated when a profile is set
        let deny_code: &'static str = if opt_nonempty(&req.auth_profile_ref).is_some() {
            "authenticated_fetch_failed"
        } else {
            "fetch_failed"
        };

        // 8. Broker policy method allowlist (extended requires POST, which is
        //    already implied by this set)
        if !matches!(shape.method.as_str(), "GET" | "HEAD" | "POST") {
            return broker_failed_response(deny_code);
        }

        // 9. Header rules
        match validate_pack_headers(req.headers.as_ref(), extended_capable) {
            Ok(headers) => shape.validated_headers = headers,
            Err(_) => return broker_failed_response(deny_code),
        }

        // 10. Mode-specific pre-dispatch gates. Raw mode validates the
        // request target with the same hop-level egress rules the live path
        // applies per redirect (scheme, userinfo, host shape, IP literals,
        // manifest domains, and HTTPS for extended/auth hops).
        match mode {
            RequestMode::Raw => {
                let url = req.url.as_deref().unwrap_or_default();
                let has_auth = opt_nonempty(&req.auth_profile_ref).is_some();
                if check_hop_target(url, manifest, shape.wants_extended, has_auth).is_err() {
                    return broker_failed_response(deny_code);
                }
            }
            RequestMode::Ref => {}
        }

        // 11. Auth profile resolution (only basic fetch can reach this point;
        //     the capability gate already ran above). The resolved pair is
        //     reused on every hop — the local provider has no per-URL scope.
        let auth_holder = if let Some(profile_ref) = opt_nonempty(&req.auth_profile_ref) {
            match auth_provider.get_auth_header(profile_ref) {
                Some(header) => Some(header),
                None => return broker_failed_response("authenticated_fetch_failed"),
            }
        } else {
            None
        };
        let auth_header = auth_holder
            .as_ref()
            .map(|(name, value)| (name.as_str(), value.as_str()));

        // 12. Dispatch
        match self {
            Self::Mock(mock) => {
                if let Some(resp) = mock.resolve(&req, &shape, auth_header, manifest) {
                    resp
                } else {
                    HostHTTPFetchResponse {
                        ok: false,
                        error_code: Some("no_mock_match".to_string()),
                        message: Some(format!(
                            "no mock rule matched request for URL: {:?}",
                            req.url
                        )),
                        ..Default::default()
                    }
                }
            }
            Self::Live(live) => live.fetch(&req, &shape, auth_header, manifest),
            Self::Disabled => HostHTTPFetchResponse {
                ok: false,
                error_code: Some("broker_disabled".to_string()),
                message: Some("host network broker is disabled".to_string()),
                ..Default::default()
            },
        }
    }

    /// Handle goaria_host.register_download_auth: budget → kind/token
    /// checks → capability → mint an opaque ref recorded in the run-local
    /// registry. Both Mock and Live mint the same deterministic shape.
    pub fn handle_register_download_auth(
        &self,
        manifest: &Manifest,
        budget: &mut HostCallBudget,
        req: HostRegisterDownloadAuthRequest,
        registry: &mut DownloadAuthRegistry,
    ) -> HostRegisterDownloadAuthResponse {
        if let Err(e) = budget.consume() {
            return HostRegisterDownloadAuthResponse {
                ok: false,
                error_code: Some("budget_exhausted".to_string()),
                message: Some(e.to_string()),
                ..Default::default()
            };
        }
        if req.kind != "bearer" {
            return HostRegisterDownloadAuthResponse {
                ok: false,
                error_code: Some("invalid_request".to_string()),
                message: Some("kind must be bearer".to_string()),
                ..Default::default()
            };
        }
        if let Err(message) = validate_download_auth_token(&req.token) {
            return HostRegisterDownloadAuthResponse {
                ok: false,
                error_code: Some("invalid_request".to_string()),
                message: Some(message.to_string()),
                ..Default::default()
            };
        }
        if !manifest.has_capability(CAPABILITY_DOWNLOAD_AUTH) {
            return HostRegisterDownloadAuthResponse {
                ok: false,
                error_code: Some("policy_denied".to_string()),
                message: Some("pack is not allowed to register download auth".to_string()),
                ..Default::default()
            };
        }
        if matches!(self, Self::Disabled) {
            return HostRegisterDownloadAuthResponse {
                ok: false,
                error_code: Some("not_configured".to_string()),
                message: Some("download auth registry is not configured".to_string()),
                ..Default::default()
            };
        }

        match registry.register(&req.token) {
            Ok(reference) => HostRegisterDownloadAuthResponse {
                ok: true,
                download_auth_ref: Some(reference),
                ..Default::default()
            },
            Err(message) => HostRegisterDownloadAuthResponse {
                ok: false,
                error_code: Some("registry_full".to_string()),
                message: Some(message.to_string()),
                ..Default::default()
            },
        }
    }

    /// Handle goaria_host.host_time: one budget unit per call, same frozen
    /// snapshot for the whole run. Mock serves the deterministic constant;
    /// every other mode serves the invocation snapshot — host_time needs
    /// no broker, so a Disabled broker still answers.
    pub fn handle_host_time(
        &self,
        budget: &mut HostCallBudget,
        snapshot_secs: i64,
    ) -> HostTimeResponse {
        if let Err(e) = budget.consume() {
            return HostTimeResponse {
                ok: false,
                error_code: Some("budget_exhausted".to_string()),
                message: Some(e.to_string()),
                ..Default::default()
            };
        }
        match self {
            Self::Mock(_) => HostTimeResponse {
                ok: true,
                unix_secs: Some(MOCK_HOST_TIME_SECS),
                ..Default::default()
            },
            Self::Live(_) | Self::Disabled => HostTimeResponse {
                ok: true,
                unix_secs: Some(snapshot_secs),
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_header_name, check_hop_target, classify_response, contains_secret_reflection,
        content_encoding_is_opaque, decode_extended_body, effective_max_response_bytes,
        effective_timeout, is_denied_extended_name, is_extended_body_content_type_allowed,
        is_http_token, is_valid_pack_owned_authorization, is_valid_profile_slug,
        normalize_fetch_method, redact_sensitive, validate_auth_profile_ref,
        validate_extended_fetch_shape, validate_pack_headers, validate_ref_params, HopAction,
        LiveBroker, MockBroker, MockBrokerRule, PublicOnlyResolver, UrlPattern,
        ValidatedFetchShape, SSRF_BLOCKED_MARKER,
    };
    use crate::manifest::{DomainRule, Manifest, ResourceLimits};
    use base64::Engine;
    use goaria_extractor_sdk::types::HostHTTPFetchRequest;
    use std::collections::BTreeMap;
    use std::time::Duration;
    use ureq::Resolver;
    use url::Url;

    fn manifest_with_domains(hosts: &[&str]) -> Manifest {
        Manifest {
            pack_id: "test-pack".to_string(),
            pack_version: "0.1.0".to_string(),
            abi_version: 1,
            description: None,
            capabilities: vec![],
            domains: Some(
                hosts
                    .iter()
                    .map(|host| DomainRule {
                        host: host.to_string(),
                        include_subdomains: false,
                    })
                    .collect(),
            ),
            domain_policy_refs: None,
            broker_policy_refs: None,
            resource_limits: ResourceLimits::default(),
            payload_sha256: None,
        }
    }

    #[test]
    fn transport_resolver_returns_only_validated_addresses() {
        let resolver = PublicOnlyResolver;
        let public = resolver.resolve("8.8.8.8:443").unwrap();
        assert_eq!(public.len(), 1);
        assert_eq!(public[0].ip().to_string(), "8.8.8.8");

        let error = resolver.resolve("127.0.0.1:80").unwrap_err();
        assert!(error.to_string().contains(SSRF_BLOCKED_MARKER));
    }

    #[test]
    fn live_agent_blocks_dns_results_at_connection_time() {
        let manifest = manifest_with_domains(&["localhost"]);
        let req = HostHTTPFetchRequest {
            url: Some("http://localhost/".to_string()),
            ..Default::default()
        };
        let shape = ValidatedFetchShape {
            method: "GET".to_string(),
            ..Default::default()
        };
        let response = LiveBroker::new().fetch(&req, &shape, None, &manifest);
        assert!(!response.ok);
        assert_eq!(response.error_code.as_deref(), Some("fetch_failed"));
        assert_eq!(response.message.as_deref(), Some("fetch failed"));
    }

    #[test]
    fn live_fetch_reports_ref_mode_as_unsupported() {
        let manifest = manifest_with_domains(&[]);
        let req = HostHTTPFetchRequest {
            broker_policy_ref: Some("br-main".to_string()),
            endpoint_ref: Some("ep-main".to_string()),
            ..Default::default()
        };
        let shape = ValidatedFetchShape::default();
        let response = LiveBroker::new().fetch(&req, &shape, None, &manifest);
        assert_eq!(
            response.error_code.as_deref(),
            Some("ref_mode_not_supported_in_live_runner")
        );
    }

    #[test]
    fn mock_resolve_redacts_egress_and_denies_secret_echo() {
        let mut broker = MockBroker::new();
        let mut headers = BTreeMap::new();
        headers.insert("etag".to_string(), vec!["plain-etag".to_string()]);
        broker.add_rule(MockBrokerRule {
            pattern: UrlPattern::Exact("https://example.com/?sig=tok123456".to_string()),
            status_code: 200,
            headers,
            body: b"plain body".to_vec(),
            expect: None,
        });
        let req = HostHTTPFetchRequest {
            url: Some("https://example.com/?sig=tok123456".to_string()),
            ..Default::default()
        };
        let shape = ValidatedFetchShape {
            method: "GET".to_string(),
            ..Default::default()
        };
        let manifest = manifest_with_domains(&["example.com"]);
        let auth = Some(("Authorization", "tok123456"));

        // Egress fields redact the credential; non-echoing fixtures deliver.
        let resp = broker.resolve(&req, &shape, auth, &manifest).unwrap();
        assert!(resp.ok, "unexpected deny: {:?}", resp);
        assert_eq!(
            resp.headers.as_ref().unwrap()["Etag"],
            vec!["plain-etag".to_string()]
        );
        assert_eq!(
            resp.final_url.as_deref(),
            Some("https://example.com/?sig=[REDACTED]")
        );

        // A fixture echoing a tracked secret is denied whole.
        let mut echo = MockBroker::new();
        echo.add_rule(MockBrokerRule {
            pattern: UrlPattern::Exact("https://example.com/?sig=tok123456".to_string()),
            status_code: 200,
            headers: BTreeMap::new(),
            body: b"echo tok123456 back".to_vec(),
            expect: None,
        });
        let denied = echo.resolve(&req, &shape, auth, &manifest).unwrap();
        assert!(!denied.ok);
        assert_eq!(denied.error_code.as_deref(), Some("fetch_failed"));

        // Fixture bodies beyond the effective cap deny like a live read.
        let mut capped = manifest_with_domains(&["example.com"]);
        capped.resource_limits.max_response_bytes = 4;
        let over = broker.resolve(&req, &shape, None, &capped).unwrap();
        assert!(!over.ok);
        assert_eq!(over.error_code.as_deref(), Some("fetch_failed"));
    }

    #[test]
    fn method_normalization_defaults_and_rejects() {
        assert_eq!(normalize_fetch_method("").unwrap(), "GET");
        assert_eq!(normalize_fetch_method(" post ").unwrap(), "POST");
        assert!(normalize_fetch_method("   ").is_err());
        assert!(normalize_fetch_method("G ET").is_err());
        assert!(normalize_fetch_method("GE\tT").is_err());
    }

    #[test]
    fn body_decode_is_strict_padded_base64() {
        assert!(decode_extended_body("").unwrap().is_empty());
        assert_eq!(decode_extended_body("aGVsbG8=").unwrap(), b"hello".to_vec());
        assert!(decode_extended_body("aGVsbG8=\n").is_err());
        assert!(decode_extended_body("aGVsbG8 =").is_err());
        assert!(decode_extended_body("aGVsbG8").is_err());
        assert!(decode_extended_body("%%%").is_err());
        let oversized = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 16 * 1024 + 1]);
        assert!(decode_extended_body(&oversized).is_err());
    }

    #[test]
    fn auth_profile_ref_slug_validation() {
        assert!(validate_auth_profile_ref("my-profile").is_ok());
        assert!(validate_auth_profile_ref("").is_err());
        assert!(validate_auth_profile_ref("-abc").is_err());
        assert!(validate_auth_profile_ref("abc-").is_err());
        assert!(validate_auth_profile_ref("Abc").is_err());
        assert!(validate_auth_profile_ref("a_b").is_err());
        assert!(validate_auth_profile_ref(&"a".repeat(65)).is_err());
    }

    #[test]
    fn pack_owned_authorization_shape() {
        assert!(is_valid_pack_owned_authorization("Bearer abc.def"));
        assert!(is_valid_pack_owned_authorization("Basic dGVzdA=="));
        assert!(!is_valid_pack_owned_authorization("Bearer"));
        assert!(!is_valid_pack_owned_authorization(" Bearer x"));
        assert!(!is_valid_pack_owned_authorization("Bearer x "));
        assert!(!is_valid_pack_owned_authorization("Bearer  x"));
        assert!(!is_valid_pack_owned_authorization("Bad(scheme) v"));
    }

    #[test]
    fn extended_body_content_type_rules() {
        assert!(is_extended_body_content_type_allowed("application/json"));
        assert!(is_extended_body_content_type_allowed(
            "application/json; charset=utf-8"
        ));
        assert!(is_extended_body_content_type_allowed(
            "application/x-www-form-urlencoded"
        ));
        assert!(!is_extended_body_content_type_allowed("text/plain"));
        assert!(!is_extended_body_content_type_allowed(
            "application/json; bad-param"
        ));
        assert!(!is_extended_body_content_type_allowed("application/json;"));
    }

    #[test]
    fn shape_requires_post_and_content_type_for_body() {
        let req = HostHTTPFetchRequest {
            method: Some("GET".to_string()),
            body_base64: Some("aGk=".to_string()),
            ..Default::default()
        };
        assert!(validate_extended_fetch_shape(&req).is_err());

        let req = HostHTTPFetchRequest {
            method: Some("POST".to_string()),
            body_base64: Some("aGk=".to_string()),
            ..Default::default()
        };
        assert!(validate_extended_fetch_shape(&req).is_err());

        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let req = HostHTTPFetchRequest {
            method: Some("POST".to_string()),
            headers: Some(headers),
            body_base64: Some("aGk=".to_string()),
            ..Default::default()
        };
        let shape = validate_extended_fetch_shape(&req).unwrap();
        assert_eq!(shape.method, "POST");
        assert_eq!(shape.body, b"hi");
        assert!(shape.wants_extended);
    }

    #[test]
    fn shape_marks_extended_features_and_auth_conflict() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Api-Version".to_string(), "1".to_string());
        let req = HostHTTPFetchRequest {
            headers: Some(headers),
            ..Default::default()
        };
        assert!(validate_extended_fetch_shape(&req).unwrap().wants_extended);

        let req = HostHTTPFetchRequest {
            method: Some("POST".to_string()),
            auth_profile_ref: Some("prof".to_string()),
            ..Default::default()
        };
        let err = validate_extended_fetch_shape(&req).unwrap_err();
        assert_eq!(err.error_code, "invalid_request");
    }

    #[test]
    fn denied_extended_names_cover_exact_and_prefix() {
        for name in [
            "x-forwarded-for",
            "x-real-ip",
            "x-client-cert",
            "x-client-cert-cn",
            "x-auth-user",
            "x-auth-user-extra",
            "x-ms-client-principal",
            "x-proxy-foo",
            "x-goaria-x",
            "x-amzn-oidc-sub",
            "x-goog-iap-jwt",
        ] {
            assert!(is_denied_extended_name(name), "{name} should be denied");
        }
        for name in ["x-user", "x-username", "x-uid", "x-amzn-mkt-token"] {
            assert!(!is_denied_extended_name(name), "{name} should be allowed");
        }
    }

    #[test]
    fn header_canonicalization_and_tokens() {
        assert_eq!(canonical_header_name("cONTENT-tYPE"), "Content-Type");
        assert!(is_http_token("Authorization"));
        assert!(!is_http_token(""));
        assert!(!is_http_token("bad name"));
        assert!(!is_http_token("bad(name)"));
        assert!(!is_http_token("bad\x7fname"));
    }

    #[test]
    fn pack_headers_reject_duplicates_and_forbidden() {
        // Canonical-collision duplicate names.
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_string(), "Bearer a".to_string());
        headers.insert("authorization".to_string(), "Bearer b".to_string());
        assert!(validate_pack_headers(Some(&headers), true).is_err());

        // Privileged header without extended capability.
        let mut headers = BTreeMap::new();
        headers.insert("X-User".to_string(), "u1".to_string());
        assert!(validate_pack_headers(Some(&headers), false).is_err());
        assert!(validate_pack_headers(Some(&headers), true).is_ok());

        // Forbidden / unsafe basic names.
        for name in [
            "Cookie",
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Proxy-Authorization",
            "Range",
            "Accept-Encoding",
        ] {
            let mut headers = BTreeMap::new();
            headers.insert(name.to_string(), "v".to_string());
            assert!(
                validate_pack_headers(Some(&headers), true).is_err(),
                "{name} should be rejected"
            );
        }

        // Safe names pass; control bytes are rejected.
        let mut headers = BTreeMap::new();
        headers.insert("Accept".to_string(), "text/plain".to_string());
        headers.insert("Referer".to_string(), "https://example.com/".to_string());
        assert!(validate_pack_headers(Some(&headers), false).is_ok());

        let mut headers = BTreeMap::new();
        headers.insert("Accept".to_string(), "a\rb".to_string());
        assert!(validate_pack_headers(Some(&headers), false).is_err());
        let mut headers = BTreeMap::new();
        headers.insert("X-Tab".to_string(), "a\tb".to_string());
        assert!(validate_pack_headers(Some(&headers), true).is_err());
    }

    #[test]
    fn pack_headers_enforce_count_and_value_caps() {
        let headers: BTreeMap<String, String> = (0..17)
            .map(|i| (format!("x-h{i:02}"), "v".to_string()))
            .collect();
        assert!(validate_pack_headers(Some(&headers), true).is_err());

        let mut headers = BTreeMap::new();
        headers.insert("x-big".to_string(), "v".repeat(1025));
        assert!(validate_pack_headers(Some(&headers), true).is_err());
    }

    #[test]
    fn response_classification_hops() {
        let base = Url::parse("https://example.com/a").unwrap();
        assert_eq!(
            classify_response(200, None, &base, false, 0),
            HopAction::Deliver
        );
        assert_eq!(
            classify_response(301, Some("/b"), &base, true, 0),
            HopAction::Deny
        );
        assert_eq!(
            classify_response(301, Some("/b"), &base, false, 5),
            HopAction::Deny
        );
        assert_eq!(
            classify_response(302, None, &base, false, 0),
            HopAction::Deny
        );
        assert_eq!(
            classify_response(302, Some("/b"), &base, false, 0),
            HopAction::Follow(Url::parse("https://example.com/b").unwrap())
        );
        assert_eq!(
            classify_response(302, Some("http://[::1"), &base, false, 0),
            HopAction::Deny
        );
    }

    #[test]
    fn effective_limits_take_smallest_positive() {
        let mut manifest = manifest_with_domains(&[]);
        manifest.resource_limits.timeout_millis = 4_000;
        manifest.resource_limits.max_response_bytes = 64;

        let req = HostHTTPFetchRequest {
            timeout_millis: Some(2_000),
            max_response_bytes: Some(32),
            ..Default::default()
        };
        assert_eq!(
            effective_timeout(&req, &manifest),
            Duration::from_millis(2_000)
        );
        assert_eq!(effective_max_response_bytes(&req, &manifest), 32);

        // Zero/absent values are unset; manifest wins over the 10s cap.
        let req = HostHTTPFetchRequest {
            timeout_millis: Some(0),
            ..Default::default()
        };
        assert_eq!(
            effective_timeout(&req, &manifest),
            Duration::from_millis(4_000)
        );

        manifest.resource_limits.timeout_millis = 60_000;
        assert_eq!(
            effective_timeout(&req, &manifest),
            Duration::from_millis(10_000)
        );
    }

    #[test]
    fn secret_reflection_ignores_short_secrets() {
        let headers = BTreeMap::new();
        assert!(!contains_secret_reflection(b"body", &headers, &["short"]));
        assert!(contains_secret_reflection(
            b"prefix-livesecret-suffix",
            &headers,
            &["livesecret"]
        ));
        let mut headers = BTreeMap::new();
        headers.insert("etag".to_string(), vec!["has-livesecret".to_string()]);
        assert!(contains_secret_reflection(b"", &headers, &["livesecret"]));
    }

    #[test]
    fn hop_target_enforces_scheme_userinfo_host_and_https() {
        let manifest = manifest_with_domains(&["example.com"]);

        // Unsafe schemes, userinfo, and host shapes are all denied.
        for url in [
            "ftp://example.com/x",
            "javascript:alert(1)",
            "data:text/plain,x",
            "https:example.com",
            "https://user@example.com/",
            "https://user:pw@example.com/",
            "https://@example.com/",
            "https://example.com./",
            "https://%65xample.com/",
        ] {
            assert!(
                check_hop_target(url, &manifest, false, false).is_err(),
                "{url} should be denied"
            );
        }

        // Query and fragment contents are not part of the raw authority.
        for url in [
            "https://example.com?q=a@b",
            "https://example.com?q=%41",
            "https://example.com#frag@x",
            "https://example.com?email=user@x.com",
        ] {
            assert!(
                check_hop_target(url, &manifest, false, false).is_ok(),
                "{url} should pass"
            );
        }

        // IP literals are always denied, including IPv6 bracket forms.
        for url in [
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://[::ffff:8.8.8.8]/",
        ] {
            assert!(
                check_hop_target(url, &manifest, false, false).is_err(),
                "{url} should be denied"
            );
        }

        // Plain HTTPS on an allowed domain passes; off-domain fails.
        assert!(check_hop_target("https://example.com/x", &manifest, false, false).is_ok());
        assert!(check_hop_target("https://other.com/x", &manifest, false, false).is_err());

        // Extended and auth-bearing hops require HTTPS.
        assert!(check_hop_target("http://example.com/x", &manifest, false, false).is_ok());
        assert!(check_hop_target("http://example.com/x", &manifest, true, false).is_err());
        assert!(check_hop_target("http://example.com/x", &manifest, false, true).is_err());
        assert!(check_hop_target("https://example.com/x", &manifest, true, true).is_ok());
    }

    #[test]
    fn redact_sensitive_covers_known_secrets_query_keys_and_header_spans() {
        let secrets = vec!["s3cr3t-value".to_string()];
        assert_eq!(
            redact_sensitive("prefix-s3cr3t-value-suffix", &secrets),
            "prefix-[REDACTED]-suffix"
        );
        // Short secrets still redact (the >=8B floor applies to reflection,
        // not egress redaction).
        let secrets = vec!["ab".to_string()];
        assert_eq!(redact_sensitive("xabx", &secrets), "x[REDACTED]x");

        // Token-like query keys redact without any known secret.
        assert_eq!(
            redact_sensitive("https://h/?token=abc&x=1", &[]),
            "https://h/?token=[REDACTED]&x=1"
        );
        assert_eq!(
            redact_sensitive("https://h/?next=/a&api_key=k1", &[]),
            "https://h/?next=/a&api_key=[REDACTED]"
        );

        // Embedded credential-shaped spans redact through the line end.
        assert_eq!(
            redact_sensitive("h: Authorization: Bearer xyz\nnext", &[]),
            "h: Authorization: [REDACTED]\nnext"
        );
        assert_eq!(
            redact_sensitive("X-Api-Key=v1, tail", &[]),
            "X-Api-Key= [REDACTED]"
        );
    }

    #[test]
    fn content_encoding_opacity_normalizes_case_and_whitespace() {
        for enc in ["gzip", " GZIP ", "Br", "deflate"] {
            assert!(content_encoding_is_opaque(Some(enc)), "{enc} is opaque");
        }
        for enc in ["identity", " Identity ", "IDENTITY", "", "  "] {
            assert!(
                !content_encoding_is_opaque(Some(enc)),
                "{enc} is not opaque"
            );
        }
        assert!(!content_encoding_is_opaque(None));
    }

    #[test]
    fn ref_params_enforce_shape_sensitive_keys_and_value_rules() {
        let valid = BTreeMap::from([
            ("store".to_string(), "main".to_string()),
            ("page-no".to_string(), "42".to_string()),
        ]);
        assert!(validate_ref_params(&valid).is_ok());
        // Single-char keys are legal.
        assert!(validate_ref_params(&BTreeMap::from([("k".to_string(), "v".to_string())])).is_ok());

        // Too many entries.
        let many: BTreeMap<String, String> = (0..17)
            .map(|i| (format!("k{i:02}"), "v".to_string()))
            .collect();
        assert!(validate_ref_params(&many).is_err());

        // Sensitive and malformed keys.
        for key in [
            "token",
            "api-key",
            "my-secret",
            "auth-id",
            "Bad_Key",
            "-lead",
            "trail-",
            " space",
        ] {
            let params = BTreeMap::from([(key.to_string(), "v".to_string())]);
            assert!(validate_ref_params(&params).is_err(), "{key} must fail");
        }

        // Reserved URL / credential syntax in values.
        for value in [
            "https://x",
            "a/b",
            "a?b",
            "a@b",
            "a%b",
            "a=b",
            "a;b",
            "a:b",
            "Bearer tok",
            "x authorization:y",
            " cookie:v",
        ] {
            let params = BTreeMap::from([("k".to_string(), value.to_string())]);
            assert!(validate_ref_params(&params).is_err(), "{value} must fail");
        }

        // Empty and oversized values fail.
        assert!(validate_ref_params(&BTreeMap::from([("k".to_string(), String::new())])).is_err());
        assert!(
            validate_ref_params(&BTreeMap::from([("k".to_string(), "v".repeat(513))])).is_err()
        );
        // Boundary value of exactly 512 bytes passes.
        assert!(validate_ref_params(&BTreeMap::from([("k".to_string(), "v".repeat(512))])).is_ok());
    }

    #[test]
    fn profile_slug_predicate_matches_validator() {
        for good in ["a", "ab", "a-b", "prof-1"] {
            assert!(is_valid_profile_slug(good), "{good} should pass");
        }
        for bad in ["", "A", "-a", "a-", "a_b", "a.b"] {
            assert!(!is_valid_profile_slug(bad), "{bad} should fail");
        }
    }

    #[test]
    fn register_download_auth_mints_deterministic_refs_and_records_tokens() {
        use super::{DownloadAuthRegistry, HostBroker};
        use crate::manifest::{Capability, CAPABILITY_DOWNLOAD_AUTH};
        use crate::runner::limits::HostCallBudget;
        use goaria_extractor_sdk::types::HostRegisterDownloadAuthRequest;

        let mut manifest = manifest_with_domains(&["example.com"]);
        manifest
            .capabilities
            .push(Capability(CAPABILITY_DOWNLOAD_AUTH.to_string()));

        let broker = HostBroker::Mock(MockBroker::new());
        let mut registry = DownloadAuthRegistry::default();
        let mut budget = HostCallBudget::new(10);

        let resp = broker.handle_register_download_auth(
            &manifest,
            &mut budget,
            HostRegisterDownloadAuthRequest {
                kind: "bearer".to_string(),
                token: "guest-token-1".to_string(),
            },
            &mut registry,
        );
        assert!(resp.ok, "unexpected deny: {:?}", resp);
        let first_ref = resp.download_auth_ref.unwrap();
        assert_eq!(first_ref, "dar-00000000000000000000000000000001");

        let resp = broker.handle_register_download_auth(
            &manifest,
            &mut budget,
            HostRegisterDownloadAuthRequest {
                kind: "bearer".to_string(),
                token: "guest-token-2".to_string(),
            },
            &mut registry,
        );
        assert!(resp.ok);
        let second_ref = resp.download_auth_ref.unwrap();
        assert_eq!(second_ref, "dar-00000000000000000000000000000002");
        assert_ne!(first_ref, second_ref);

        assert!(registry.contains_ref(&first_ref));
        assert!(registry.is_registered_token("guest-token-1"));
        assert!(!registry.is_registered_token("dar-00000000000000000000000000000001"));
        assert_eq!(
            registry.registered_refs(),
            vec![first_ref.clone(), second_ref]
        );
    }

    #[test]
    fn register_download_auth_enforces_per_invocation_limit() {
        use super::{DownloadAuthRegistry, HostBroker};
        use crate::manifest::{Capability, CAPABILITY_DOWNLOAD_AUTH};
        use crate::runner::limits::HostCallBudget;
        use goaria_extractor_sdk::types::HostRegisterDownloadAuthRequest;

        let mut manifest = manifest_with_domains(&["example.com"]);
        manifest
            .capabilities
            .push(Capability(CAPABILITY_DOWNLOAD_AUTH.to_string()));
        let broker = HostBroker::Mock(MockBroker::new());
        let mut registry = DownloadAuthRegistry::default();
        let mut budget = HostCallBudget::new(16);

        for i in 0..super::DOWNLOAD_AUTH_MAX_PER_INVOCATION {
            let resp = broker.handle_register_download_auth(
                &manifest,
                &mut budget,
                HostRegisterDownloadAuthRequest {
                    kind: "bearer".to_string(),
                    token: format!("token-{i}"),
                },
                &mut registry,
            );
            assert!(resp.ok, "registration {i} denied: {:?}", resp);
        }
        let resp = broker.handle_register_download_auth(
            &manifest,
            &mut budget,
            HostRegisterDownloadAuthRequest {
                kind: "bearer".to_string(),
                token: "token-overflow".to_string(),
            },
            &mut registry,
        );
        assert!(!resp.ok);
        assert_eq!(resp.error_code.as_deref(), Some("registry_full"));
        assert_eq!(
            registry.registered_refs().len(),
            super::DOWNLOAD_AUTH_MAX_PER_INVOCATION
        );
    }

    #[test]
    fn register_download_auth_enforces_kind_token_capability_and_budget() {
        use super::{DownloadAuthRegistry, HostBroker};
        use crate::manifest::{Capability, CAPABILITY_DOWNLOAD_AUTH};
        use crate::runner::limits::HostCallBudget;
        use goaria_extractor_sdk::types::HostRegisterDownloadAuthRequest;

        let mut manifest = manifest_with_domains(&["example.com"]);
        manifest
            .capabilities
            .push(Capability(CAPABILITY_DOWNLOAD_AUTH.to_string()));
        let broker = HostBroker::Mock(MockBroker::new());

        let request = |kind: &str, token: &str| HostRegisterDownloadAuthRequest {
            kind: kind.to_string(),
            token: token.to_string(),
        };

        // budget consumed first: a zero-budget run denies with budget_exhausted
        let mut registry = DownloadAuthRegistry::default();
        let mut budget = HostCallBudget::new(0);
        let resp = broker.handle_register_download_auth(
            &manifest,
            &mut budget,
            request("bearer", "tok"),
            &mut registry,
        );
        assert_eq!(resp.error_code.as_deref(), Some("budget_exhausted"));

        // wrong kind
        let mut registry = DownloadAuthRegistry::default();
        let mut budget = HostCallBudget::new(10);
        let resp = broker.handle_register_download_auth(
            &manifest,
            &mut budget,
            request("cookie", "tok"),
            &mut registry,
        );
        assert_eq!(resp.error_code.as_deref(), Some("invalid_request"));

        // invalid tokens: empty, CRLF, double-prefixed bearer
        for token in ["", "tok\nen", "tok\r\nen", "Bearer abc", "bearer abc"] {
            let resp = broker.handle_register_download_auth(
                &manifest,
                &mut budget,
                request("bearer", token),
                &mut registry,
            );
            assert_eq!(
                resp.error_code.as_deref(),
                Some("invalid_request"),
                "token {token:?} must be denied"
            );
        }

        // missing capability
        let mut no_cap = manifest_with_domains(&["example.com"]);
        no_cap.capabilities.clear();
        let resp = broker.handle_register_download_auth(
            &no_cap,
            &mut budget,
            request("bearer", "tok"),
            &mut registry,
        );
        assert_eq!(resp.error_code.as_deref(), Some("policy_denied"));

        // disabled broker is not configured for registration
        let resp = HostBroker::Disabled.handle_register_download_auth(
            &manifest,
            &mut budget,
            request("bearer", "tok"),
            &mut registry,
        );
        assert_eq!(resp.error_code.as_deref(), Some("not_configured"));
    }

    #[test]
    fn host_time_serves_mock_constant_and_snapshot_without_broker() {
        use super::{HostBroker, MOCK_HOST_TIME_SECS};
        use crate::runner::limits::HostCallBudget;

        let mut budget = HostCallBudget::new(3);
        let mock = HostBroker::Mock(MockBroker::new());
        let resp = mock.handle_host_time(&mut budget, 12345);
        assert!(resp.ok);
        assert_eq!(resp.unix_secs, Some(MOCK_HOST_TIME_SECS));

        let live = HostBroker::Live(LiveBroker::new());
        let resp = live.handle_host_time(&mut budget, 12345);
        assert!(resp.ok);
        assert_eq!(resp.unix_secs, Some(12345));

        // host_time needs no broker: a disabled broker still serves the
        // invocation snapshot rather than an out-of-vocabulary error.
        let resp = HostBroker::Disabled.handle_host_time(&mut budget, 12345);
        assert!(resp.ok);
        assert_eq!(resp.unix_secs, Some(12345));

        // each call consumed one budget unit; the next is exhausted
        let resp = mock.handle_host_time(&mut budget, 12345);
        assert_eq!(resp.error_code.as_deref(), Some("budget_exhausted"));
    }

    #[test]
    fn omit_browser_context_conflicts_with_auth_profile_and_matches_expectation() {
        use super::MockRequestExpectation;

        // validate_extended_fetch_shape: omit + auth_profile_ref is invalid
        let req = HostHTTPFetchRequest {
            url: Some("https://example.com/x".to_string()),
            auth_profile_ref: Some("prof-1".to_string()),
            omit_browser_context: Some(true),
            ..Default::default()
        };
        assert!(validate_extended_fetch_shape(&req).is_err());

        // omit alone passes shape validation
        let req = HostHTTPFetchRequest {
            url: Some("https://example.com/x".to_string()),
            omit_browser_context: Some(true),
            ..Default::default()
        };
        assert!(validate_extended_fetch_shape(&req).is_ok());

        // mock expectation matching honors the flag
        let rule = MockBrokerRule {
            pattern: UrlPattern::Exact("https://example.com/x".to_string()),
            status_code: 200,
            headers: BTreeMap::new(),
            body: Vec::new(),
            expect: Some(MockRequestExpectation {
                omit_browser_context: Some(true),
                ..Default::default()
            }),
        };
        let shape = ValidatedFetchShape {
            method: "GET".to_string(),
            ..Default::default()
        };
        let omitting = HostHTTPFetchRequest {
            url: Some("https://example.com/x".to_string()),
            omit_browser_context: Some(true),
            ..Default::default()
        };
        assert!(rule.matches_request(&omitting, &shape));
        let default_req = HostHTTPFetchRequest {
            url: Some("https://example.com/x".to_string()),
            ..Default::default()
        };
        assert!(!rule.matches_request(&default_req, &shape));
    }
}
