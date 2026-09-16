use crate::error::ExtractorError;
use crate::host::{
    raw_auth_profile_status, raw_host_time, raw_http_fetch, raw_register_download_auth,
};
use crate::types::{
    HostAuthProfileStatusRequest, HostAuthProfileStatusResponse, HostHTTPFetchRequest,
    HostHTTPFetchResponse, HostRegisterDownloadAuthRequest, HostRegisterDownloadAuthResponse,
    HostTimeRequest, HostTimeResponse,
};
use base64::Engine;
use std::collections::BTreeMap;

/// Pass through a successful fetch response or map `ok: false`/HTTP >= 400
/// into the matching [`ExtractorError`] variant.
///
/// # Errors
/// Returns [`ExtractorError::HostError`] carrying the response's wire
/// `error_code`/`message` when `response.ok` is `false` (defaulting to
/// `unknown_error` when the host omitted a code), and
/// [`ExtractorError::HttpError`] when `status_code` is >= 400.
pub fn ensure_fetch_success(
    response: HostHTTPFetchResponse,
) -> Result<HostHTTPFetchResponse, ExtractorError> {
    if !response.ok {
        return Err(ExtractorError::HostError {
            error_code: response
                .error_code
                .clone()
                .unwrap_or_else(|| "unknown_error".into()),
            message: response
                .message
                .clone()
                .unwrap_or_else(|| "host call failed".into()),
        });
    }

    if let Some(status) = response.status_code {
        if status >= 400 {
            return Err(ExtractorError::HttpError {
                status_code: status,
                message: format!("HTTP status {}", status),
            });
        }
    }

    Ok(response)
}

/// Build a POST request carrying `body` under a single `Content-Type` header.
/// Shared by `fetch_url_with_body` and tests.
///
/// The helper performs no local validation: the host only accepts a
/// `body_base64` request when the method is `POST` and the sole
/// `Content-Type` is `application/json` or `application/x-www-form-urlencoded`,
/// so `content_type` must be one of those values.
pub fn build_post_body_request(
    url: impl Into<String>,
    body: &[u8],
    content_type: &str,
) -> HostHTTPFetchRequest {
    let mut headers = BTreeMap::new();
    headers.insert("Content-Type".to_string(), content_type.to_string());
    HostHTTPFetchRequest {
        method: Some("POST".to_string()),
        url: Some(url.into()),
        headers: Some(headers),
        body_base64: Some(base64::engine::general_purpose::STANDARD.encode(body)),
        ..Default::default()
    }
}

/// High-level client API for calling GoAria host services.
///
/// Stateless: every method serializes a request DTO, invokes the matching
/// `goaria_host` import, and decodes the response. Each call consumes one
/// unit of the manifest `resource_limits.max_host_calls` budget; exhausting
/// it surfaces as a `budget_exhausted` host error.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostBroker;

impl HostBroker {
    /// Create a stateless host broker client.
    pub fn new() -> Self {
        Self
    }

    /// Execute an HTTP fetch request via the host broker.
    ///
    /// Requires `cap.http.fetch`; the extended features on
    /// [`HostHTTPFetchRequest`] additionally require `cap.http.fetch.extended`.
    ///
    /// # Errors
    /// * [`ExtractorError::Serialization`] — request encode or response
    ///   decode failure.
    /// * [`ExtractorError::HostError`] — transport failure
    ///   (`host_call_failed`, `invalid_response_buffer`) or the host's wire
    ///   `error_code` when `ok` is `false`: `invalid_request`,
    ///   `policy_denied`, `fetch_failed` / `authenticated_fetch_failed`,
    ///   `budget_exhausted`, `not_configured`, `response_too_large`,
    ///   `internal_error`. The local CLI may also emit `no_mock_match`,
    ///   `broker_disabled`, or `ref_mode_not_supported_in_live_runner`.
    /// * [`ExtractorError::HttpError`] — the request was permitted and
    ///   executed but the remote server answered with status >= 400.
    pub fn fetch(
        &self,
        req: &HostHTTPFetchRequest,
    ) -> Result<HostHTTPFetchResponse, ExtractorError> {
        let req_json = serde_json::to_vec(req)?;
        let buf = raw_http_fetch(&req_json)?;
        let resp: HostHTTPFetchResponse = serde_json::from_slice(buf.as_slice())?;
        ensure_fetch_success(resp)
    }

    /// Fetch a direct URL via raw mode (`GET`).
    ///
    /// # Errors
    /// Returns [`ExtractorError`] under the same conditions as [`Self::fetch`].
    pub fn fetch_url(
        &self,
        url: impl Into<String>,
    ) -> Result<HostHTTPFetchResponse, ExtractorError> {
        self.fetch(&HostHTTPFetchRequest {
            url: Some(url.into()),
            method: Some("GET".to_string()),
            ..Default::default()
        })
    }

    /// POST `body` to `url` with a single `Content-Type` header.
    ///
    /// Requires the manifest to declare `cap.http.fetch.extended` alongside
    /// `cap.http.fetch`. Extended requests must use HTTPS and fail closed on
    /// any redirect. The host performs all request validation; `content_type`
    /// must be `application/json` or `application/x-www-form-urlencoded` and
    /// the decoded body is capped at 16 KiB.
    ///
    /// # Errors
    /// Returns [`ExtractorError`] under the same conditions as [`Self::fetch`].
    pub fn fetch_url_with_body(
        &self,
        url: impl Into<String>,
        body: &[u8],
        content_type: &str,
    ) -> Result<HostHTTPFetchResponse, ExtractorError> {
        self.fetch(&build_post_body_request(url, body, content_type))
    }

    /// Fetch an endpoint via ref mode (`broker_policy_ref` + `endpoint_ref`,
    /// plus optional `params`), valid under an alias (policy-ref) manifest.
    ///
    /// The local runner only supports ref mode on mock fixtures; a `--live`
    /// run fails it with `ref_mode_not_supported_in_live_runner`.
    ///
    /// # Errors
    /// Returns [`ExtractorError`] under the same conditions as [`Self::fetch`].
    pub fn fetch_ref(
        &self,
        broker_policy_ref: impl Into<String>,
        endpoint_ref: impl Into<String>,
        params: BTreeMap<String, String>,
    ) -> Result<HostHTTPFetchResponse, ExtractorError> {
        self.fetch(&HostHTTPFetchRequest {
            broker_policy_ref: Some(broker_policy_ref.into()),
            endpoint_ref: Some(endpoint_ref.into()),
            params: if params.is_empty() {
                None
            } else {
                Some(params)
            },
            ..Default::default()
        })
    }

    /// Fetch and decode the response body as raw bytes.
    ///
    /// # Errors
    /// Returns [`ExtractorError`] under the same conditions as [`Self::fetch`],
    /// or [`ExtractorError::Base64Decode`] when `body_base64` is not valid
    /// base64.
    pub fn fetch_bytes(&self, req: &HostHTTPFetchRequest) -> Result<Vec<u8>, ExtractorError> {
        let resp = self.fetch(req)?;
        let b64 = resp.body_base64.unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;
        Ok(bytes)
    }

    /// Fetch and decode the response body as a UTF-8 string.
    ///
    /// # Errors
    /// Returns [`ExtractorError`] under the same conditions as
    /// [`Self::fetch_bytes`], or [`ExtractorError::ExecutionFailed`] when the
    /// decoded body is not valid UTF-8.
    pub fn fetch_text(&self, req: &HostHTTPFetchRequest) -> Result<String, ExtractorError> {
        let bytes = self.fetch_bytes(req)?;
        String::from_utf8(bytes)
            .map_err(|e| ExtractorError::ExecutionFailed(format!("invalid utf-8 body: {}", e)))
    }

    /// Fetch and deserialize a JSON body into `T`.
    ///
    /// # Errors
    /// Returns [`ExtractorError`] under the same conditions as
    /// [`Self::fetch_bytes`], or [`ExtractorError::Serialization`] when the
    /// body is not valid JSON for `T`.
    pub fn fetch_json<T: serde::de::DeserializeOwned>(
        &self,
        req: &HostHTTPFetchRequest,
    ) -> Result<T, ExtractorError> {
        let bytes = self.fetch_bytes(req)?;
        serde_json::from_slice(&bytes).map_err(ExtractorError::from)
    }

    /// Query the availability and metadata of an authentication profile.
    ///
    /// Requires `cap.auth.profile`. Unlike the fetch helpers this returns the
    /// raw response: a profile lookup miss or host denial arrives as
    /// `ok: false` *inside* the payload (see
    /// [`HostAuthProfileStatusResponse::error_code`]), not as an `Err`.
    ///
    /// # Errors
    /// Returns [`ExtractorError::Serialization`] on encode/decode failure or
    /// [`ExtractorError::HostError`] on transport failure
    /// (`host_call_failed`, `invalid_response_buffer`).
    pub fn auth_profile_status(
        &self,
        req: &HostAuthProfileStatusRequest,
    ) -> Result<HostAuthProfileStatusResponse, ExtractorError> {
        let req_json = serde_json::to_vec(req)?;
        let buf = raw_auth_profile_status(&req_json)?;
        let resp: HostAuthProfileStatusResponse = serde_json::from_slice(buf.as_slice())?;
        Ok(resp)
    }

    /// Check whether an auth profile is available for a raw-mode URL.
    ///
    /// Unlike [`Self::auth_profile_status`], an `ok: false` response is
    /// mapped to an `Err`.
    ///
    /// # Errors
    /// Returns [`ExtractorError::HostError`] carrying the response's wire
    /// `error_code` when the status call fails (`invalid_request`,
    /// `policy_denied`, `auth_unavailable`, `budget_exhausted`,
    /// `not_configured`, `response_too_large`, `internal_error`), plus the
    /// transport and serialization failures of [`Self::auth_profile_status`].
    pub fn is_auth_available_for_url(
        &self,
        auth_profile_ref: impl Into<String>,
        url: impl Into<String>,
    ) -> Result<bool, ExtractorError> {
        let resp = self.auth_profile_status(&HostAuthProfileStatusRequest {
            auth_profile_ref: auth_profile_ref.into(),
            url: Some(url.into()),
            ..Default::default()
        })?;
        if !resp.ok {
            return Err(ExtractorError::HostError {
                error_code: resp
                    .error_code
                    .unwrap_or_else(|| "unknown_error".to_string()),
                message: resp
                    .message
                    .unwrap_or_else(|| "auth profile status failed".to_string()),
            });
        }
        Ok(resp.available.unwrap_or(false))
    }

    /// Check whether an auth profile is available for a ref-mode endpoint.
    ///
    /// # Errors
    /// Returns [`ExtractorError::HostError`] under the same conditions as
    /// [`Self::is_auth_available_for_url`].
    pub fn is_auth_available_for_endpoint(
        &self,
        auth_profile_ref: impl Into<String>,
        broker_policy_ref: impl Into<String>,
        endpoint_ref: impl Into<String>,
        params: BTreeMap<String, String>,
    ) -> Result<bool, ExtractorError> {
        let resp = self.auth_profile_status(&HostAuthProfileStatusRequest {
            auth_profile_ref: auth_profile_ref.into(),
            broker_policy_ref: Some(broker_policy_ref.into()),
            endpoint_ref: Some(endpoint_ref.into()),
            params: if params.is_empty() {
                None
            } else {
                Some(params)
            },
            ..Default::default()
        })?;
        if !resp.ok {
            return Err(ExtractorError::HostError {
                error_code: resp
                    .error_code
                    .unwrap_or_else(|| "unknown_error".to_string()),
                message: resp
                    .message
                    .unwrap_or_else(|| "auth profile status failed".to_string()),
            });
        }
        Ok(resp.available.unwrap_or(false))
    }

    /// Convenience alias for [`Self::is_auth_available_for_url`].
    ///
    /// # Errors
    /// Returns [`ExtractorError::HostError`] under the same conditions as
    /// [`Self::is_auth_available_for_url`].
    pub fn is_auth_available(
        &self,
        auth_profile_ref: impl Into<String>,
        url: impl Into<String>,
    ) -> Result<bool, ExtractorError> {
        self.is_auth_available_for_url(auth_profile_ref, url)
    }

    /// Register a pack-minted bearer token with the host and receive the
    /// opaque `download_auth_ref` to bind onto emitted items.
    ///
    /// Requires `cap.download.auth`. `token` is the raw credential (see
    /// [`HostRegisterDownloadAuthRequest::token`] for the size/charset/prefix
    /// rules); after this call it is host-only — the returned `dar-…` ref is
    /// the only value that may appear on
    /// [`ExtractedItemRef::download_auth_ref`](crate::types::ExtractedItemRef::download_auth_ref).
    /// The ref is bound to this pack identity and the current invocation;
    /// unreferenced registrations are purged when the invocation ends.
    ///
    /// # Errors
    /// Returns [`ExtractorError::HostError`] on transport failure, on an
    /// `ok: false` response (`invalid_request`, `policy_denied`,
    /// `budget_exhausted`, `not_configured`, `registry_full`,
    /// `response_too_large`, `internal_error`), or with the SDK-minted code
    /// `invalid_response` when a successful response lacks
    /// `download_auth_ref`.
    pub fn register_download_auth(
        &self,
        token: impl Into<String>,
    ) -> Result<String, ExtractorError> {
        let req_json = serde_json::to_vec(&HostRegisterDownloadAuthRequest {
            kind: "bearer".to_string(),
            token: token.into(),
        })?;
        let buf = raw_register_download_auth(&req_json)?;
        let resp: HostRegisterDownloadAuthResponse = serde_json::from_slice(buf.as_slice())?;
        if !resp.ok {
            return Err(ExtractorError::HostError {
                error_code: resp
                    .error_code
                    .unwrap_or_else(|| "unknown_error".to_string()),
                message: resp
                    .message
                    .unwrap_or_else(|| "register download auth failed".to_string()),
            });
        }
        resp.download_auth_ref
            .ok_or_else(|| ExtractorError::HostError {
                error_code: "invalid_response".to_string(),
                message: "register_download_auth response missing download_auth_ref".to_string(),
            })
    }

    /// Read the host's invocation-scoped Unix timestamp.
    ///
    /// Requires no capability. The value is frozen for the duration of one
    /// invocation — repeated calls inside the same `goaria_extract` return
    /// identical timestamps — but each call still consumes one host-call
    /// budget unit.
    ///
    /// # Errors
    /// Returns [`ExtractorError::HostError`] on transport failure, on an
    /// `ok: false` response (`invalid_request`, `budget_exhausted`,
    /// `response_too_large`, `internal_error`), or with `invalid_response`
    /// when a successful response lacks `unix_secs`.
    pub fn host_time(&self) -> Result<i64, ExtractorError> {
        let req_json = serde_json::to_vec(&HostTimeRequest {})?;
        let buf = raw_host_time(&req_json)?;
        let resp: HostTimeResponse = serde_json::from_slice(buf.as_slice())?;
        if !resp.ok {
            return Err(ExtractorError::HostError {
                error_code: resp
                    .error_code
                    .unwrap_or_else(|| "unknown_error".to_string()),
                message: resp
                    .message
                    .unwrap_or_else(|| "host_time failed".to_string()),
            });
        }
        resp.unix_secs.ok_or_else(|| ExtractorError::HostError {
            error_code: "invalid_response".to_string(),
            message: "host_time response missing unix_secs".to_string(),
        })
    }
}
