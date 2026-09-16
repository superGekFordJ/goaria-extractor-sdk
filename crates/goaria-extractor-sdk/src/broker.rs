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
#[derive(Debug, Default, Clone, Copy)]
pub struct HostBroker;

impl HostBroker {
    pub fn new() -> Self {
        Self
    }

    /// Execute a general HTTP fetch request via host broker.
    pub fn fetch(
        &self,
        req: &HostHTTPFetchRequest,
    ) -> Result<HostHTTPFetchResponse, ExtractorError> {
        let req_json = serde_json::to_vec(req)?;
        let buf = raw_http_fetch(&req_json)?;
        let resp: HostHTTPFetchResponse = serde_json::from_slice(buf.as_slice())?;
        ensure_fetch_success(resp)
    }

    /// Fetch a direct URL via legacy raw mode.
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
    /// `cap.http.fetch`; the host performs all request validation.
    pub fn fetch_url_with_body(
        &self,
        url: impl Into<String>,
        body: &[u8],
        content_type: &str,
    ) -> Result<HostHTTPFetchResponse, ExtractorError> {
        self.fetch(&build_post_body_request(url, body, content_type))
    }

    /// Fetch an endpoint via alias ref mode.
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
    pub fn fetch_bytes(&self, req: &HostHTTPFetchRequest) -> Result<Vec<u8>, ExtractorError> {
        let resp = self.fetch(req)?;
        let b64 = resp.body_base64.unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;
        Ok(bytes)
    }

    /// Fetch and decode the response body as a UTF-8 string.
    pub fn fetch_text(&self, req: &HostHTTPFetchRequest) -> Result<String, ExtractorError> {
        let bytes = self.fetch_bytes(req)?;
        String::from_utf8(bytes)
            .map_err(|e| ExtractorError::ExecutionFailed(format!("invalid utf-8 body: {}", e)))
    }

    /// Fetch and deserialize JSON payload into type `T`.
    pub fn fetch_json<T: serde::de::DeserializeOwned>(
        &self,
        req: &HostHTTPFetchRequest,
    ) -> Result<T, ExtractorError> {
        let bytes = self.fetch_bytes(req)?;
        serde_json::from_slice(&bytes).map_err(ExtractorError::from)
    }

    /// Query the availability and metadata of an authentication profile.
    pub fn auth_profile_status(
        &self,
        req: &HostAuthProfileStatusRequest,
    ) -> Result<HostAuthProfileStatusResponse, ExtractorError> {
        let req_json = serde_json::to_vec(req)?;
        let buf = raw_auth_profile_status(&req_json)?;
        let resp: HostAuthProfileStatusResponse = serde_json::from_slice(buf.as_slice())?;
        Ok(resp)
    }

    /// Check whether an auth profile is available for a given legacy URL.
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

    /// Check whether an auth profile is available for an alias ref endpoint.
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

    /// Convenience check for whether an auth profile is available for a URL.
    pub fn is_auth_available(
        &self,
        auth_profile_ref: impl Into<String>,
        url: impl Into<String>,
    ) -> Result<bool, ExtractorError> {
        self.is_auth_available_for_url(auth_profile_ref, url)
    }

    /// Register a pack-minted bearer token with the host and receive the
    /// opaque `download_auth_ref` to bind onto emitted items. Requires the
    /// manifest to declare `cap.download.auth`; the token itself never
    /// crosses the ABI boundary again.
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

    /// Read the host's invocation-scoped Unix timestamp. Consumes one
    /// host-call budget unit; requires no capability.
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
