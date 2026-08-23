use crate::error::ExtractorError;
use crate::host::{raw_auth_profile_status, raw_http_fetch};
use crate::types::{
    HostAuthProfileStatusRequest, HostAuthProfileStatusResponse, HostHTTPFetchRequest,
    HostHTTPFetchResponse,
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
}
