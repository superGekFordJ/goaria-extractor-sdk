pub mod auth_provider;
pub mod engine;
pub mod host_broker;
pub mod limits;
pub mod memory_tracker;

use thiserror::Error;
use wasmi::{StoreLimitsBuilder, TypedFunc};

use goaria_extractor_sdk::abi::{unpack_result, CURRENT_ABI_VERSION};
use goaria_extractor_sdk::types::{ExtractInput, ExtractOutput, MatchInput, MatchOutput};

use crate::manifest::{Manifest, ManifestError};
pub use crate::runner::auth_provider::AuthProvider;
use crate::runner::engine::{HostState, WasmEngine};
pub use crate::runner::host_broker::{
    DownloadAuthRegistry, HostBroker, LiveBroker, MockBroker, MockBrokerRule,
    MockRequestExpectation, UrlPattern, ValidatedFetchShape, MOCK_HOST_TIME_SECS,
};
pub use crate::runner::limits::{
    HostCallBudget, LimitsError, MAX_ABI_INPUT_BYTES, MAX_HOST_IMPORT_REQUEST_BYTES,
    MAX_HOST_IMPORT_RESPONSE_BYTES,
};
pub use crate::runner::memory_tracker::{MemoryTracker, MemoryTrackerError};

const MAX_ABI_REASON_BYTES: usize = 512;
const MAX_ABI_STRING_FIELD_BYTES: usize = 1024;
const MAX_ABI_URL_BYTES: usize = 2048;
const MAX_ABI_METADATA_ENTRIES: usize = 16;
const MAX_ABI_METADATA_KEY_BYTES: usize = 64;
const MAX_ABI_METADATA_VALUE_BYTES: usize = 512;

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("WASM engine error: {0}")]
    Engine(#[from] wasmi::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ABI validation error: {0}")]
    AbiValidation(String),
    #[error("resource limits exceeded: {0}")]
    Limits(#[from] LimitsError),
    #[error("host-visible buffer ownership violation: {0}")]
    Memory(#[from] MemoryTrackerError),
    #[error("pack abi_version {actual} does not match runner expected abi_version {expected}")]
    AbiVersionMismatch { expected: u32, actual: u32 },
}

/// Execution options and mocked environments for WASM runner.
#[derive(Debug, Clone)]
pub struct RunnerOptions {
    pub broker: HostBroker,
    pub auth_provider: AuthProvider,
    pub verify_buffer_ownership: bool,
}

impl Default for RunnerOptions {
    fn default() -> Self {
        Self {
            broker: HostBroker::Mock(MockBroker::new()),
            auth_provider: AuthProvider::new(),
            verify_buffer_ownership: true,
        }
    }
}

/// High-level in-process runner for GoAria extractor WebAssembly packs.
pub struct ExtractorRunner {
    engine: WasmEngine,
    manifest: Manifest,
    options: RunnerOptions,
}

impl ExtractorRunner {
    pub fn new(wasm_bytes: &[u8], manifest: Manifest) -> Result<Self, RunnerError> {
        manifest.validate_runnable()?;
        let engine = WasmEngine::new(wasm_bytes)?;

        Ok(Self {
            engine,
            manifest,
            options: RunnerOptions::default(),
        })
    }

    pub fn with_options(mut self, options: RunnerOptions) -> Self {
        self.options = options;
        self
    }

    pub fn with_mock_broker(mut self, broker: MockBroker) -> Self {
        self.options.broker = HostBroker::Mock(broker);
        self
    }

    pub fn with_live_broker(mut self) -> Self {
        self.options.broker = HostBroker::Live(LiveBroker::new());
        self
    }

    pub fn with_auth_provider(mut self, auth_provider: AuthProvider) -> Self {
        self.options.auth_provider = auth_provider;
        self
    }

    /// Check guest ABI version matches expected version 1.
    pub fn check_abi(&self) -> Result<u32, RunnerError> {
        let state = self.build_host_state();
        let (version, _) = self
            .engine
            .instantiate_and_run(state, |store, instance, _| {
                let version_fn: TypedFunc<(), i32> = instance
                    .get_typed_func(&*store, "goaria_abi_version")
                    .map_err(|e| wasmi::Error::new(format!("missing goaria_abi_version: {}", e)))?;

                let ver = version_fn.call(&mut *store, ())?;
                Ok(ver as u32)
            })?;

        if version != CURRENT_ABI_VERSION {
            return Err(RunnerError::AbiVersionMismatch {
                expected: CURRENT_ABI_VERSION,
                actual: version,
            });
        }

        Ok(version)
    }

    /// Execute `goaria_match` against a candidate URL.
    pub fn match_url(&self, url: &str) -> Result<MatchOutput, RunnerError> {
        validate_abi_url(url, "match input url")?;
        let input = MatchInput {
            url: url.to_string(),
        };
        let input_bytes = serde_json::to_vec(&input)?;

        let (output_bytes, _) = self.run_operation("goaria_match", &input_bytes)?;
        decode_match_output(&output_bytes)
    }

    /// Execute `goaria_extract` against a target URL.
    pub fn extract(&self, url: &str) -> Result<ExtractOutput, RunnerError> {
        self.extract_with_registrations(url).map(|(output, _)| output)
    }

    /// Execute `goaria_extract` and also return the download-auth refs the
    /// pack registered during that invocation, in registration order.
    pub fn extract_with_registrations(
        &self,
        url: &str,
    ) -> Result<(ExtractOutput, Vec<String>), RunnerError> {
        validate_abi_url(url, "extract input url")?;
        let input = ExtractInput {
            url: url.to_string(),
        };
        let input_bytes = serde_json::to_vec(&input)?;

        let (output_bytes, final_state) = self.run_operation("goaria_extract", &input_bytes)?;
        let output = decode_extract_output(&output_bytes)?;

        if output.items.len() > self.manifest.resource_limits.max_output_items as usize {
            return Err(RunnerError::Limits(LimitsError::TooManyOutputItems {
                actual: output.items.len(),
                max: self.manifest.resource_limits.max_output_items as usize,
            }));
        }
        validate_extract_output(&output, &final_state.download_auth)?;

        Ok((output, final_state.download_auth.registered_refs()))
    }

    fn run_operation(
        &self,
        op_name: &str,
        input_bytes: &[u8],
    ) -> Result<(Vec<u8>, HostState), RunnerError> {
        if input_bytes.is_empty() || input_bytes.len() > MAX_ABI_INPUT_BYTES {
            return Err(RunnerError::Limits(LimitsError::RequestTooLarge {
                actual: input_bytes.len(),
                max: MAX_ABI_INPUT_BYTES,
            }));
        }

        let state = self.build_host_state();
        let (output_res, final_state) =
            self.engine
                .instantiate_and_run(state, |store, instance, memory| {
                    let alloc_fn: TypedFunc<i32, i32> = instance
                        .get_typed_func(&*store, "goaria_alloc")
                        .map_err(|_| wasmi::Error::new("missing goaria_alloc"))?;
                    let free_fn: TypedFunc<(i32, i32), ()> = instance
                        .get_typed_func(&*store, "goaria_free")
                        .map_err(|_| wasmi::Error::new("missing goaria_free"))?;
                    let op_fn: TypedFunc<(i32, i32), i64> = instance
                        .get_typed_func(&*store, op_name)
                        .map_err(|_| wasmi::Error::new(format!("missing {}", op_name)))?;

                    // 1. Allocate input buffer in guest
                    let input_len = input_bytes.len() as i32;
                    let input_ptr = alloc_fn.call(&mut *store, input_len)?;
                    if input_ptr <= 0 {
                        return Err(wasmi::Error::new("goaria_alloc returned null"));
                    }

                    store.data_mut().memory_tracker.record_alloc(
                        input_ptr as u32,
                        input_len as u32,
                        "host_input_buffer",
                    );

                    // 2. Write input into guest memory
                    memory
                        .write(&mut *store, input_ptr as usize, input_bytes)
                        .map_err(|e| wasmi::Error::new(format!("memory write error: {}", e)))?;

                    // 3. Call target operation
                    let packed_result = op_fn.call(&mut *store, (input_ptr, input_len))?;

                    // 4. Free input buffer
                    free_fn.call(&mut *store, (input_ptr, input_len))?;
                    if let Err(error) = store
                        .data_mut()
                        .memory_tracker
                        .record_free(input_ptr as u32, input_len as u32)
                    {
                        return Ok(Err(RunnerError::Memory(error)));
                    }

                    if packed_result == 0 {
                        return Err(wasmi::Error::new("guest returned null packed result"));
                    }

                    // 5. Read output from guest memory
                    let (out_ptr, out_len) = unpack_result(packed_result as u64);
                    if out_ptr == 0 || out_len == 0 {
                        return Err(wasmi::Error::new("guest returned empty output"));
                    }

                    store.data_mut().memory_tracker.record_alloc(
                        out_ptr,
                        out_len,
                        "guest_output_buffer",
                    );

                    // Enforce output payload size limit before host buffer allocation
                    let max_bytes = store.data().manifest.resource_limits.max_output_bytes as usize;
                    if out_len as usize > max_bytes {
                        free_fn.call(&mut *store, (out_ptr as i32, out_len as i32))?;
                        if let Err(error) = store
                            .data_mut()
                            .memory_tracker
                            .record_free(out_ptr, out_len)
                        {
                            return Ok(Err(RunnerError::Memory(error)));
                        }
                        return Ok(Err(RunnerError::Limits(
                            LimitsError::OutputPayloadTooLarge {
                                actual: out_len as usize,
                                max: max_bytes,
                            },
                        )));
                    }

                    let mut out_bytes = vec![0u8; out_len as usize];
                    if let Err(error) = memory.read(&*store, out_ptr as usize, &mut out_bytes) {
                        free_fn.call(&mut *store, (out_ptr as i32, out_len as i32))?;
                        let _ = store
                            .data_mut()
                            .memory_tracker
                            .record_free(out_ptr, out_len);
                        return Err(wasmi::Error::new(format!("memory read error: {error}")));
                    }

                    // 6. Free output buffer in guest
                    free_fn.call(&mut *store, (out_ptr as i32, out_len as i32))?;
                    if let Err(error) = store
                        .data_mut()
                        .memory_tracker
                        .record_free(out_ptr, out_len)
                    {
                        return Ok(Err(RunnerError::Memory(error)));
                    }

                    Ok(Ok(out_bytes))
                })?;

        let output_bytes = output_res?;

        // 7. Verify host-visible buffer ownership if enabled
        if self.options.verify_buffer_ownership {
            final_state.memory_tracker.check_leaks()?;
        }

        Ok((output_bytes, final_state))
    }

    fn build_host_state(&self) -> HostState {
        let max_memory_pages = self.manifest.resource_limits.max_memory_pages;
        let max_bytes = (max_memory_pages as usize).saturating_mul(64 * 1024);
        let limits = StoreLimitsBuilder::new()
            .memory_size(max_bytes)
            .memories(1)
            .trap_on_grow_failure(true)
            .build();

        HostState {
            manifest: self.manifest.clone(),
            budget: HostCallBudget::new(self.manifest.resource_limits.max_host_calls),
            broker: self.options.broker.clone(),
            auth_provider: self.options.auth_provider.clone(),
            memory_tracker: MemoryTracker::new(),
            limits,
            download_auth: DownloadAuthRegistry::default(),
            host_time_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs() as i64)
                .unwrap_or_default(),
        }
    }
}

fn decode_match_output(raw: &[u8]) -> Result<MatchOutput, RunnerError> {
    let output: MatchOutput = serde_json::from_slice(raw)?;
    validate_match_output(&output)?;
    Ok(output)
}

fn decode_extract_output(raw: &[u8]) -> Result<ExtractOutput, RunnerError> {
    Ok(serde_json::from_slice(raw)?)
}

fn validate_match_output(output: &MatchOutput) -> Result<(), RunnerError> {
    if let Some(reason) = &output.reason {
        if reason.len() > MAX_ABI_REASON_BYTES {
            return Err(validation_error(format!(
                "match reason exceeds {MAX_ABI_REASON_BYTES} bytes"
            )));
        }
        validate_safe_string(reason, "match reason")?;
    }
    Ok(())
}

fn is_valid_download_auth_ref(reference: &str) -> bool {
    let Some(hex_part) = reference.strip_prefix("dar-") else {
        return false;
    };
    hex_part.len() == 32
        && hex_part
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_extract_output(
    output: &ExtractOutput,
    download_auth: &DownloadAuthRegistry,
) -> Result<(), RunnerError> {
    for (index, item) in output.items.iter().enumerate() {
        if item.size_bytes.is_some_and(|size| size < 0) {
            return Err(validation_error(format!(
                "extract output item {index}: size_bytes must not be negative"
            )));
        }
        if let Some(url) = item.url.as_deref().filter(|url| !url.is_empty()) {
            validate_abi_url(url, "item url").map_err(|error| {
                validation_error(format!("extract output item {index}: {error}"))
            })?;
        }

        // Credential-bearing items are https-only, mirroring the host's
        // fail-closed rule for materialized auth headers.
        let has_credential_ref = item.download_auth_ref.is_some()
            || item.auth_profile_ref.is_some()
            || item.header_profile_ref.is_some();
        if has_credential_ref {
            let scheme = item
                .url
                .as_deref()
                .and_then(|url| url::Url::parse(url).ok())
                .map(|parsed| parsed.scheme().to_string());
            if scheme.as_deref() != Some("https") {
                return Err(validation_error(format!(
                    "extract output item {index}: item url must use https for credentialed downloads"
                )));
            }
        }

        for (name, value) in [
            ("id", item.id.as_deref()),
            ("filename", item.filename.as_deref()),
            ("mime_type", item.mime_type.as_deref()),
            ("auth_profile_ref", item.auth_profile_ref.as_deref()),
            ("header_profile_ref", item.header_profile_ref.as_deref()),
            ("download_auth_ref", item.download_auth_ref.as_deref()),
        ] {
            if let Some(value) = value {
                if value.len() > MAX_ABI_STRING_FIELD_BYTES {
                    return Err(validation_error(format!(
                        "extract output item {index}: {name} exceeds {MAX_ABI_STRING_FIELD_BYTES} bytes"
                    )));
                }
                validate_safe_string(value, name).map_err(|error| {
                    validation_error(format!("extract output item {index}: {error}"))
                })?;
            }
        }

        if let Some(reference) = item.download_auth_ref.as_deref() {
            if !is_valid_download_auth_ref(reference) {
                return Err(validation_error(format!(
                    "extract output item {index}: download_auth_ref must be dar- plus 32 lowercase hex characters"
                )));
            }
            if item.auth_profile_ref.is_some() || item.header_profile_ref.is_some() {
                return Err(validation_error(format!(
                    "extract output item {index}: download_auth_ref must not combine with auth_profile_ref or header_profile_ref"
                )));
            }
            validate_download_auth_item_host(item.url.as_deref().unwrap_or_default(), index)?;
            if download_auth.is_registered_token(reference) {
                return Err(validation_error(format!(
                    "extract output item {index}: download_auth_ref must be an opaque ref, not a registered token"
                )));
            }
            if !download_auth.contains_ref(reference) {
                return Err(validation_error(format!(
                    "extract output item {index}: download_auth_ref was not registered during this invocation"
                )));
            }
        }

        if let Some(metadata) = &item.metadata {
            if metadata.len() > MAX_ABI_METADATA_ENTRIES {
                return Err(validation_error(format!(
                    "extract output item {index}: metadata has more than {MAX_ABI_METADATA_ENTRIES} entries"
                )));
            }
            for (key, value) in metadata {
                if key.is_empty() {
                    return Err(validation_error(format!(
                        "extract output item {index}: metadata key must be non-empty"
                    )));
                }
                if key.len() > MAX_ABI_METADATA_KEY_BYTES {
                    return Err(validation_error(format!(
                        "extract output item {index}: metadata key exceeds {MAX_ABI_METADATA_KEY_BYTES} bytes"
                    )));
                }
                if value.len() > MAX_ABI_METADATA_VALUE_BYTES {
                    return Err(validation_error(format!(
                        "extract output item {index}: metadata value exceeds {MAX_ABI_METADATA_VALUE_BYTES} bytes"
                    )));
                }
                validate_safe_string(key, "metadata key").map_err(|error| {
                    validation_error(format!("extract output item {index}: {error}"))
                })?;
                validate_safe_string(value, "metadata value").map_err(|error| {
                    validation_error(format!("extract output item {index}: {error}"))
                })?;
                if is_credential_shaped_metadata_key(key) {
                    return Err(validation_error(format!(
                        "extract output item {index}: metadata key '{key}' is credential-shaped"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Mirror of the host's ParseHTTPURLHost admission for download-auth item
/// URLs: no IP literals, trailing dots, single-label or otherwise invalid
/// domain hosts. `validate_abi_url` already covers userinfo, escapes, and
/// port shape.
fn validate_download_auth_item_host(raw_url: &str, index: usize) -> Result<(), RunnerError> {
    let unsafe_host = || {
        validation_error(format!(
            "extract output item {index}: item url has an unsafe or unsupported host"
        ))
    };
    let authority = raw_url
        .split_once("://")
        .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or_default())
        .unwrap_or_default();
    if !authority.is_ascii() {
        return Err(unsafe_host());
    }
    let parsed = url::Url::parse(raw_url).map_err(|_| unsafe_host())?;
    let host = parsed.host_str().ok_or_else(unsafe_host)?;
    if host != host.trim() || host.ends_with('.') || host.contains('%') {
        return Err(unsafe_host());
    }
    let ip_candidate = host.trim_matches(|c| c == '[' || c == ']');
    if ip_candidate.parse::<std::net::IpAddr>().is_ok() {
        return Err(unsafe_host());
    }
    let host = host.to_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let valid = labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    if !valid {
        return Err(unsafe_host());
    }
    Ok(())
}

fn validate_abi_url(raw_url: &str, field: &str) -> Result<(), RunnerError> {
    if raw_url.is_empty() {
        return Err(validation_error(format!("{field} must be non-empty")));
    }
    if raw_url.len() > MAX_ABI_URL_BYTES {
        return Err(validation_error(format!(
            "{field} exceeds {MAX_ABI_URL_BYTES} bytes"
        )));
    }
    validate_safe_string(raw_url, field)?;
    if raw_url.trim() != raw_url {
        return Err(validation_error(format!("{field} must be trimmed")));
    }

    let (_, remainder) = raw_url
        .split_once("://")
        .ok_or_else(|| validation_error(format!("{field} is malformed")))?;
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(validation_error(format!("{field} must include host")));
    }
    if authority.contains('\\') {
        return Err(validation_error(format!("{field} is malformed")));
    }

    let parsed =
        url::Url::parse(raw_url).map_err(|_| validation_error(format!("{field} is malformed")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(validation_error(format!("{field} must use http or https")));
    }
    if authority.contains('@') || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(validation_error(format!(
            "{field} must not contain credentials"
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| validation_error(format!("{field} must include host")))?;
    if host.contains('%') {
        return Err(validation_error(format!(
            "{field} host must not contain escapes"
        )));
    }
    if (host.contains(':') || authority.ends_with(':')) && parsed.port().is_none() {
        return Err(validation_error(format!(
            "{field} host contains invalid port"
        )));
    }
    Ok(())
}

fn validate_safe_string(value: &str, field: &str) -> Result<(), RunnerError> {
    if value
        .chars()
        .any(|character| character <= '\u{1f}' || character == '\u{7f}')
    {
        return Err(validation_error(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

fn is_credential_shaped_metadata_key(key: &str) -> bool {
    let normalized = key.trim().to_lowercase();
    let normalized_underscore: String = normalized
        .chars()
        .map(|character| match character {
            '-' | ' ' | '.' | ':' | '/' => '_',
            _ => character,
        })
        .collect();

    if matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "token"
            | "secret"
            | "api_key"
            | "x-api-key"
    ) || matches!(
        normalized_underscore.as_str(),
        "authorization"
            | "proxy_authorization"
            | "cookie"
            | "set_cookie"
            | "token"
            | "secret"
            | "api_key"
            | "x_api_key"
    ) {
        return true;
    }

    if normalized_underscore
        .split('_')
        .any(|part| matches!(part, "authorization" | "cookie" | "token" | "secret"))
    {
        return true;
    }

    let padded = format!("_{normalized_underscore}_");
    [
        "_authorization_",
        "_auth_token_",
        "_bearer_token_",
        "_access_token_",
        "_refresh_token_",
        "_session_cookie_",
        "_client_secret_",
        "_api_key_",
        "_x_api_key_",
    ]
    .iter()
    .any(|substring| padded.contains(substring))
}

fn validation_error(message: impl Into<String>) -> RunnerError {
    RunnerError::AbiValidation(message.into())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_extract_output, decode_match_output, validate_abi_url, validate_extract_output,
        DownloadAuthRegistry,
    };
    use goaria_extractor_sdk::types::{ExtractOutput, ExtractedItemRef};
    use std::collections::BTreeMap;

    #[test]
    fn strict_output_decoding_rejects_unknown_fields() {
        assert!(decode_match_output(br#"{"matched":true,"unexpected":1}"#).is_err());
        assert!(decode_extract_output(br#"{"items":[],"unexpected":1}"#).is_err());
        assert!(decode_extract_output(
            br#"{"items":[{"url":"https://example.com/file","unexpected":1}]}"#
        )
        .is_err());
    }

    #[test]
    fn abi_url_and_match_output_validation_match_host_boundaries() {
        for url in [
            "",
            "ftp://example.com/file",
            "https:example.com/file",
            "https://example.com\\path",
            "https://user:pass@example.com/file",
            " https://example.com/file",
            "https://example.com/file\r\nheader: value",
        ] {
            assert!(validate_abi_url(url, "input url").is_err());
        }
        assert!(decode_match_output(
            format!(r#"{{"matched":true,"reason":"{}"}}"#, "x".repeat(513)).as_bytes()
        )
        .is_err());
    }

    #[test]
    fn extract_output_validation_matches_host_boundaries() {
        let registry = DownloadAuthRegistry::default();
        let invalid_items = [
            ExtractedItemRef {
                size_bytes: Some(-1),
                ..Default::default()
            },
            ExtractedItemRef {
                url: Some("file:///tmp/file.bin".to_string()),
                ..Default::default()
            },
            ExtractedItemRef {
                metadata: Some(BTreeMap::from([(
                    "access_token".to_string(),
                    "redacted".to_string(),
                )])),
                ..Default::default()
            },
            ExtractedItemRef {
                metadata: Some(BTreeMap::from([("source".to_string(), "x".repeat(513))])),
                ..Default::default()
            },
        ];

        for item in invalid_items {
            assert!(
                validate_extract_output(&ExtractOutput::single(item), &registry).is_err()
            );
        }
    }

    #[test]
    fn download_auth_ref_must_have_been_registered_this_run() {
        use crate::runner::host_broker::HostBroker;
        use crate::manifest::{Capability, Manifest, ResourceLimits, CAPABILITY_DOWNLOAD_AUTH};
        use crate::runner::limits::HostCallBudget;
        use goaria_extractor_sdk::types::HostRegisterDownloadAuthRequest;

        let mut registry = DownloadAuthRegistry::default();
        let manifest = Manifest {
            pack_id: "test-pack".to_string(),
            pack_version: "0.1.0".to_string(),
            abi_version: 1,
            description: None,
            capabilities: vec![Capability(CAPABILITY_DOWNLOAD_AUTH.to_string())],
            domains: Some(vec![]),
            domain_policy_refs: None,
            broker_policy_refs: None,
            resource_limits: ResourceLimits::default(),
            payload_sha256: None,
        };
        let broker = HostBroker::Mock(crate::runner::host_broker::MockBroker::new());
        let mut budget = HostCallBudget::new(4);
        let resp = broker.handle_register_download_auth(
            &manifest,
            &mut budget,
            HostRegisterDownloadAuthRequest {
                kind: "bearer".to_string(),
                token: "raw-token-value".to_string(),
            },
            &mut registry,
        );
        let minted = resp.download_auth_ref.unwrap();

        // A properly registered ref passes.
        let bound = ExtractedItemRef {
            url: Some("https://example.com/file".to_string()),
            download_auth_ref: Some(minted.clone()),
            ..Default::default()
        };
        assert!(validate_extract_output(&ExtractOutput::single(bound), &registry).is_ok());

        // Malformed shapes fail.
        for bad_ref in [
            "dar-short",
            "dar-0123456789ABCDEF0123456789abcdef",
            "ref-0123456789abcdef0123456789abcdef",
            "dar-0123456789abcdef0123456789abcdeg",
        ] {
            let item = ExtractedItemRef {
                url: Some("https://example.com/file".to_string()),
                download_auth_ref: Some(bad_ref.to_string()),
                ..Default::default()
            };
            assert!(
                validate_extract_output(&ExtractOutput::single(item), &registry).is_err(),
                "ref {bad_ref} must fail"
            );
        }

        // A well-shaped but unregistered (forged) ref fails.
        let forged = ExtractedItemRef {
            url: Some("https://example.com/file".to_string()),
            download_auth_ref: Some("dar-ffffffffffffffffffffffffffffffff".to_string()),
            ..Default::default()
        };
        assert!(validate_extract_output(&ExtractOutput::single(forged), &registry).is_err());

        // Echoing a registered raw token that happens to be dar-shaped fails:
        // the value is a token, not the opaque ref minted for it.
        let mut registry = DownloadAuthRegistry::default();
        let mut budget = HostCallBudget::new(4);
        let resp = broker.handle_register_download_auth(
            &manifest,
            &mut budget,
            HostRegisterDownloadAuthRequest {
                kind: "bearer".to_string(),
                token: "dar-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            },
            &mut registry,
        );
        assert!(resp.ok, "dar-shaped token is still a valid bearer token");
        let echoed = ExtractedItemRef {
            url: Some("https://example.com/file".to_string()),
            download_auth_ref: Some("dar-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            ..Default::default()
        };
        assert!(validate_extract_output(&ExtractOutput::single(echoed), &registry).is_err());
    }

    #[test]
    fn credentialed_items_require_https_and_exclude_profile_refs() {
        use crate::manifest::{Capability, Manifest, ResourceLimits, CAPABILITY_DOWNLOAD_AUTH};
        use crate::runner::host_broker::{HostBroker, MockBroker};
        use crate::runner::limits::HostCallBudget;
        use goaria_extractor_sdk::types::HostRegisterDownloadAuthRequest;

        let mut registry = DownloadAuthRegistry::default();
        let manifest = Manifest {
            pack_id: "test-pack".to_string(),
            pack_version: "0.1.0".to_string(),
            abi_version: 1,
            description: None,
            capabilities: vec![Capability(CAPABILITY_DOWNLOAD_AUTH.to_string())],
            domains: Some(vec![]),
            domain_policy_refs: None,
            broker_policy_refs: None,
            resource_limits: ResourceLimits::default(),
            payload_sha256: None,
        };
        let broker = HostBroker::Mock(MockBroker::new());
        let mut budget = HostCallBudget::new(4);
        let minted = broker
            .handle_register_download_auth(
                &manifest,
                &mut budget,
                HostRegisterDownloadAuthRequest {
                    kind: "bearer".to_string(),
                    token: "raw-token".to_string(),
                },
                &mut registry,
            )
            .download_auth_ref
            .unwrap();

        // download_auth_ref cannot combine with profile refs (host mirror).
        for extra in [
            ExtractedItemRef {
                auth_profile_ref: Some("apr-x".to_string()),
                ..Default::default()
            },
            ExtractedItemRef {
                header_profile_ref: Some("hpr-x".to_string()),
                ..Default::default()
            },
        ] {
            let mut item = extra;
            item.url = Some("https://example.com/file".to_string());
            item.download_auth_ref = Some(minted.clone());
            assert!(
                validate_extract_output(&ExtractOutput::single(item), &registry).is_err(),
                "profile ref combination must fail"
            );
        }

        // Any credential ref on a plaintext URL fails closed.
        for (url, auth_ref, header_ref) in [
            ("http://example.com/file", None, None),
            ("ftp://example.com/file", None, None),
        ] {
            let item = ExtractedItemRef {
                url: Some(url.to_string()),
                download_auth_ref: Some(minted.clone()),
                auth_profile_ref: auth_ref.map(str::to_string),
                header_profile_ref: header_ref.map(str::to_string),
                ..Default::default()
            };
            assert!(
                validate_extract_output(&ExtractOutput::single(item), &registry).is_err(),
                "url {url} must fail"
            );
        }
        let profile_http = ExtractedItemRef {
            url: Some("http://example.com/file".to_string()),
            auth_profile_ref: Some("apr-x".to_string()),
            ..Default::default()
        };
        assert!(validate_extract_output(&ExtractOutput::single(profile_http), &registry).is_err());
        let header_http = ExtractedItemRef {
            url: Some("http://example.com/file".to_string()),
            header_profile_ref: Some("hpr-x".to_string()),
            ..Default::default()
        };
        assert!(validate_extract_output(&ExtractOutput::single(header_http), &registry).is_err());

        // Unsafe host shapes the host's bind admission rejects.
        for url in [
            "https://127.0.0.1/file",
            "https://[::1]/file",
            "https://localhost/file",
            "https://example.com./file",
            "https://user:pass@example.com/file",
            "https://exa_mple.com/file",
        ] {
            let item = ExtractedItemRef {
                url: Some(url.to_string()),
                download_auth_ref: Some(minted.clone()),
                ..Default::default()
            };
            assert!(
                validate_extract_output(&ExtractOutput::single(item), &registry).is_err(),
                "url {url} must fail"
            );
        }

        // A plain http item without credential refs is still allowed.
        let plain = ExtractedItemRef {
            url: Some("http://example.com/file".to_string()),
            ..Default::default()
        };
        assert!(validate_extract_output(&ExtractOutput::single(plain), &registry).is_ok());
    }
}
