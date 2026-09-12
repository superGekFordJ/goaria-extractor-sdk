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
    HostBroker, LiveBroker, MockBroker, MockBrokerRule, MockRequestExpectation, UrlPattern,
    ValidatedFetchShape,
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

        let output_bytes = self.run_operation("goaria_match", &input_bytes)?;
        decode_match_output(&output_bytes)
    }

    /// Execute `goaria_extract` against a target URL.
    pub fn extract(&self, url: &str) -> Result<ExtractOutput, RunnerError> {
        validate_abi_url(url, "extract input url")?;
        let input = ExtractInput {
            url: url.to_string(),
        };
        let input_bytes = serde_json::to_vec(&input)?;

        let output_bytes = self.run_operation("goaria_extract", &input_bytes)?;
        let output = decode_extract_output(&output_bytes)?;

        if output.items.len() > self.manifest.resource_limits.max_output_items as usize {
            return Err(RunnerError::Limits(LimitsError::TooManyOutputItems {
                actual: output.items.len(),
                max: self.manifest.resource_limits.max_output_items as usize,
            }));
        }
        validate_extract_output(&output)?;

        Ok(output)
    }

    fn run_operation(&self, op_name: &str, input_bytes: &[u8]) -> Result<Vec<u8>, RunnerError> {
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

        Ok(output_bytes)
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

fn validate_extract_output(output: &ExtractOutput) -> Result<(), RunnerError> {
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

        for (name, value) in [
            ("id", item.id.as_deref()),
            ("filename", item.filename.as_deref()),
            ("mime_type", item.mime_type.as_deref()),
            ("auth_profile_ref", item.auth_profile_ref.as_deref()),
            ("header_profile_ref", item.header_profile_ref.as_deref()),
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
            assert!(validate_extract_output(&ExtractOutput::single(item)).is_err());
        }
    }
}
