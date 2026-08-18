pub mod auth_provider;
pub mod engine;
pub mod host_broker;
pub mod limits;
pub mod memory_tracker;

use thiserror::Error;
use wasmi::TypedFunc;

use goaria_extractor_sdk::abi::unpack_result;
use goaria_extractor_sdk::types::{ExtractInput, ExtractOutput, MatchInput, MatchOutput};

use crate::manifest::{Manifest, ManifestError, CURRENT_ABI_VERSION};
pub use auth_provider::AuthProvider;
pub use engine::{HostState, WasmEngine};
pub use host_broker::{HostBroker, LiveBroker, MockBroker, MockBrokerRule, UrlPattern};
pub use limits::{HostCallBudget, LimitsError, MAX_ABI_INPUT_BYTES};
pub use memory_tracker::{MemoryTracker, MemoryTrackerError};

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("wasm engine error: {0}")]
    Wasm(#[from] wasmi::Error),
    #[error("resource limits error: {0}")]
    Limits(#[from] LimitsError),
    #[error("memory leak error: {0}")]
    MemoryLeak(#[from] MemoryTrackerError),
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("missing export function '{0}'")]
    MissingExport(String),
    #[error("guest returned null or empty output pointer")]
    EmptyOutputPointer,
    #[error("ABI version mismatch: expected {expected}, guest returned {actual}")]
    AbiVersionMismatch { expected: u32, actual: u32 },
    #[error("guest memory read/write out of bounds")]
    MemoryOutOfBounds,
}

/// Configuration options for ExtractorRunner.
#[derive(Debug, Clone)]
pub struct RunnerOptions {
    pub broker: HostBroker,
    pub auth_provider: AuthProvider,
    pub verify_memory_leaks: bool,
}

impl Default for RunnerOptions {
    fn default() -> Self {
        Self {
            broker: HostBroker::Mock(MockBroker::new()),
            auth_provider: AuthProvider::new(),
            verify_memory_leaks: true,
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
        let (version, _) = self.engine.instantiate_and_run(state, |store, instance, _| {
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
        let input = MatchInput {
            url: url.to_string(),
        };
        let input_bytes = serde_json::to_vec(&input)?;

        let output_bytes = self.run_operation("goaria_match", &input_bytes)?;
        let output: MatchOutput = serde_json::from_slice(&output_bytes)?;

        Ok(output)
    }

    /// Execute `goaria_extract` against a target URL.
    pub fn extract(&self, url: &str) -> Result<ExtractOutput, RunnerError> {
        let input = ExtractInput {
            url: url.to_string(),
        };
        let input_bytes = serde_json::to_vec(&input)?;

        let output_bytes = self.run_operation("goaria_extract", &input_bytes)?;
        let output: ExtractOutput = serde_json::from_slice(&output_bytes)?;

        // Enforce output item count limit
        if output.items.len() > self.manifest.resource_limits.max_output_items as usize {
            return Err(RunnerError::Limits(LimitsError::TooManyOutputItems {
                actual: output.items.len(),
                max: self.manifest.resource_limits.max_output_items as usize,
            }));
        }

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
                        .map_err(|e| {
                            wasmi::Error::new(format!("memory write error: {}", e))
                        })?;

                    // 3. Call target operation
                    let packed_result = op_fn.call(&mut *store, (input_ptr, input_len))?;

                    // 4. Free input buffer
                    free_fn.call(&mut *store, (input_ptr, input_len))?;
                    let _ = store
                        .data_mut()
                        .memory_tracker
                        .record_free(input_ptr as u32, input_len as u32);

                    if packed_result == 0 {
                        return Err(wasmi::Error::new(
                            "guest returned null packed result",
                        ));
                    }

                    // 5. Read output from guest memory
                    let (out_ptr, out_len) = unpack_result(packed_result as u64);
                    if out_ptr == 0 || out_len == 0 {
                        return Err(wasmi::Error::new("guest returned empty output"));
                    }

                    // Enforce output payload size limit before host buffer allocation
                    let max_bytes = store.data().manifest.resource_limits.max_output_bytes as usize;
                    if out_len as usize > max_bytes {
                        let _ = free_fn.call(&mut *store, (out_ptr as i32, out_len as i32));
                        return Ok(Err(RunnerError::Limits(LimitsError::OutputPayloadTooLarge {
                            actual: out_len as usize,
                            max: max_bytes,
                        })));
                    }

                    let mut out_bytes = vec![0u8; out_len as usize];
                    memory
                        .read(&*store, out_ptr as usize, &mut out_bytes)
                        .map_err(|e| {
                            wasmi::Error::new(format!("memory read error: {}", e))
                        })?;

                    // 6. Free output buffer in guest
                    free_fn.call(&mut *store, (out_ptr as i32, out_len as i32))?;

                    Ok(Ok(out_bytes))
                })?;

        let output_bytes = output_res?;

        // 7. Verify memory leaks if enabled
        if self.options.verify_memory_leaks {
            final_state.memory_tracker.check_leaks()?;
        }

        Ok(output_bytes)
    }

    fn build_host_state(&self) -> HostState {
        HostState {
            manifest: self.manifest.clone(),
            budget: HostCallBudget::new(self.manifest.resource_limits.max_host_calls),
            broker: self.options.broker.clone(),
            auth_provider: self.options.auth_provider.clone(),
            memory_tracker: MemoryTracker::new(),
        }
    }
}
