use wasmi::{
    AsContext, Caller, Config, Engine, Extern, Instance, Linker, Memory, Module, Store, StoreLimits,
};

use goaria_extractor_sdk::abi::pack_result;
use goaria_extractor_sdk::types::{
    HostAuthProfileStatusRequest, HostAuthProfileStatusResponse, HostHTTPFetchRequest,
    HostHTTPFetchResponse,
};

use crate::manifest::Manifest;
use crate::runner::auth_provider::AuthProvider;
use crate::runner::host_broker::HostBroker;
use crate::runner::limits::{
    HostCallBudget, MAX_HOST_IMPORT_REQUEST_BYTES, MAX_HOST_IMPORT_RESPONSE_BYTES,
};
use crate::runner::memory_tracker::MemoryTracker;

const FUEL_UNITS_PER_TIMEOUT_MILLI: u64 = 1_000_000;

fn approximate_instruction_budget(timeout_millis: u64) -> u64 {
    timeout_millis.saturating_mul(FUEL_UNITS_PER_TIMEOUT_MILLI)
}

/// Decode a fetch request body; failure yields the wire error response the
/// host would return for malformed request JSON instead of a null result.
fn decode_fetch_request(req_bytes: &[u8]) -> Result<HostHTTPFetchRequest, HostHTTPFetchResponse> {
    serde_json::from_slice(req_bytes).map_err(|error| HostHTTPFetchResponse {
        ok: false,
        error_code: Some("invalid_request".to_string()),
        message: Some(error.to_string()),
        ..Default::default()
    })
}

/// Same decode-error contract for the auth_profile_status import.
fn decode_status_request(
    req_bytes: &[u8],
) -> Result<HostAuthProfileStatusRequest, HostAuthProfileStatusResponse> {
    serde_json::from_slice(req_bytes).map_err(|error| HostAuthProfileStatusResponse {
        ok: false,
        error_code: Some("invalid_request".to_string()),
        message: Some(error.to_string()),
        ..Default::default()
    })
}

/// Compact payload returned when a serialized host-import response exceeds
/// the wire cap; mirrors the host's response-size truncation contract.
fn fetch_response_too_large_bytes() -> Vec<u8> {
    serde_json::to_vec(&HostHTTPFetchResponse {
        ok: false,
        error_code: Some("response_too_large".to_string()),
        message: Some("host import response exceeds size cap".to_string()),
        ..Default::default()
    })
    .unwrap_or_default()
}

fn status_response_too_large_bytes() -> Vec<u8> {
    serde_json::to_vec(&HostAuthProfileStatusResponse {
        ok: false,
        error_code: Some("response_too_large".to_string()),
        message: Some("host import response exceeds size cap".to_string()),
        ..Default::default()
    })
    .unwrap_or_default()
}

/// Serialize the response, allocate guest memory via `goaria_alloc`, copy the
/// bytes in, and return the packed ptr/len handle. An oversized response is
/// replaced by the compact `response_too_large` payload; 0 only remains for
/// failures where no response can be delivered at all.
fn write_guest_response(
    caller: &mut Caller<'_, HostState>,
    memory: &Memory,
    resp_bytes: Vec<u8>,
    too_large_bytes: &[u8],
) -> i64 {
    let resp_bytes = if resp_bytes.len() > MAX_HOST_IMPORT_RESPONSE_BYTES {
        too_large_bytes.to_vec()
    } else {
        resp_bytes
    };
    if resp_bytes.is_empty() || resp_bytes.len() > MAX_HOST_IMPORT_RESPONSE_BYTES {
        return 0;
    }

    let alloc_func = match caller
        .get_export("goaria_alloc")
        .and_then(Extern::into_func)
    {
        Some(f) => match f.typed::<i32, i32>(caller.as_context()) {
            Ok(tf) => tf,
            Err(_) => return 0,
        },
        None => return 0,
    };

    let resp_len = resp_bytes.len() as i32;
    let resp_ptr = match alloc_func.call(&mut *caller, resp_len) {
        Ok(ptr) if ptr > 0 => ptr as u32,
        _ => return 0,
    };

    if memory
        .write(&mut *caller, resp_ptr as usize, &resp_bytes)
        .is_err()
    {
        return 0;
    }

    pack_result(resp_ptr, resp_len as u32) as i64
}

/// Mutable state passed into the wasmi Store.
pub struct HostState {
    pub manifest: Manifest,
    pub budget: HostCallBudget,
    pub broker: HostBroker,
    pub auth_provider: AuthProvider,
    pub memory_tracker: MemoryTracker,
    pub limits: StoreLimits,
}

/// In-process WebAssembly Execution Sandbox.
pub struct WasmEngine {
    engine: Engine,
    module: Module,
}

impl WasmEngine {
    pub fn new(wasm_bytes: &[u8]) -> Result<Self, wasmi::Error> {
        let mut config = Config::default();
        config.consume_fuel(true);

        let engine = Engine::new(&config);
        let module = Module::new(&engine, wasm_bytes)?;

        Ok(Self { engine, module })
    }

    /// Instantiate a module with a fuel-based instruction budget and execute one operation.
    /// Fuel approximates CPU work for local testing; it is not a wall-clock deadline and cannot
    /// preempt a blocking host call.
    pub fn instantiate_and_run<R>(
        &self,
        state: HostState,
        run_fn: impl FnOnce(&mut Store<HostState>, Instance, Memory) -> Result<R, wasmi::Error>,
    ) -> Result<(R, HostState), wasmi::Error> {
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);

        let instruction_budget =
            approximate_instruction_budget(store.data().manifest.resource_limits.timeout_millis);
        store.set_fuel(instruction_budget)?;

        let mut linker = Linker::new(&self.engine);

        // Define host import: goaria_host.http_fetch
        linker.func_wrap(
            "goaria_host",
            "http_fetch",
            |mut caller: Caller<'_, HostState>, req_ptr: i32, req_len: i32| -> i64 {
                if req_ptr <= 0 || req_len <= 0 || req_len as usize > MAX_HOST_IMPORT_REQUEST_BYTES
                {
                    return 0;
                }

                let memory = match caller.get_export("memory").and_then(Extern::into_memory) {
                    Some(m) => m,
                    None => return 0,
                };

                let mut req_bytes = vec![0u8; req_len as usize];
                if memory
                    .read(&caller, req_ptr as usize, &mut req_bytes)
                    .is_err()
                {
                    return 0;
                }

                let too_large = fetch_response_too_large_bytes();
                let req: HostHTTPFetchRequest = match decode_fetch_request(&req_bytes) {
                    Ok(r) => r,
                    Err(resp) => {
                        // A malformed payload still burns one host call before
                        // the invalid_request response.
                        let mut budget = caller.data().budget.clone();
                        let resp = match budget.consume() {
                            Ok(()) => {
                                caller.data_mut().budget = budget;
                                resp
                            }
                            Err(e) => HostHTTPFetchResponse {
                                ok: false,
                                error_code: Some("budget_exhausted".to_string()),
                                message: Some(e.to_string()),
                                ..Default::default()
                            },
                        };
                        let bytes = serde_json::to_vec(&resp).unwrap_or_default();
                        return write_guest_response(&mut caller, &memory, bytes, &too_large);
                    }
                };

                let manifest = caller.data().manifest.clone();
                let mut budget = caller.data().budget.clone();
                let broker = caller.data().broker.clone();
                let auth_provider = caller.data().auth_provider.clone();

                let resp = broker.handle_fetch(&manifest, &mut budget, req, &auth_provider);
                caller.data_mut().budget = budget;

                let resp_bytes = match serde_json::to_vec(&resp) {
                    Ok(b) => b,
                    Err(_) => return 0,
                };

                write_guest_response(&mut caller, &memory, resp_bytes, &too_large)
            },
        )?;

        // Define host import: goaria_host.auth_profile_status
        linker.func_wrap(
            "goaria_host",
            "auth_profile_status",
            |mut caller: Caller<'_, HostState>, req_ptr: i32, req_len: i32| -> i64 {
                if req_ptr <= 0 || req_len <= 0 || req_len as usize > MAX_HOST_IMPORT_REQUEST_BYTES
                {
                    return 0;
                }

                let memory = match caller.get_export("memory").and_then(Extern::into_memory) {
                    Some(m) => m,
                    None => return 0,
                };

                let mut req_bytes = vec![0u8; req_len as usize];
                if memory
                    .read(&caller, req_ptr as usize, &mut req_bytes)
                    .is_err()
                {
                    return 0;
                }

                let too_large = status_response_too_large_bytes();
                let req: HostAuthProfileStatusRequest = match decode_status_request(&req_bytes) {
                    Ok(r) => r,
                    Err(resp) => {
                        // Same budget burn as the fetch import for malformed
                        // payloads.
                        let mut budget = caller.data().budget.clone();
                        let resp = match budget.consume() {
                            Ok(()) => {
                                caller.data_mut().budget = budget;
                                resp
                            }
                            Err(e) => HostAuthProfileStatusResponse {
                                ok: false,
                                error_code: Some("budget_exhausted".to_string()),
                                message: Some(e.to_string()),
                                ..Default::default()
                            },
                        };
                        let bytes = serde_json::to_vec(&resp).unwrap_or_default();
                        return write_guest_response(&mut caller, &memory, bytes, &too_large);
                    }
                };

                let manifest = caller.data().manifest.clone();
                let mut budget = caller.data().budget.clone();
                let auth_provider = caller.data().auth_provider.clone();

                let resp = auth_provider.handle_status(&manifest, &mut budget, req);
                caller.data_mut().budget = budget;

                let resp_bytes = match serde_json::to_vec(&resp) {
                    Ok(b) => b,
                    Err(_) => return 0,
                };

                write_guest_response(&mut caller, &memory, resp_bytes, &too_large)
            },
        )?;

        let instance = linker
            .instantiate(&mut store, &self.module)?
            .start(&mut store)?;

        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| wasmi::Error::new("missing memory export"))?;

        let result = run_fn(&mut store, instance, memory)?;
        let final_state = store.into_data();

        Ok((result, final_state))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        approximate_instruction_budget, decode_fetch_request, decode_status_request,
        fetch_response_too_large_bytes, status_response_too_large_bytes,
    };
    use crate::runner::limits::MAX_HOST_IMPORT_RESPONSE_BYTES;
    use goaria_extractor_sdk::types::{HostAuthProfileStatusResponse, HostHTTPFetchResponse};

    #[test]
    fn oversized_response_fallback_is_compact_and_parseable() {
        let bytes = fetch_response_too_large_bytes();
        assert!(bytes.len() < MAX_HOST_IMPORT_RESPONSE_BYTES);
        let resp: HostHTTPFetchResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error_code.as_deref(), Some("response_too_large"));
        assert_eq!(resp.status_code, None);
        assert_eq!(resp.final_url, None);
        assert_eq!(resp.headers, None);

        let bytes = status_response_too_large_bytes();
        let resp: HostAuthProfileStatusResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error_code.as_deref(), Some("response_too_large"));
    }

    #[test]
    fn decode_failures_produce_invalid_request_responses() {
        for bad in [
            &b"{not json"[..],
            br#"{"url":"https://example.com","bogus":1}"#,
            br#"{"url":"https://example.com"} trailing"#,
        ] {
            let err = decode_fetch_request(bad).unwrap_err();
            assert!(!err.ok);
            assert_eq!(err.error_code.as_deref(), Some("invalid_request"));
        }
        assert!(decode_fetch_request(br#"{"url":"https://example.com"}"#).is_ok());

        let err = decode_status_request(b"{]").unwrap_err();
        assert_eq!(err.error_code.as_deref(), Some("invalid_request"));
        assert!(decode_status_request(br#"{"auth_profile_ref":"p1"}"#).is_ok());
    }

    #[test]
    fn instruction_budget_scales_without_a_hidden_minimum() {
        assert_eq!(approximate_instruction_budget(1), 1_000_000);
        assert_eq!(approximate_instruction_budget(10), 10_000_000);
        assert_eq!(approximate_instruction_budget(u64::MAX), u64::MAX);
    }
}
