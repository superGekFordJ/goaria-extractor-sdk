use wasmi::{Caller, Config, Engine, Extern, Instance, Linker, Memory, Module, Store};

use goaria_extractor_sdk::abi::pack_result;
use goaria_extractor_sdk::types::{HostAuthProfileStatusRequest, HostHTTPFetchRequest};

use crate::manifest::Manifest;
use crate::runner::auth_provider::AuthProvider;
use crate::runner::host_broker::HostBroker;
use crate::runner::limits::{
    HostCallBudget, MAX_HOST_IMPORT_REQUEST_BYTES, MAX_HOST_IMPORT_RESPONSE_BYTES,
};
use crate::runner::memory_tracker::MemoryTracker;

/// Mutable state passed into the wasmi Store.
pub struct HostState {
    pub manifest: Manifest,
    pub budget: HostCallBudget,
    pub broker: HostBroker,
    pub auth_provider: AuthProvider,
    pub memory_tracker: MemoryTracker,
}

/// In-process WebAssembly Execution Sandbox.
pub struct WasmEngine {
    engine: Engine,
    module: Module,
}

impl WasmEngine {
    pub fn new(wasm_bytes: &[u8]) -> Result<Self, wasmi::Error> {
        let mut config = Config::default();
        config.consume_fuel(false);

        let engine = Engine::new(&config);
        let module = Module::new(&engine, wasm_bytes)?;

        Ok(Self { engine, module })
    }

    /// Instantiate module and execute an operation with the given host state.
    pub fn instantiate_and_run<R>(
        &self,
        state: HostState,
        run_fn: impl FnOnce(&mut Store<HostState>, Instance, Memory) -> Result<R, wasmi::Error>,
    ) -> Result<(R, HostState), wasmi::Error> {
        let mut store = Store::new(&self.engine, state);
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

                let req: HostHTTPFetchRequest = match serde_json::from_slice(&req_bytes) {
                    Ok(r) => r,
                    Err(_) => return 0,
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

                if resp_bytes.len() > MAX_HOST_IMPORT_RESPONSE_BYTES {
                    return 0;
                }

                // Allocate response buffer in guest memory
                let alloc_func = match caller
                    .get_export("goaria_alloc")
                    .and_then(Extern::into_func)
                {
                    Some(f) => match f.typed::<i32, i32>(&caller) {
                        Ok(tf) => tf,
                        Err(_) => return 0,
                    },
                    None => return 0,
                };

                let resp_len = resp_bytes.len() as i32;
                let resp_ptr = match alloc_func.call(&mut caller, resp_len) {
                    Ok(ptr) if ptr > 0 => ptr as u32,
                    _ => return 0,
                };

                if memory
                    .write(&mut caller, resp_ptr as usize, &resp_bytes)
                    .is_err()
                {
                    return 0;
                }

                pack_result(resp_ptr, resp_len as u32) as i64
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

                let req: HostAuthProfileStatusRequest = match serde_json::from_slice(&req_bytes) {
                    Ok(r) => r,
                    Err(_) => return 0,
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

                let alloc_func = match caller
                    .get_export("goaria_alloc")
                    .and_then(Extern::into_func)
                {
                    Some(f) => match f.typed::<i32, i32>(&caller) {
                        Ok(tf) => tf,
                        Err(_) => return 0,
                    },
                    None => return 0,
                };

                let resp_len = resp_bytes.len() as i32;
                let resp_ptr = match alloc_func.call(&mut caller, resp_len) {
                    Ok(ptr) if ptr > 0 => ptr as u32,
                    _ => return 0,
                };

                if memory
                    .write(&mut caller, resp_ptr as usize, &resp_bytes)
                    .is_err()
                {
                    return 0;
                }

                pack_result(resp_ptr, resp_len as u32) as i64
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
