use thiserror::Error;

pub const MAX_HOST_IMPORT_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_HOST_IMPORT_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ABI_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_WASM_MEMORY_PAGES: u32 = 65_536;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LimitsError {
    #[error("host call budget exhausted (max {max_calls})")]
    BudgetExceeded { max_calls: u32 },
    #[error("request size {actual} exceeds maximum allowed {max} bytes")]
    RequestTooLarge { actual: usize, max: usize },
    #[error("response size {actual} exceeds maximum allowed {max} bytes")]
    ResponseTooLarge { actual: usize, max: usize },
    #[error("output item count {actual} exceeds max_output_items {max}")]
    TooManyOutputItems { actual: usize, max: usize },
    #[error("output payload size {actual} bytes exceeds max_output_bytes {max}")]
    OutputPayloadTooLarge { actual: usize, max: usize },
}

/// Tracks and decrements host call budget during execution.
#[derive(Debug, Clone)]
pub struct HostCallBudget {
    pub max_calls: u32,
    pub remaining: u32,
    pub calls_made: u32,
}

impl HostCallBudget {
    pub fn new(max_calls: u32) -> Self {
        Self {
            max_calls,
            remaining: max_calls,
            calls_made: 0,
        }
    }

    pub fn consume(&mut self) -> Result<(), LimitsError> {
        if self.remaining == 0 {
            return Err(LimitsError::BudgetExceeded {
                max_calls: self.max_calls,
            });
        }
        self.remaining -= 1;
        self.calls_made += 1;
        Ok(())
    }
}
