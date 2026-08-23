use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MemoryTrackerError {
    #[error("attempted to release unregistered host-visible buffer at ptr {ptr:#x} (len {len})")]
    UnregisteredFree { ptr: u32, len: u32 },
    #[error(
        "host-visible buffer length mismatch at ptr {ptr:#x}: registered {allocated_len}, released {free_len}"
    )]
    LengthMismatch {
        ptr: u32,
        allocated_len: u32,
        free_len: u32,
    },
    #[error("host-visible buffer ownership check failed: {unfreed_count} un-released buffers ({unfreed_bytes} bytes)")]
    MemoryLeaksDetected {
        unfreed_count: usize,
        unfreed_bytes: u64,
        leaks: Vec<UnfreedBufferInfo>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnfreedBufferInfo {
    pub ptr: u32,
    pub len: u32,
    pub tag: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationRecord {
    pub ptr: u32,
    pub len: u32,
    pub tag: &'static str,
}

/// Tracks ownership of buffers visible at the host/guest ABI boundary.
/// It does not observe arbitrary allocations performed inside the guest allocator.
#[derive(Debug, Default, Clone)]
pub struct MemoryTracker {
    allocations: BTreeMap<u32, AllocationRecord>,
    total_allocated_bytes: u64,
    total_freed_bytes: u64,
}

impl MemoryTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_alloc(&mut self, ptr: u32, len: u32, tag: &'static str) {
        if ptr == 0 || len == 0 {
            return;
        }
        self.allocations
            .insert(ptr, AllocationRecord { ptr, len, tag });
        self.total_allocated_bytes += len as u64;
    }

    pub fn record_free(&mut self, ptr: u32, len: u32) -> Result<(), MemoryTrackerError> {
        if ptr == 0 || len == 0 {
            return Ok(());
        }

        let Some(record) = self.allocations.get(&ptr) else {
            return Err(MemoryTrackerError::UnregisteredFree { ptr, len });
        };
        if record.len != len {
            return Err(MemoryTrackerError::LengthMismatch {
                ptr,
                allocated_len: record.len,
                free_len: len,
            });
        }

        self.allocations.remove(&ptr);
        self.total_freed_bytes += len as u64;
        Ok(())
    }

    pub fn check_leaks(&self) -> Result<(), MemoryTrackerError> {
        if self.allocations.is_empty() {
            Ok(())
        } else {
            let leaks: Vec<UnfreedBufferInfo> = self
                .allocations
                .values()
                .map(|r| UnfreedBufferInfo {
                    ptr: r.ptr,
                    len: r.len,
                    tag: r.tag,
                })
                .collect();

            let unfreed_bytes = leaks.iter().map(|l| l.len as u64).sum();

            Err(MemoryTrackerError::MemoryLeaksDetected {
                unfreed_count: leaks.len(),
                unfreed_bytes,
                leaks,
            })
        }
    }

    pub fn active_allocations_count(&self) -> usize {
        self.allocations.len()
    }

    pub fn active_bytes(&self) -> u64 {
        self.total_allocated_bytes
            .saturating_sub(self.total_freed_bytes)
    }
}
