use std::alloc::{alloc as std_alloc, dealloc as std_dealloc, Layout};
use std::str::Utf8Error;

#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Mutex;

#[cfg(not(target_arch = "wasm32"))]
struct MockAllocEntry {
    ptr: *mut u8,
    layout: Layout,
}

#[cfg(not(target_arch = "wasm32"))]
unsafe impl Send for MockAllocEntry {}

#[cfg(not(target_arch = "wasm32"))]
static MOCK_HEAP: Mutex<Option<HashMap<i32, MockAllocEntry>>> = Mutex::new(None);
#[cfg(not(target_arch = "wasm32"))]
static NEXT_HANDLE: AtomicI32 = AtomicI32::new(1);

/// On `wasm32` the value is a linear-memory offset cast directly to a
/// pointer. On native targets it is a handle into the SDK's mock heap used
/// by tests; unknown handles yield null.
///
/// # Safety
/// On `wasm32` the caller must ensure `ptr` is a valid offset within the
/// exported linear memory for the buffer being accessed. Dereferencing the
/// result additionally requires the buffer to be live (not yet freed via
/// [`free`]).
///
/// # Panics
/// Panics on non-wasm32 targets if the mock-heap mutex is poisoned.
#[inline]
pub unsafe fn ptr_to_raw(ptr: i32) -> *mut u8 {
    if ptr == 0 {
        return std::ptr::null_mut();
    }
    #[cfg(target_arch = "wasm32")]
    {
        ptr as usize as *mut u8
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let heap = MOCK_HEAP.lock().unwrap();
        if let Some(map) = heap.as_ref() {
            if let Some(entry) = map.get(&ptr) {
                return entry.ptr;
            }
        }
        std::ptr::null_mut()
    }
}

/// Allocate `len` contiguous bytes in guest memory, backing the exported
/// `goaria_alloc`.
///
/// Returns the guest-memory pointer/handle, or `0` when `len <= 0` or
/// allocation fails. The host calls this to stage both input buffers and
/// host-import response buffers; the guest calls it for output buffers it
/// returns across the ABI.
///
/// # Safety
/// Every non-zero return owns `len` bytes that must be released exactly once
/// via [`free`] with the same `len` (the deallocation layout is
/// reconstructed from `len`), or handed to the host, which then performs
/// that `goaria_free` itself.
///
/// # Panics
/// Panics on non-wasm32 targets if the mock-heap mutex is poisoned.
pub unsafe fn alloc(len: i32) -> i32 {
    if len <= 0 {
        return 0;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let layout = match Layout::from_size_align(len as usize, 1) {
            Ok(l) => l,
            Err(_) => return 0,
        };
        let ptr = std_alloc(layout);
        ptr as usize as i32
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let layout = match Layout::from_size_align(len as usize, 8) {
            Ok(l) => l,
            Err(_) => return 0,
        };
        let raw = std_alloc(layout);
        if raw.is_null() {
            return 0;
        }
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
        let mut heap = MOCK_HEAP.lock().unwrap();
        let map = heap.get_or_insert_with(HashMap::new);
        map.insert(handle, MockAllocEntry { ptr: raw, layout });
        handle
    }
}

/// Deallocate a buffer previously returned by [`alloc`], backing the
/// exported `goaria_free`.
///
/// No-ops on `ptr == 0` or `len <= 0`.
///
/// # Safety
/// `ptr`/`len` must come from a single live [`alloc`] allocation: `len` must
/// equal the originally requested length, the buffer must not have been
/// freed already, and no live pointers may alias it. Under the ABI the host
/// calls this on input buffers and on buffers the guest returned; the guest
/// calls it (typically through [`GuestBuffer`]) on host-import response
/// buffers it owns.
///
/// # Panics
/// Panics on non-wasm32 targets if the mock-heap mutex is poisoned.
pub unsafe fn free(ptr: i32, len: i32) {
    if ptr == 0 || len <= 0 {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let layout = match Layout::from_size_align(len as usize, 1) {
            Ok(l) => l,
            Err(_) => return,
        };
        std_dealloc(ptr_to_raw(ptr), layout);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let entry = {
            let mut heap = MOCK_HEAP.lock().unwrap();
            if let Some(map) = heap.as_mut() {
                map.remove(&ptr)
            } else {
                None
            }
        };
        if let Some(entry) = entry {
            std_dealloc(entry.ptr, entry.layout);
        }
    }
}

/// Allocate a fresh guest buffer via [`alloc`] and copy `slice` into it.
///
/// Returns `(ptr, len)`, or `(0, 0)` for an empty slice or on allocation
/// failure.
///
/// # Safety
/// On success the returned buffer is owned by the caller and must be
/// released exactly once via [`free`], or ownership may be handed to the
/// host by returning it from an ABI entrypoint.
pub unsafe fn copy_slice_to_guest(slice: &[u8]) -> (i32, i32) {
    let len = slice.len() as i32;
    if len <= 0 {
        return (0, 0);
    }
    let ptr = alloc(len);
    if ptr == 0 {
        return (0, 0);
    }
    let raw = ptr_to_raw(ptr);
    if raw.is_null() {
        free(ptr, len);
        return (0, 0);
    }
    std::ptr::copy_nonoverlapping(slice.as_ptr(), raw, slice.len());
    (ptr, len)
}

/// RAII owner for a buffer living in guest memory — typically a host-import
/// response buffer the host allocated inside the guest via `goaria_alloc`.
/// Frees the buffer with [`free`] on drop.
pub struct GuestBuffer {
    ptr: i32,
    len: i32,
}

impl GuestBuffer {
    /// Wraps a raw pointer/length pair returned by a host import.
    ///
    /// Returns `None` for a null pointer, an empty buffer, or a length
    /// exceeding `i32::MAX`.
    ///
    /// # Safety
    /// `ptr`/`len` must designate a live guest buffer allocated via
    /// [`alloc`] (on the host's behalf) whose ownership transfers to the
    /// returned `GuestBuffer`; it must not be freed elsewhere afterwards.
    pub(crate) unsafe fn from_host_raw(ptr: u32, len: u32) -> Option<Self> {
        if ptr == 0 || len == 0 || len > i32::MAX as u32 {
            None
        } else {
            Some(Self {
                ptr: ptr as i32,
                len: len as i32,
            })
        }
    }

    /// Guest-memory pointer/handle of the buffer.
    pub fn ptr(&self) -> i32 {
        self.ptr
    }

    pub fn len(&self) -> i32 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            let raw = ptr_to_raw(self.ptr);
            if raw.is_null() {
                &[]
            } else {
                std::slice::from_raw_parts(raw, self.len as usize)
            }
        }
    }

    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(self.as_slice())
    }
}

impl Drop for GuestBuffer {
    fn drop(&mut self) {
        unsafe {
            free(self.ptr, self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_buffer_from_host_raw_validation() {
        unsafe {
            assert!(GuestBuffer::from_host_raw(0, 10).is_none());
            assert!(GuestBuffer::from_host_raw(100, 0).is_none());
            assert!(GuestBuffer::from_host_raw(100, (i32::MAX as u32) + 1).is_none());

            let (ptr, len) = copy_slice_to_guest(b"internal-test");
            let buf = GuestBuffer::from_host_raw(ptr as u32, len as u32).expect("valid buffer");
            assert_eq!(buf.as_slice(), b"internal-test");
            assert_eq!(buf.len(), len);
        }
    }
}
