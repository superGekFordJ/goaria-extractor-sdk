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

/// Convert a guest memory handle/pointer `i32` into a raw host pointer `*mut u8`.
///
/// # Safety
/// The caller must ensure that `ptr` represents a valid guest memory address or handle
/// allocated by [`alloc`].
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

/// Allocate contiguous bytes in guest memory.
///
/// # Safety
/// The caller must guarantee that the allocated memory will be properly deallocated
/// using [`free`].
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

/// Deallocate memory buffer previously allocated with `alloc`.
///
/// # Safety
/// The `ptr` and `len` must correspond to a valid buffer previously allocated by [`alloc`].
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

/// Allocate a new buffer in guest memory and copy `slice` into it.
///
/// # Safety
/// The allocated buffer must subsequently be managed and deallocated safely.
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
        return (0, 0);
    }
    std::ptr::copy_nonoverlapping(slice.as_ptr(), raw, slice.len());
    (ptr, len)
}

/// RAII wrapper around a buffer allocated in guest memory (e.g. returned by host import).
/// Automatically frees the buffer on drop.
pub struct GuestBuffer {
    ptr: i32,
    len: i32,
}

impl GuestBuffer {
    pub fn from_raw(ptr: i32, len: i32) -> Option<Self> {
        if ptr == 0 || len <= 0 {
            None
        } else {
            Some(Self { ptr, len })
        }
    }

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
