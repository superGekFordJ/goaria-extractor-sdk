# GoAria Extractor ABI Version 1 Formal Specification

## 1. Overview & Architecture

GoAria Extractor ABI v1 defines the binary interface and communication protocol between the GoAria host runtime (powered by `wazero`) and guest WebAssembly extractor plugins.

Extractors are sandboxed WebAssembly modules (`wasm32-unknown-unknown` for Rust, `wasm32-freestanding` for Zig) executed in isolated runtime contexts with zero raw OS access, zero direct network access, and zero direct file system access.

```
+-------------------------------------------------------------------------------+
|                               GoAria Host Engine                              |
|                                                                               |
|  +---------------------------+         +-----------------------------------+  |
|  |     AddTaskDispatcher     |         |     HTTP Broker & Auth Runtime    |  |
|  +-------------+-------------+         +-----------------+-----------------+  |
|                |                                         ^                    |
|                | Invoke                                  | Host Syscalls      |
|                v                                         |                    |
|  +-------------------------------------------------------------------------+  |
|  |                     Wazero WebAssembly Guest Sandbox                    |  |
|  |                                                                         |  |
|  |   Exports:                                                              |  |
|  |     - goaria_abi_version() -> i32                                       |  |
|  |     - goaria_alloc(len) -> i32                                          |  |
|  |     - goaria_free(ptr, len)                                             |  |
|  |     - goaria_match(ptr, len) -> i64                                     |  |
|  |     - goaria_extract(ptr, len) -> i64                                   |  |
|  |                                                                         |  |
|  |   Imports ("goaria_host"):                                              |  |
|  |     - http_fetch(ptr, len) -> i64                                       |  |
|  |     - auth_profile_status(ptr, len) -> i64                              |  |
|  |                                                                         |  |
|  |   Linear Memory:                                                        |  |
|  |     Exported as "memory" (64KB WebAssembly pages)                       |  |
|  +-------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------+
```

---

## 2. Linear Memory Model & Pointer Marshalling

### 2.1 Memory Export
The guest WebAssembly module MUST export its primary linear memory under the exported name `"memory"`.

### 2.2 64-Bit Packed Pointer Representation
All functions that return dynamic buffers across the ABI boundary return an unsigned 64-bit integer (`i64` in WASM) encoding both memory offset pointer (`ptr`) and buffer length (`len`):

$$\text{PackedResult} = (\text{uint64}(\text{ptr}) \ll 32) \mid \text{uint64}(\text{len})$$

- **High 32 bits (`result >> 32`)**: Byte offset within the guest linear memory where the payload starts.
- **Low 32 bits (`result & 0xFFFFFFFF`)**: Byte length of the payload.
- If length is zero, pointer MAY be zero (`0x0000000000000000`).

### 2.3 Guest Allocator Protocol
The guest MUST export allocation and deallocation functions so the host can safely copy data into guest memory:
- `goaria_alloc(len: i32) -> i32`: Allocates `len` contiguous bytes in the guest heap and returns the starting pointer. Returns `0` if allocation fails.
- `goaria_free(ptr: i32, len: i32)`: Releases memory previously allocated via `goaria_alloc` or returned by guest functions.

### 2.4 ABI Buffer Ownership Lifecycle
The ABI defines deterministic ownership transfer for buffers crossing the host/guest boundary:
1. **Host-to-Guest Input**:
   - Host calls `goaria_alloc(len)` to obtain `ptr`.
   - Host writes serialized JSON input into `memory[ptr : ptr+len]`.
   - Host calls `goaria_match(ptr, len)` or `goaria_extract(ptr, len)`.
   - Guest borrows the slice immutably during execution without freeing it.
   - Host is solely responsible for freeing the input buffer by invoking `goaria_free(ptr, len)` immediately after guest invocation returns.
2. **Guest-to-Host Output**:
   - Guest serializes JSON output into its heap.
   - Guest returns packed `(ptr << 32) | len`.
   - Host reads `memory[ptr : ptr+len]`.
   - Host immediately invokes `goaria_free(ptr, len)` to reclaim guest heap memory.

The local runner verifies ownership balance only for buffers visible to the host. It cannot observe arbitrary guest allocator activity and therefore does not claim whole-guest leak detection or exact leaked-byte accounting.

### 2.5 Rust Panic and Error Behavior
Rust `wasm32-unknown-unknown` builds use `panic=abort` by default. A panic in `Default::default()`, `match_url`, or `extract` emits a WebAssembly `unreachable` trap; `catch_unwind` cannot recover it. The Go/Wazero host and local runner isolate and report that trap without compromising the host process.

ABI v1 has no structured extractor-error envelope for `goaria_extract`. A normal `ExtractorError` is represented by the Rust SDK as an empty `ExtractOutput`; plugin authors must reserve panics for unrecoverable bugs and should return explicit errors for expected failures.

---

## 3. Exported C-ABI Function Signatures

Every compliant extractor module MUST export the following functions with exact names and signatures:

### 3.1 `goaria_abi_version`
```c
int32_t goaria_abi_version(void);
```
- **Description**: Returns the supported ABI version.
- **Return Value**: Current ABI version integer (`1`).

### 3.2 `goaria_alloc`
```c
int32_t goaria_alloc(int32_t len);
```
- **Description**: Allocates `len` bytes in guest memory.
- **Parameters**: `len` — number of bytes to allocate.
- **Return Value**: 32-bit pointer (offset in `"memory"`), or `0` on allocation failure.

### 3.3 `goaria_free`
```c
void goaria_free(int32_t ptr, int32_t len);
```
- **Description**: Deallocates `len` bytes starting at `ptr`.
- **Parameters**:
  - `ptr` — 32-bit memory pointer.
  - `len` — number of bytes to free.

### 3.4 `goaria_match`
```c
int64_t goaria_match(int32_t ptr, int32_t len);
```
- **Description**: Tests whether this extractor handles the target URL provided in `MatchInput`.
- **Parameters**:
  - `ptr` — pointer to UTF-8 encoded `MatchInput` JSON string.
  - `len` — length of `MatchInput` JSON string in bytes.
- **Return Value**: Packed 64-bit integer pointing to UTF-8 encoded `MatchOutput` JSON string in guest memory.

### 3.5 `goaria_extract`
```c
int64_t goaria_extract(int32_t ptr, int32_t len);
```
- **Description**: Extracts downloadable artifacts from the URL provided in `ExtractInput`.
- **Parameters**:
  - `ptr` — pointer to UTF-8 encoded `ExtractInput` JSON string.
  - `len` — length of `ExtractInput` JSON string in bytes.
- **Return Value**: Packed 64-bit integer pointing to UTF-8 encoded `ExtractOutput` JSON string in guest memory.

---

## 4. Host Imported Syscalls (`"goaria_host"`)

Modules declaring required capabilities may import broker syscalls from the `"goaria_host"` module namespace:

### 4.1 `goaria_host.http_fetch`
```c
// Required capability: "cap.http.fetch"
// Extended features (POST/body/pack-owned Authorization or X-* headers)
// additionally require "cap.http.fetch.extended".
int64_t http_fetch(int32_t req_ptr, int32_t req_len);
```
- **Description**: Executes a brokered HTTP request through the host runtime. The host attaches credentials and proxies the request according to the active host policy.
- **Parameters**:
  - `req_ptr` — pointer to UTF-8 encoded `HostHTTPFetchRequest` JSON string.
  - `req_len` — length of request JSON string in bytes.
- **Return Value**: Packed 64-bit integer pointing to UTF-8 encoded `HostHTTPFetchResponse` JSON string in guest memory.

### 4.2 `goaria_host.auth_profile_status`
```c
// Required capability: "cap.auth.profile"
int64_t auth_profile_status(int32_t req_ptr, int32_t req_len);
```
- **Description**: Queries whether a configured authentication profile exists and is available on the host without exposing sensitive tokens or cookies to the guest.
- **Parameters**:
  - `req_ptr` — pointer to UTF-8 encoded `HostAuthProfileStatusRequest` JSON string.
  - `req_len` — length of request JSON string in bytes.
- **Return Value**: Packed 64-bit integer pointing to UTF-8 encoded `HostAuthProfileStatusResponse` JSON string in guest memory.

---

## 5. Data Transfer Objects (JSON DTOs)

All structured communication between host and guest uses canonical UTF-8 JSON encoding.

### 5.1 `MatchInput` & `MatchOutput`

#### `MatchInput`
```json
{
  "url": "https://share.fixture.invalid/item/123"
}
```

#### `MatchOutput`
```json
{
  "matched": true,
  "confidence": 100,
  "reason": "matches standard share pattern"
}
```
- `matched` (`bool`, required): Whether the URL is supported.
- `confidence` (`uint8`, optional, 0–100): Match confidence level (default `100` if omitted and matched).
- `reason` (`string`, optional): Human-readable explanation.

### 5.2 `ExtractInput` & `ExtractOutput`

#### `ExtractInput`
```json
{
  "url": "https://share.fixture.invalid/item/123"
}
```

#### `ExtractOutput`
```json
{
  "items": [
    {
      "id": "artifact-123",
      "url": "https://download.fixture.invalid/artifact.bin",
      "filename": "artifact.bin",
      "size_bytes": 1048576,
      "mime_type": "application/octet-stream",
      "auth_profile_ref": "default",
      "header_profile_ref": "standard_headers",
      "metadata": {
        "source": "fixture-pack"
      }
    }
  ]
}
```
- `items` (`array`, required): List of extracted downloadable items.
- `items[].url` (`string`, required): Direct downloadable URL.
- `items[].filename` (`string`, optional): Suggested destination filename.
- `items[].size_bytes` (`int64`, optional): Known artifact size in bytes.
- `items[].mime_type` (`string`, optional): Content MIME type.
- `items[].auth_profile_ref` (`string`, optional): Opaque host authentication profile reference.
- `items[].header_profile_ref` (`string`, optional): Opaque host header profile reference.
- `items[].metadata` (`map[string]string`, optional): Key-value contextual metadata.

### 5.3 `HostHTTPFetchRequest` & `HostHTTPFetchResponse`

#### `HostHTTPFetchRequest`
```json
{
  "method": "POST",
  "url": "https://api.fixture.invalid/v1/metadata",
  "headers": {
    "Accept": "application/json",
    "Content-Type": "application/json"
  },
  "body_base64": "eyJpZCI6IjEyMyJ9",
  "timeout_millis": 5000,
  "max_response_bytes": 1048576
}
```
- `method` (`string`, optional): `GET` (default), `HEAD`, or `POST`.
- `url` (`string`, optional): Raw-mode target URL. Mutually exclusive with `broker_policy_ref`/`endpoint_ref`/`params`; a request uses exactly one mode.
- `broker_policy_ref`, `endpoint_ref` (`string`, optional): Ref-mode opaque references; only valid as a pair under an alias (policy-ref) manifest.
- `params` (`map[string]string`, optional): Ref-mode parameters.
- `headers` (`map[string]string`, optional): Request headers. Safe names pass with `cap.http.fetch`; pack-owned `Authorization` and business `X-*` names additionally require `cap.http.fetch.extended`. Forbidden names (e.g. `Cookie`, `Host`, `Content-Length`) are always rejected.
- `body_base64` (`string`, optional): Strict padded standard Base64 request body, decoded cap 16 KiB. Requires `method: "POST"` and exactly one `Content-Type` of `application/json` or `application/x-www-form-urlencoded`.
- `auth_profile_ref` (`string`, optional): Host auth profile reference. Mutually exclusive with extended fetch features.
- `timeout_millis`, `max_response_bytes` (`int`, optional): Per-request limits; `0` or omitted means unset (effective value is the smallest positive of request, manifest, and policy maximum).

#### `HostHTTPFetchResponse`
```json
{
  "ok": true,
  "status_code": 200,
  "final_url": "https://api.fixture.invalid/v1/metadata?id=123",
  "headers": {
    "content-type": ["application/json"]
  },
  "body_base64": "eyJzdGF0dXMiOiJzdWNjZXNzIn0=",
  "error_code": "",
  "message": ""
}
```
- `ok` (`bool`, required): Whether the HTTP call succeeded and was permitted by policy.
- `status_code` (`int`, optional): HTTP status code (e.g. `200`, `404`).
- `final_url` (`string`, optional): URL after redirects.
- `headers` (`map[string][]string`, optional): Response headers.
- `body_base64` (`string`, optional): Base64-encoded response payload bytes.
- `error_code` (`string`, optional): Error identifier if `ok` is `false`.
- `message` (`string`, optional): Error message if `ok` is `false`.

### 5.4 `HostAuthProfileStatusRequest` & `HostAuthProfileStatusResponse`

#### `HostAuthProfileStatusRequest`
```json
{
  "auth_profile_ref": "default",
  "url": "https://share.fixture.invalid"
}
```

#### `HostAuthProfileStatusResponse`
```json
{
  "ok": true,
  "available": true,
  "kind": "bearer",
  "redacted_display": "tok_****_abc",
  "error_code": "",
  "message": ""
}
```
- `ok` (`bool`, required): Whether status resolution succeeded.
- `available` (`bool`, optional): True if credentials exist in host custody.
- `kind` (`string`, optional): `"bearer"` or `"cookie"`.
- `redacted_display` (`string`, optional): Safe masked visual representation for UI.

---

## 6. Capability & Security Boundaries

### 6.1 Capability Manifest Enforcement
Packs declare required capabilities in `manifest.json`. The host strictly checks capabilities before allowing execution:
- `cap.parse.wasm`: Grants permission to compile and instantiate the WebAssembly payload.
- `cap.http.fetch`: Grants permission to invoke `goaria_host.http_fetch` for basic GET/HEAD requests.
- `cap.http.fetch.extended`: Grants extended fetch features (`POST`, `body_base64`, pack-owned `Authorization`, business `X-*` headers). Requires `cap.http.fetch`; cannot be combined with `auth_profile_ref`. Extended requests must use HTTPS and fail closed on any redirect.
- `cap.auth.profile`: Grants permission to invoke `goaria_host.auth_profile_status`.

### 6.2 Host-Custody Credential Isolation
Guest extractors MUST NOT receive raw credentials (passwords, private tokens, cookies, auth headers). All credential injection is performed exclusively by the GoAria host runtime when executing downstream download tasks or brokered HTTP requests.

### 6.3 Resource Limits
Extractors operate within resource boundaries defined in `resource_limits`:
- `timeout_millis`: Host wall-clock deadline per invocation (default `5000`, maximum `10000` ms). The local `wasmi` runner maps this value to an approximate fuel/instruction budget; fuel is not a wall-clock timer and cannot preempt a blocking host call.
- `max_memory_pages`: WebAssembly memory page cap (default `32`, maximum `256` pages).
- `max_host_calls`: Maximum broker host calls permitted per invocation (default `50`, maximum `128`).
- `max_response_bytes`: Maximum HTTP response size permitted (default `1048576`, maximum `10485760` bytes).
- `max_output_items`: Maximum number of items in `ExtractOutput` (default `50`, maximum `1000`).
- `max_output_bytes`: Maximum serialized `ExtractOutput` JSON byte size (default and maximum `1048576` bytes).

The production Go/Wazero host enforces the wall-clock deadline with cancellation. Local CLI fuel exhaustion is a deterministic safety approximation for CPU-bound guest code, not an equivalence claim for elapsed time.

---

## 7. Deterministic Packaging & Supply-Chain Specification

### 7.1 Deterministic ZIP Format
A compiled extractor distribution archive (`.pack.zip`) MUST adhere to deterministic ZIP packaging rules:
- **Compression Method**: Uncompressed (`0` / `zip.Store`).
- **File Permissions**: Fixed mode `0o644` (`0100644`).
- **Timestamps**: Fixed UTC timestamp `2026-01-01T00:00:00Z` (`DosTime: 0x5c00`, `DosDate: 0x5c21`).
- **Archive Entry Sequence**:
  1. `manifest.json`: Canonical manifest JSON with SHA256 payload digest.
  2. `payload.wasm`: Compiled WebAssembly binary.
  3. `manifest.sig`: Raw 64-byte Ed25519 digital signature of `manifest.json`.

### 7.2 Cryptographic Signing
- Digital signatures use standard Ed25519 (RFC 8032).
- The signature is calculated over the exact bytes of `manifest.json`.
- `manifest.json` contains `payload_sha256`, cryptographically binding the manifest to the WASM payload.

### 7.3 Companion Lock File (`.lock.json`)
The packaging tool outputs a companion lock file matching schema version `1`:
```json
{
  "schema_version": 1,
  "packs": [
    {
      "pack_id": "rust-fixture-pack",
      "pack_version": "0.1.0",
      "asset_path": "rust-fixture-pack-0.1.0.pack.zip",
      "asset_sha256": "5cba1e59b9604d173531b8c864df60d9ba7d8a83e8223ebc59169a885994bd80",
      "public_keys": [
        "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6"
      ],
      "manifest_sha256": "95e6d3b9253e6e5a56229045582062cf19a05dd84b9b076646dd04def3af16da",
      "payload_sha256": "616c6c6d7dbcfd077ae669da8b5514db7f93637240d6960bb28b15c4225f9367",
      "signature_sha256": "6fb073e2e8738fdb1526644e7c73f02faf93216a0e19f46ac959281dbb38f84e"
    }
  ]
}
```
