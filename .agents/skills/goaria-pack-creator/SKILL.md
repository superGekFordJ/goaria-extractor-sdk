---
name: goaria-pack-creator
description: Comprehensive architecture, SDK mechanics, and exhaustive CLI manual for building WebAssembly URL extractor packs for GoAria using Rust or Zig. Explains ABI v1 contract, HostBroker hierarchy, manifest policy rules, all CLI commands and parameters, memory conventions, and packaging workflows without needing to read SDK source code.
---

# GoAria Extractor Pack Architecture & Creation Guide

This guide provides the complete architectural mental model, type contracts, runtime mechanics, and toolchain rules for authoring WebAssembly (WASM) extractor packs for GoAria.

---

## 1. CLI Toolchain Full Command Reference

The `cargo-goaria-pack` CLI is the official developer toolkit for GoAria extractor packs.

### Invocation Methods
- As a Cargo subcommand (recommended after `cargo install --path crates/cargo-goaria-pack`):
  ```bash
  cargo goaria-pack <COMMAND> [OPTIONS]
  ```
- Direct executable or development invocation:
  ```bash
  cargo-goaria-pack goaria-pack <COMMAND> [OPTIONS]
  # Or via workspace:
  cargo run -p cargo-goaria-pack -- goaria-pack <COMMAND> [OPTIONS]
  ```

---

### Command 1: `new` (Project Initialization & Scaffolding)
Scaffolds a fully configured, compilable extractor pack repository.

```bash
cargo goaria-pack new <NAME> [OPTIONS]
```
| Parameter / Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `<NAME>` | String (Arg) | *Required* | Name of the extractor pack (e.g. `video-share-pack`, `image-host-pack`). |
| `-l`, `--lang <LANG>` | `rust` \| `zig` | `rust` | Implementation language. |
| `-p`, `--path <PATH>` | Path | `./<NAME>` | Target directory for the new pack project. |

**Scaffolded Structure**:
- **Rust (`--lang rust`)**: `Cargo.toml`, `manifest.json`, `src/lib.rs`, `.gitignore`
- **Zig (`--lang zig`)**: `build.zig`, `build.zig.zon`, `manifest.json`, `src/main.zig`, `.gitignore`

---

### Command 2: `build` (WASM Compilation)
Compiles guest WebAssembly bytecode (`wasm32-unknown-unknown` for Rust, freestanding for Zig).

```bash
cargo goaria-pack build [OPTIONS]
```
| Parameter / Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-p`, `--project-dir <DIR>` | Path | `.` (Current) | Target project directory containing `Cargo.toml` or `build.zig`. |
| `--release` | Bool | `true` | Compile with release profile and optimizations. |

---

### Command 3: `check` (Static Analysis & Security Linting)
Statically parses `.wasm` binary exports/imports and verifies `manifest.json` against host security policies.

```bash
cargo goaria-pack check [OPTIONS]
```
| Parameter / Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-p`, `--project-dir <DIR>` | Path | `.` | Target project directory. |
| `-w`, `--wasm <PATH>` | Path | Auto-detected | Explicit path to compiled `.wasm` binary. |
| `-m`, `--manifest <PATH>` | Path | `<DIR>/manifest.json` | Explicit path to `manifest.json`. |

**Check Assertions**:
1. Manifest JSON syntax & schema conformance (ABI v1, valid limits, no unknown fields).
2. Domain mode consistency (no mixing of concrete domains with alias policy refs).
3. Export of all 5 ABI v1 symbols (`goaria_abi_version`, `goaria_alloc`, `goaria_free`, `goaria_match`, `goaria_extract`).
4. Export of linear `memory`.
5. Host imports match declared `capabilities` (e.g. importing `http_fetch` requires `cap.http.fetch`).

---

### Command 4: `test` (Local WASM Sandbox Unit Testing)
Executes pack matching and extraction inside an isolated, local Wasmi interpreter sandbox without network dependencies.

```bash
cargo goaria-pack test [OPTIONS]
```
| Parameter / Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-p`, `--project-dir <DIR>` | Path | `.` | Target project directory. |
| `-w`, `--wasm <PATH>` | Path | Auto-detected | Explicit path to compiled `.wasm` binary. |
| `-m`, `--manifest <PATH>` | Path | `<DIR>/manifest.json` | Explicit path to `manifest.json`. |
| `--fixtures <DIR>` | Path | `fixtures/` or `tests/fixtures/` | Directory containing mock HTTP response JSON definitions. |
| `--live` | Flag | `false` | Enable live network access (bypasses `MockBroker`). |

---

### Command 5: `run` (Interactive Extraction Diagnostics)
Evaluates matching and extraction interactively on a specific target URL.

```bash
cargo goaria-pack run <URL> [OPTIONS]
```
| Parameter / Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `<URL>` | String (Arg) | *Required* | Target URL to test matching and extraction against. |
| `-p`, `--project-dir <DIR>` | Path | `.` | Target project directory. |
| `-w`, `--wasm <PATH>` | Path | Auto-detected | Path to compiled `.wasm` binary. |
| `-m`, `--manifest <PATH>` | Path | `<DIR>/manifest.json` | Path to `manifest.json`. |
| `--live` | Flag | `false` | Enable live network fetch. |
| `--auth-profile <ID>` | String | `None` | Auth profile identifier to simulate in guest (e.g. `apr-sample01`). |
| `--auth-secret <SECRET>` | String | `None` | Secret token/cookie to inject during simulation. |

---

### Command 6: `keygen` (Ed25519 Key Generation)
Generates cryptographically secure Ed25519 signing keypairs for pack developers.

```bash
cargo goaria-pack keygen --out-seed <PATH> [--out-pub <PATH>]
```
| Parameter / Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--out-seed <PATH>` | Path | *Required* | Path to write the private signing key seed hex (64 hex characters). Never overwrites existing files. |
| `--out-pub <PATH>` | Path | `None` | Path to write the public key hex string (optional). |

---

### Command 7: `sign` (Manifest Signing)
Signs `manifest.json` using an Ed25519 private key to produce a detached binary signature `manifest.sig`.

```bash
cargo goaria-pack sign --key <KEY_OR_PATH> [OPTIONS]
```
| Parameter / Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-k`, `--key <KEY_OR_PATH>` | String/Path | *Required* | 64-character private key seed hex string OR path to key file. |
| `-m`, `--manifest <PATH>` | Path | `manifest.json` | Path to `manifest.json` to sign. |
| `-o`, `--out <PATH>` | Path | `manifest.sig` | Path to output signature file. |

---

### Command 8: `pack` (Deterministic Packaging Pipeline)
Runs compilation, static analysis, signature generation, and deterministic archive compression.

```bash
cargo goaria-pack pack [OPTIONS]
```
| Parameter / Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-p`, `--project-dir <DIR>` | Path | `.` | Target project directory. |
| `-o`, `--out-dir <DIR>` | Path | `dist/` | Output directory for `.pack.zip` and `.lock.json`. |
| `-k`, `--sign-key <KEY_OR_PATH>` | String/Path | Ephemeral key | Ed25519 signing key seed hex or key file path. |
| `--asset-name <NAME>` | String | `<id>-<version>.pack.zip` | Custom output archive filename. |
| `--skip-build` | Flag | `false` | Skip compiling WASM if binary is already up-to-date. |

**Output Artifacts in `dist/`**:
1. `<pack_id>-<pack_version>.pack.zip` — Deterministic zip containing:
   - `manifest.json` (canonical JSON manifest)
   - `payload.wasm` (compiled guest bytecode)
   - `manifest.sig` (64-byte Ed25519 signature over `manifest.json`)
2. `<pack_id>.lock.json` — Supply-chain lockfile containing cryptographic SHA-256 hashes of all components.

---

## 2. System Architecture & Execution Model

GoAria uses a zero-trust, capability-gated WebAssembly sandbox to execute extractor plugins:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Host Layer (Go / Wails3 Desktop Runtime)                                │
│  - Task Dispatcher & Downloader Engine                                  │
│  - Host Policy Broker & Security Policy Enforcer                        │
│  - Secret Vault & Auth Profile Provider (Credentials never touch Guest) │
└────────────────────────────────────▲────────────────────────────────────┘
                                     │ Host Imports (goaria_host.*)
                                     │ Packed (ptr << 32 | len)
┌────────────────────────────────────▼────────────────────────────────────┐
│ WASM Sandbox Boundary (Wasmi / Wazero, ABI v1, 32-bit linear memory)     │
└────────────────────────────────────▲────────────────────────────────────┘
                                     │ Guest Exports (goaria_*)
┌────────────────────────────────────▼────────────────────────────────────┐
│ Extractor Pack Layer (Rust / Zig Native WASM)                           │
│  - Matcher: Fast URL & domain classification                           │
│  - Extractor: Invokes HostBroker, traverses payloads, builds items      │
│  - Zero-credential guest execution (receives sanitized responses)       │
└─────────────────────────────────────────────────────────────────────────┘
```

### Guest ABI v1 Exports (The 5 Mandatory Symbols)
Every compiled `.wasm` binary MUST export these 5 functions plus linear `memory`:
1. `goaria_abi_version() -> u32`: Returns current ABI version (`1`).
2. `goaria_alloc(len: u32) -> u32`: Allocates `len` bytes in guest memory, returns pointer.
3. `goaria_free(ptr: u32, len: u32) -> void`: Deallocates guest memory buffer.
4. `goaria_match(input_ptr: u32, input_len: u32) -> u64`: Evaluates URL match; returns packed `(output_ptr << 32) | output_len`.
5. `goaria_extract(input_ptr: u32, input_len: u32) -> u64`: Executes extraction; returns packed `(output_ptr << 32) | output_len`.

SDK macros (`#[goaria_extractor]` in Rust, `goaria.exportExtractor` in Zig) automatically implement and export these ABI symbols.

### Host Imports (`goaria_host`)
The guest can import host capabilities declared in its manifest:
1. `goaria_host.http_fetch(req_ptr: i32, req_len: i32) -> i64` (Requires `cap.http.fetch`)
2. `goaria_host.auth_profile_status(req_ptr: i32, req_len: i32) -> i64` (Requires `cap.auth.profile`)

---

## 3. Core SDK Hierarchy & Types

### Data Transfer Objects (DTOs)

#### Matching Flow
- **`MatchInput`**:
  - `url: String` — The URL input by the user.
- **`MatchOutput`**:
  - `matched: bool` — `true` if this pack handles the URL.
  - `confidence: Option<u8>` — `0..=100` (typically `100` for deterministic matches).
  - `reason: Option<String>` — Brief human-readable description for routing diagnostics.

#### Extraction Flow
- **`ExtractInput`**:
  - `url: String` — The matched URL to extract resources from.
- **`ExtractOutput`**:
  - `items: Vec<ExtractedItemRef>` — List of resolved downloadable files/streams.
- **`ExtractedItemRef`** (Item Descriptor):
  - `id: Option<String>` — Remote resource ID.
  - `url: Option<String>` — **Direct download HTTPS URL**. Must belong to allowed host output domains.
  - `filename: Option<String>` — Sanitized filename (no `..`, control chars, or path separators).
  - `size_bytes: Option<i64>` — Expected content length in bytes (if known).
  - `mime_type: Option<String>` — MIME type (e.g. `image/png`, `video/mp4`).
  - `auth_profile_ref: Option<String>` — If set, instructs the host downloader to attach credentials for this profile when downloading the direct link.
  - `header_profile_ref: Option<String>` — Reserved for custom header profile binding.
  - `metadata: Option<BTreeMap<String, String>>` — Key-value metadata (never include sensitive tokens).

---

## 4. HostBroker Mechanics & Network Calling

The `HostBroker` client is the guest's interface to host networking. Guests **do not possess raw sockets**; all network requests pass through the HostBroker for capability checks, TLS fingerprinting, rate limiting, and credential injection.

### Request Payload (`HostHTTPFetchRequest`)
```rust
pub struct HostHTTPFetchRequest {
    pub method: Option<String>,              // Defaults to "GET"
    pub url: Option<String>,                 // Direct URL (for open mode)
    pub broker_policy_ref: Option<String>,   // Policy ref (for alias mode, e.g. "bpr-xxx")
    pub endpoint_ref: Option<String>,        // Endpoint ref (for alias mode, e.g. "ep-xxx")
    pub params: Option<BTreeMap<String, String>>, // Path/query substitutions (e.g. {"id": "123"})
    pub headers: Option<BTreeMap<String, String>>,
    pub body_base64: Option<String>,         // POST body as padded base64 (extended cap)
    pub auth_profile_ref: Option<String>,    // Host injects credentials if authorized
    pub timeout_millis: Option<i32>,
    pub max_response_bytes: Option<i64>,
}
```

### High-Level `HostBroker` Methods (Rust)
- `HostBroker::fetch(&req) -> Result<HostHTTPFetchResponse, ExtractorError>`: Raw JSON response with base64 body. Automatically validates `resp.ok` and HTTP status `< 400`.
- `HostBroker::fetch_text(&req) -> Result<String, ExtractorError>`: Fetches and decodes body base64 into a UTF-8 `String`.
- `HostBroker::fetch_json<T: DeserializeOwned>(&req) -> Result<T, ExtractorError>`: Fetches, decodes base64, and deserializes JSON directly into struct `T`.
- `HostBroker::fetch_url_with_body(url, body, content_type) -> Result<HostHTTPFetchResponse, ExtractorError>`: POST a raw body with a single `Content-Type` header (requires `cap.http.fetch.extended`).
- `HostBroker::fetch_ref(bpr, ep, params) -> Result<HostHTTPFetchResponse, ExtractorError>`: Shorthand for alias-mode endpoint invocation (refs only — never combine with `url`).
- `HostBroker::is_auth_available(profile_ref, url) -> Result<bool, ExtractorError>`: Checks if valid user credentials exist for the profile without exposing the secret.

### High-Level `HostBroker` Methods (Zig)
- `goaria.HostBroker.fetch(allocator, req) -> !Parsed(HostHTTPFetchResponse)`
- `goaria.HostBroker.fetchText(allocator, req) -> ![]const u8` (Zero-copy decoded slice)
- `goaria.HostBroker.fetchBytes(allocator, req) -> ![]u8`
- `goaria.HostBroker.fetchUrlWithBody(allocator, url, body, content_type) -> !Parsed(HostHTTPFetchResponse)` (requires `cap.http.fetch.extended`)
- `goaria.HostBroker.fetchRef(allocator, bpr, ep, params) -> !Parsed(HostHTTPFetchResponse)` (refs only — never combine with `url`)
- `goaria.HostBroker.isAuthAvailable(allocator, profile_ref, url) -> !bool`

---

## 5. Manifest Policy Invariants & Security Boundaries

`manifest.json` defines identity, capabilities, and hard resource boundaries.

### Strict Validation Rules
1. **Mode Isolation (Never Mix!)**:
   - **Concrete Domain Mode**: `domains` is non-empty (`[{"host": "example.com", "include_subdomains": true}]`). `domain_policy_refs` and `broker_policy_refs` MUST be omitted or null.
   - **Alias Policy Ref Mode**: `domains` MUST be an explicit empty array `[]`. `domain_policy_refs` and `broker_policy_refs` MUST be non-empty arrays.
2. **Capability Matching**:
   - If importing `http_fetch`, manifest must declare `"cap.http.fetch"`.
   - POST/`body_base64`, pack-owned `Authorization`, or business `X-*` headers additionally require `"cap.http.fetch.extended"` (which must be declared alongside `"cap.http.fetch"`); extended fetch must not be combined with `auth_profile_ref`.
   - If querying auth status or binding auth profiles, manifest must declare `"cap.auth.profile"`.
   - All packs must declare `"cap.parse.wasm"`.
3. **Resource Limits & Host Ceilings**:
   - `timeout_millis`: 1..=10,000 (Default: 5,000)
   - `max_memory_pages`: 1..=256 pages = 16MB (Default: 32 pages = 2MB)
   - `max_host_calls`: 1..=128 calls per run (Default: 10~50)
   - `max_response_bytes`: Up to 10MB (Default: 1MB = 1,048,576 bytes)
   - `max_output_items`: Up to 1,000 items (Default: 50~100)
   - `max_output_bytes`: Up to 1MB (Default: 1MB)

---

## 6. Implementation Blueprints

### Rust Blueprint
```rust
use base64::Engine;
use goaria_extractor_sdk::prelude::*;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct ServicePayload {
    status: Option<String>,
    direct_link: Option<String>,
    filename: Option<String>,
    size: Option<i64>,
}

#[goaria_extractor]
#[derive(Default)]
pub struct CustomExtractor;

impl Extractor for CustomExtractor {
    fn match_url(&self, input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        if input.url.contains("target-service.net") {
            Ok(MatchOutput::matched().with_confidence(100).with_reason("matches target service"))
        } else {
            Ok(MatchOutput::unmatched())
        }
    }

    fn extract(&self, input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        let broker = HostBroker::new();
        // Params are placeholder substitutions for the endpoint template —
        // slug-shaped keys and values without URL/credential syntax.
        let mut params = BTreeMap::new();
        params.insert("item".to_string(), "item-123".to_string());

        // Ref-only invocation: never combine refs with `url`/`method`.
        let resp = match broker.fetch_ref("bpr-custom01", "ep-custom01", params) {
            Ok(resp) => resp,
            Err(_) => return Ok(ExtractOutput::default()),
        };
        let body = resp.body_base64.as_deref().unwrap_or_default();
        let payload: ServicePayload = match base64::engine::general_purpose::STANDARD
            .decode(body)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        {
            Some(payload) => payload,
            None => return Ok(ExtractOutput::default()),
        };

        if payload.status.as_deref() != Some("ok") {
            return Ok(ExtractOutput::default());
        }

        if let Some(url) = payload.direct_link {
            let item = ExtractedItemRef {
                id: None,
                url: Some(url),
                filename: payload.filename.or_else(|| Some("download.bin".to_string())),
                size_bytes: payload.size,
                mime_type: None,
                auth_profile_ref: None,
                header_profile_ref: None,
                metadata: None,
            };
            return Ok(ExtractOutput::single(item));
        }

        Ok(ExtractOutput::default())
    }
}
```

### Zig Blueprint (<90KB WASM)
```zig
const std = @import("std");
const goaria = @import("goaria_sdk");

pub const CustomExtractor = struct {
    pub fn matchUrl(allocator: std.mem.Allocator, input: goaria.MatchInput) !goaria.MatchOutput {
        _ = allocator;
        if (std.mem.indexOf(u8, input.url, "target-service.net") != null) {
            return goaria.MatchOutput.matchedResult().withConfidence(100);
        }
        return goaria.MatchOutput.unmatchedResult();
    }

    pub fn extract(allocator: std.mem.Allocator, input: goaria.ExtractInput) !goaria.ExtractOutput {
        // Ref-only invocation: never combine refs with `url`/`method`.
        var parsed = goaria.HostBroker.fetchRef(
            allocator,
            "bpr-custom01",
            "ep-custom01",
            null,
        ) catch return goaria.ExtractOutput.empty();
        defer parsed.deinit();

        const encoded = parsed.value.body_base64 orelse return goaria.ExtractOutput.empty();
        const body_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return goaria.ExtractOutput.empty();
        const body = allocator.alloc(u8, body_len) catch return goaria.ExtractOutput.empty();
        defer allocator.free(body);
        std.base64.standard.Decoder.decode(body, encoded) catch return goaria.ExtractOutput.empty();

        // Perform zero-copy string slicing or JSON parsing
        const download_url = extractUrl(body) orelse return goaria.ExtractOutput.empty();

        const item = goaria.ExtractedItemRef{
            .url = try allocator.dupe(u8, download_url),
            .filename = "file.zip",
            .mime_type = "application/zip",
        };

        return try goaria.ExtractOutput.single(allocator, item);
    }
};

comptime {
    goaria.exportExtractor(CustomExtractor);
}
```

---

## 7. Sandbox Test Fixtures (`fixtures/*.json`)

Place mock HTTP response definitions in `fixtures/` inside the pack folder. When running `cargo goaria-pack test`, `MockBroker` automatically intercepts host calls matching the URL patterns and serves mock responses without hitting live networks:

```json
[
  {
    "prefix": "https://api.example.com/",
    "status": 200,
    "headers": { "Content-Type": "application/json" },
    "json": {
      "status": "ok",
      "direct_link": "https://cdn.example.com/files/resource.dat",
      "filename": "resource.dat",
      "size": 65536
    }
  }
]
```

---

## 8. Key Developer Invariants & Gotchas

1. **Fail-Closed Principle**:
   - If an unexpected HTTP status code, malformed JSON, or forbidden credential marker (`Authorization:`, `Bearer `) appears, return `ExtractOutput::default()` / `ExtractOutput.empty()`. Never panic and never leak partial unsanitized data.
2. **Deterministic Output**:
   - `cargo goaria-pack pack` produces deterministic zip archives. Timestamps are normalized and file ordering is sorted.
3. **No File System or OS Access in Guest**:
   - WASM target is `wasm32-unknown-unknown` (Rust) or freestanding (Zig). Use standard memory allocators and data structures only.
4. **Binary Size Optimization**:
   - Always set `opt-level = "z"`, `lto = true`, `strip = true`, and `panic = "abort"` in Rust workspace release profile to keep WASM sizes compact.