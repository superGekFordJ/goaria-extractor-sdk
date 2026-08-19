# GoAria Extractor SDK — Developer Guide & Quickstart

Welcome to the **GoAria Extractor SDK** developer guide. This guide explains how to build, test, sign, and package high-performance WebAssembly extractors for the GoAria ecosystem using Rust or Zig.

---

## Table of Contents

1. [3-Minute Quickstart](#1-3-minute-quickstart)
2. [Rust Extractor Authoring Guide](#2-rust-extractor-authoring-guide)
3. [Zig Extractor Authoring Guide](#3-zig-extractor-authoring-guide)
4. [CLI Command Reference (`cargo-goaria-pack`)](#4-cli-command-reference-cargo-goaria-pack)
5. [Testing & Sandboxing](#5-testing--sandboxing)
6. [Packaging, Signing & Distribution](#6-packaging-signing--distribution)
7. [Security Principles & Capabilities](#7-security-principles--capabilities)

---

## 1. 3-Minute Quickstart

### Step 1: Install the SDK CLI

Install `cargo-goaria-pack` from the workspace:

```bash
cargo install --path crates/cargo-goaria-pack
```

Verify installation:

```bash
cargo goaria-pack --help
```

### Step 2: Scaffold a New Extractor Project

Create a new Rust-based extractor:

```bash
cargo goaria-pack new my-extractor --lang rust
cd my-extractor
```

*(Or for Zig: `cargo goaria-pack new my-extractor --lang zig`)*

### Step 3: Run Static Validation & Unit Tests

```bash
cargo goaria-pack check
cargo goaria-pack test
```

### Step 4: Execute Against a Target URL

Execute the extractor in the local WebAssembly sandbox with a mock broker:

```bash
cargo goaria-pack run https://share.fixture.invalid/item/123
```

### Step 5: Build & Package for Distribution

```bash
cargo goaria-pack pack --out-dir dist
```

This compiles the WebAssembly binary, embeds the canonical manifest, generates the Ed25519 cryptographic signature, and produces a deterministic `.pack.zip` and `.lock.json` in `dist/`.

---

## 2. Rust Extractor Authoring Guide

### 2.1 Project Configuration (`Cargo.toml`)

Ensure `crate-type = ["cdylib"]` is configured:

```toml
[package]
name = "my-extractor"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
goaria-extractor-sdk = { path = "../crates/goaria-extractor-sdk" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

### 2.2 Implementing the `Extractor` Trait

Use the `#[goaria_pack]` attribute macro to automatically wire memory management and C-ABI exports:

```rust
use goaria_extractor_sdk::prelude::*;

pub struct MyExtractor;

#[derive(serde::Deserialize)]
struct ApiItemResponse {
    download_url: String,
    filename: String,
    size_bytes: i64,
}

impl Extractor for MyExtractor {
    fn match_url(&self, input: MatchInput) -> Result<MatchOutput, ExtractorError> {
        if input.url.starts_with("https://share.fixture.invalid/") {
            Ok(MatchOutput::matched().with_confidence(100))
        } else {
            Ok(MatchOutput::unmatched())
        }
    }

    fn extract(&self, input: ExtractInput, broker: &HostBroker) -> Result<ExtractOutput, ExtractorError> {
        // Brokered HTTP request through host
        let api_url = format!("https://api.fixture.invalid/v1/resolve?url={}", urlencoding::encode(&input.url));
        let response = broker.fetch_json::<ApiItemResponse>(&HostHTTPFetchRequest {
            method: "GET".to_string(),
            url: api_url,
            broker_policy_ref: "standard_api".to_string(),
            endpoint_ref: "resolve_item".to_string(),
            ..Default::default()
        })?;

        let item = ExtractedItemRef {
            url: response.download_url,
            filename: Some(response.filename),
            size_bytes: Some(response.size_bytes),
            mime_type: Some("application/octet-stream".to_string()),
            auth_profile_ref: Some("default".to_string()),
            ..Default::default()
        };

        Ok(ExtractOutput::single(item))
    }
}

// Register C-ABI exports
#[goaria_pack]
impl Extractor for MyExtractor {}
```

### 2.3 Host-Custody Credentials
Notice that extractors never handle raw tokens, cookies, or secrets. Instead, the extractor supplies an opaque reference (e.g. `auth_profile_ref: Some("default".to_string())`), and the GoAria host injects credentials securely.

---

## 3. Zig Extractor Authoring Guide

### 3.1 Build Configuration (`build.zig`)

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSmall,
    });

    const sdk_dep = b.dependency("goaria_sdk", .{
        .target = target,
        .optimize = optimize,
    });
    const sdk_mod = sdk_dep.module("goaria_sdk");

    const wasm = b.addExecutable(.{
        .name = "my_extractor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .imports = &.{
                .{ .name = "goaria_sdk", .module = sdk_mod },
            },
        }),
    });

    wasm.entry = .disabled;
    wasm.rdynamic = true;

    b.installArtifact(wasm);
}
```

### 3.2 Extractor Implementation (`src/main.zig`)

```zig
const std = @import("std");
const goaria = @import("goaria_sdk");

const MyExtractor = struct {
    pub fn matchUrl(allocator: std.mem.Allocator, input: goaria.MatchInput) !goaria.MatchOutput {
        _ = allocator;
        if (std.mem.startsWith(u8, input.url, "https://share.fixture.invalid/")) {
            return goaria.MatchOutput{
                .matched = true,
                .confidence = 100,
                .reason = "matched fixture domain",
            };
        }
        return goaria.MatchOutput{
            .matched = false,
            .confidence = 0,
            .reason = null,
        };
    }

    pub fn extract(allocator: std.mem.Allocator, input: goaria.ExtractInput) !goaria.ExtractOutput {
        _ = input;
        var items = std.ArrayList(goaria.ExtractedItemRef).init(allocator);
        try items.append(.{
            .id = "artifact-001",
            .url = "https://download.fixture.invalid/artifact.bin",
            .filename = "artifact.bin",
            .size_bytes = 2048,
            .mime_type = "application/octet-stream",
            .auth_profile_ref = null,
            .header_profile_ref = null,
            .metadata = null,
        });

        return goaria.ExtractOutput{
            .items = try items.toOwnedSlice(),
        };
    }
};

// Export C-ABI functions
pub usingnamespace goaria.exportExtractor(MyExtractor);
```

---

## 4. CLI Command Reference (`cargo-goaria-pack`)

| Command | Syntax | Description |
| :--- | :--- | :--- |
| `new` | `cargo goaria-pack new <NAME> [--lang rust\|zig]` | Scaffolds a complete extractor project. |
| `build` | `cargo goaria-pack build [--release]` | Compiles the project to WebAssembly. |
| `check` | `cargo goaria-pack check [--project-dir <DIR>]` | Statically validates bytecode exports and manifest schema. |
| `test` | `cargo goaria-pack test [--project-dir <DIR>]` | Runs unit and integration tests inside the WASM sandbox. |
| `run` | `cargo goaria-pack run <URL> [--mock <JSON>] [--live]` | Executes extractor on a URL with mock or live broker. |
| `keygen` | `cargo goaria-pack keygen [--out-dir <DIR>] [--force]` | Generates an Ed25519 cryptographic keypair (`key.priv`, `key.pub`). |
| `sign` | `cargo goaria-pack sign --manifest <PATH> --key <KEY>` | Signs `manifest.json` with an Ed25519 private key. |
| `pack` | `cargo goaria-pack pack [--out-dir <DIR>] [--sign-key <KEY>]` | Builds, signs, and packages deterministic `.pack.zip` and `.lock.json`. |

---

## 5. Testing & Sandboxing

### 5.1 Local Execution (`run`)

Test extraction with a mock broker:

```bash
cargo goaria-pack run https://share.fixture.invalid/item/123
```

Provide custom mock broker responses:

```bash
cargo goaria-pack run https://share.fixture.invalid/item/123 \
  --mock '{"https://api.fixture.invalid/v1/metadata": {"status_code": 200, "body": "{\"download_url\":\"https://download.fixture.invalid/file.bin\"}"}}'
```

### 5.2 Zero-Leak Memory Verification
The CLI's built-in WASM runtime tracks every byte allocated by `goaria_alloc` and deallocated by `goaria_free`. If an extractor leaks memory or panics, the runner reports a memory leak error with the exact count of uncollected bytes.

---

## 6. Packaging, Signing & Distribution

### 6.1 Cryptographic Key Generation

```bash
cargo goaria-pack keygen --out-dir ~/.goaria/keys
```

### 6.2 Deterministic Pack Generation

```bash
cargo goaria-pack pack \
  --project-dir . \
  --out-dir dist \
  --key-file ~/.goaria/keys/key.priv
```

Output:
- `dist/my-extractor-0.1.0.pack.zip`: Deterministic ZIP containing `manifest.json`, `payload.wasm`, and `manifest.sig`.
- `dist/my-extractor.lock.json`: Companion lock file with cryptographic digests and public key.

---

## 7. Security Principles & Capabilities

1. **Host-Custody Credential Isolation**: Raw tokens and cookies never touch guest WebAssembly memory.
2. **Capability Declarations**: Extractors must declare `cap.parse.wasm`, `cap.http.fetch`, or `cap.auth.profile` in `manifest.json`.
3. **No-Name Policy / Zero Domain Leakage**: All tests, fixtures, and documentation strictly use RFC 2606 reserved domains (`fixture.invalid`, `example.com`).
4. **Supply Chain Integrity**: Every pack is digitally signed with Ed25519 and verified against the GoAria host trust policy before execution.
