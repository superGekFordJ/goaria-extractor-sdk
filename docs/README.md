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

Execute the extractor in the local WebAssembly sandbox with mock broker:

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

Annotate your extractor struct with `#[goaria_pack]` and `#[derive(Default)]` to automatically wire memory management and C-ABI exports:

```rust
use goaria_extractor_sdk::prelude::*;

#[goaria_pack]
#[derive(Default)]
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

    fn extract(&self, input: ExtractInput) -> Result<ExtractOutput, ExtractorError> {
        let broker = HostBroker::new();
        let api_url = format!("https://api.fixture.invalid/v1/resolve?url={}", urlencoding::encode(&input.url));
        let response = broker.fetch_json::<ApiItemResponse>(&HostHTTPFetchRequest {
            method: "GET".to_string(),
            url: api_url,
            broker_policy_ref: "standard_api".to_string(),
            endpoint_ref: "resolve_item".to_string(),
            ..Default::default()
        })?;

        let item = ExtractedItemRef {
            url: Some(response.download_url),
            filename: Some(response.filename),
            size_bytes: Some(response.size_bytes),
            mime_type: Some("application/octet-stream".to_string()),
            auth_profile_ref: Some("default".to_string()),
            ..Default::default()
        };

        Ok(ExtractOutput::single(item))
    }
}
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

pub const MyExtractor = struct {
    pub fn matchUrl(allocator: std.mem.Allocator, input: goaria.MatchInput) !goaria.MatchOutput {
        _ = allocator;
        if (std.mem.startsWith(u8, input.url, "https://share.fixture.invalid/")) {
            return goaria.MatchOutput.matchedResult()
                .withConfidence(100)
                .withReason("matched fixture domain");
        }
        return goaria.MatchOutput.unmatchedResult();
    }

    pub fn extract(allocator: std.mem.Allocator, input: goaria.ExtractInput) !goaria.ExtractOutput {
        _ = input;
        const item = goaria.ExtractedItemRef{
            .id = "artifact-001",
            .url = "https://download.fixture.invalid/artifact.bin",
            .filename = "artifact.bin",
            .size_bytes = 2048,
            .mime_type = "application/octet-stream",
        };

        return try goaria.ExtractOutput.single(allocator, item);
    }
};

comptime {
    goaria.exportExtractor(MyExtractor);
}
```

---

## 4. CLI Command Reference (`cargo-goaria-pack`)

| Command | Syntax | Description |
| :--- | :--- | :--- |
| `new` | `cargo goaria-pack new <NAME> [--lang rust\|zig] [--path <PATH>]` | Scaffolds a new extractor pack project. |
| `build` | `cargo goaria-pack build [--project-dir <DIR>] [--release]` | Compiles the extractor WebAssembly module. |
| `check` | `cargo goaria-pack check [--project-dir <DIR>] [--wasm <PATH>] [--manifest <PATH>]` | Statically analyzes WASM exports, imports, and validates manifest.json. |
| `test` | `cargo goaria-pack test [--project-dir <DIR>] [--live] [--fixtures <DIR>]` | Executes unit test fixtures in the local WASM interpreter sandbox. |
| `run` | `cargo goaria-pack run <URL> [--project-dir <DIR>] [--live] [--auth-profile <ID>] [--auth-secret <SECRET>]` | Runs extractor matching and extraction interactively on a URL. |
| `keygen` | `cargo goaria-pack keygen [--out-seed <PATH>] [--out-pub <PATH>]` | Generates a new Ed25519 signing keypair. |
| `sign` | `cargo goaria-pack sign --key <KEY_OR_PATH> [--manifest <PATH>] [--out <PATH>]` | Signs manifest.json with an Ed25519 private key. |
| `pack` | `cargo goaria-pack pack [--project-dir <DIR>] [--out-dir <DIR>] [-k, --sign-key <KEY_OR_PATH>] [--asset-name <NAME>] [--skip-build]` | Builds, checks, signs, and packages deterministic .pack.zip and lockfile. |

---

## 5. Testing & Sandboxing

### 5.1 Local Execution (`run`)

Test extraction with a mock broker:

```bash
cargo goaria-pack run https://share.fixture.invalid/item/123
```

Simulate an authenticated session with an auth profile:

```bash
cargo goaria-pack run https://share.fixture.invalid/item/123 \
  --auth-profile default \
  --auth-secret my-developer-token
```

Execute with live network access:

```bash
cargo goaria-pack run https://share.fixture.invalid/item/123 --live
```

### 5.2 Zero-Leak Memory Verification
The CLI's built-in WASM runtime tracks every byte allocated by `goaria_alloc` and deallocated by `goaria_free`. If an extractor leaks memory or panics, the runner reports a memory leak error with the exact count of uncollected bytes.

---

## 6. Packaging, Signing & Distribution

### 6.1 Cryptographic Key Generation

```bash
cargo goaria-pack keygen \
  --out-seed ~/.goaria/keys/seed.hex \
  --out-pub ~/.goaria/keys/key.pub
```

### 6.2 Deterministic Pack Generation

```bash
cargo goaria-pack pack \
  --project-dir . \
  --out-dir dist \
  --sign-key ~/.goaria/keys/seed.hex
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
