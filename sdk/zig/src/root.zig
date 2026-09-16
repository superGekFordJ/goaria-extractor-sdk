//! Guest-side SDK for building GoAria extractor packs in Zig.
//!
//! Define a struct with `matchUrl` and `extract` methods, call
//! `exportExtractor` on it from a comptime block, and compile to wasm32.
//! The generated entrypoints exchange UTF-8 JSON with the host through
//! guest-memory buffers using the packed `ptr << 32 | len` convention
//! defined by ABI v1.

const std = @import("std");

/// Serde DTOs matching the ABI v1 wire schema.
pub const types = @import("types.zig");
/// ABI v1 constants, result packing, and the `exportExtractor` helper.
pub const abi = @import("abi.zig");
/// `HostBroker` client plus the raw `goaria_host` import declarations.
pub const host = @import("host.zig");

// Re-export common types for top-level convenience
/// Input payload passed to `goaria_match`.
pub const MatchInput = types.MatchInput;
/// Output payload returned by `goaria_match`.
pub const MatchOutput = types.MatchOutput;
/// Input payload passed to `goaria_extract`.
pub const ExtractInput = types.ExtractInput;
/// Output payload returned by `goaria_extract`.
pub const ExtractOutput = types.ExtractOutput;
pub const ExtractedItemRef = types.ExtractedItemRef;
/// Kind of authentication secret held in a host-custody auth profile.
pub const AuthSecretKind = types.AuthSecretKind;
/// Key-value string map (e.g. metadata, params, request headers).
pub const StringMap = types.StringMap;
/// Multi-value header map (e.g. response headers).
pub const HeaderMap = types.HeaderMap;

/// Manifest capability: compile and instantiate the WebAssembly payload.
pub const CAPABILITY_PARSE_WASM = types.CAPABILITY_PARSE_WASM;
/// Manifest capability: invoke goaria_host.http_fetch (GET/HEAD, safe headers).
pub const CAPABILITY_HTTP_FETCH = types.CAPABILITY_HTTP_FETCH;
/// Manifest capability: extended fetch features (POST, request body,
/// pack-owned Authorization or X-* headers). Requires cap.http.fetch.
pub const CAPABILITY_HTTP_FETCH_EXTENDED = types.CAPABILITY_HTTP_FETCH_EXTENDED;
/// Manifest capability: use host-custody auth profiles.
pub const CAPABILITY_AUTH_PROFILE = types.CAPABILITY_AUTH_PROFILE;

/// Request payload sent to host import `goaria_host.http_fetch`.
pub const HostHTTPFetchRequest = types.HostHTTPFetchRequest;
/// Response payload received from host import `goaria_host.http_fetch`.
pub const HostHTTPFetchResponse = types.HostHTTPFetchResponse;
/// Request payload sent to host import `goaria_host.auth_profile_status`.
pub const HostAuthProfileStatusRequest = types.HostAuthProfileStatusRequest;
/// Response payload received from `goaria_host.auth_profile_status`.
pub const HostAuthProfileStatusResponse = types.HostAuthProfileStatusResponse;

/// RAII owner for a buffer allocated in guest memory (frees on `deinit`).
pub const GuestBuffer = abi.GuestBuffer;
/// Pack pointer and length into a single 64-bit ABI return value.
pub const packResult = abi.packResult;
/// Unpack a 64-bit ABI value into its pointer and length components.
pub const unpackResult = abi.unpackResult;
/// Serialize a value to JSON in guest memory; returns the packed handle.
pub const packJsonResponse = abi.packJsonResponse;
/// Allocator appropriate for the current target (wasm or native test).
pub const getAllocator = abi.getAllocator;
/// Comptime helper exporting all 5 mandatory ABI v1 guest functions.
pub const exportExtractor = abi.exportExtractor;

/// High-level client for the `goaria_host` broker imports.
pub const HostBroker = host.HostBroker;

test {
    _ = @import("types.zig");
    _ = @import("abi.zig");
    _ = @import("host.zig");
}
