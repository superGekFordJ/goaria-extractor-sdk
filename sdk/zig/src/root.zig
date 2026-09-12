const std = @import("std");

pub const types = @import("types.zig");
pub const abi = @import("abi.zig");
pub const host = @import("host.zig");

// Re-export common types for top-level convenience
pub const MatchInput = types.MatchInput;
pub const MatchOutput = types.MatchOutput;
pub const ExtractInput = types.ExtractInput;
pub const ExtractOutput = types.ExtractOutput;
pub const ExtractedItemRef = types.ExtractedItemRef;
pub const AuthSecretKind = types.AuthSecretKind;
pub const StringMap = types.StringMap;
pub const HeaderMap = types.HeaderMap;

pub const CAPABILITY_PARSE_WASM = types.CAPABILITY_PARSE_WASM;
pub const CAPABILITY_HTTP_FETCH = types.CAPABILITY_HTTP_FETCH;
pub const CAPABILITY_HTTP_FETCH_EXTENDED = types.CAPABILITY_HTTP_FETCH_EXTENDED;
pub const CAPABILITY_AUTH_PROFILE = types.CAPABILITY_AUTH_PROFILE;

pub const HostHTTPFetchRequest = types.HostHTTPFetchRequest;
pub const HostHTTPFetchResponse = types.HostHTTPFetchResponse;
pub const HostAuthProfileStatusRequest = types.HostAuthProfileStatusRequest;
pub const HostAuthProfileStatusResponse = types.HostAuthProfileStatusResponse;

pub const GuestBuffer = abi.GuestBuffer;
pub const packResult = abi.packResult;
pub const unpackResult = abi.unpackResult;
pub const packJsonResponse = abi.packJsonResponse;
pub const getAllocator = abi.getAllocator;
pub const exportExtractor = abi.exportExtractor;

pub const HostBroker = host.HostBroker;

test {
    _ = @import("types.zig");
    _ = @import("abi.zig");
    _ = @import("host.zig");
}
