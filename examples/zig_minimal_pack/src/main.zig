const std = @import("std");
const goaria = @import("goaria_sdk");

pub const MinimalExtractor = struct {
    pub fn matchUrl(allocator: std.mem.Allocator, input: goaria.MatchInput) !goaria.MatchOutput {
        _ = allocator;
        if (std.mem.indexOf(u8, input.url, "fixture.invalid") != null) {
            return goaria.MatchOutput.matchedResult()
                .withConfidence(100)
                .withReason("matches fixture.invalid test domain");
        }
        return goaria.MatchOutput.unmatchedResult();
    }

    pub fn extract(allocator: std.mem.Allocator, input: goaria.ExtractInput) !goaria.ExtractOutput {
        if (std.mem.indexOf(u8, input.url, "fixture.invalid") == null) {
            return goaria.ExtractOutput.empty();
        }

        const item = goaria.ExtractedItemRef{
            .id = "zig-item-001",
            .url = "https://download.fixture.invalid/artifact.bin",
            .filename = "artifact.bin",
            .size_bytes = 2048,
            .mime_type = "application/octet-stream",
        };

        return try goaria.ExtractOutput.single(allocator, item);
    }
};

comptime {
    goaria.exportExtractor(MinimalExtractor);
}
