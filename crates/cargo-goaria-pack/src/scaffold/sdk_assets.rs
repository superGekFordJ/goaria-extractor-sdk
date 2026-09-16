// SDK sources embedded into the CLI binary so `new --sdk vendor` works without
// a repo checkout. include_str! paths reach outside this crate's directory,
// which would affect `cargo package`/`cargo publish` of this crate.

pub struct EmbeddedFile {
    pub rel_path: &'static str,
    pub contents: &'static str,
}

// This crate shares the workspace version with the SDK crates it embeds.
pub const EMBEDDED_SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SDK_GIT_URL: &str = "https://github.com/superGekFordJ/goaria-extractor-sdk";

pub const RUST_SDK_FILES: &[EmbeddedFile] = &[
    EmbeddedFile {
        rel_path: "src/abi.rs",
        contents: include_str!("../../../goaria-extractor-sdk/src/abi.rs"),
    },
    EmbeddedFile {
        rel_path: "src/alloc.rs",
        contents: include_str!("../../../goaria-extractor-sdk/src/alloc.rs"),
    },
    EmbeddedFile {
        rel_path: "src/broker.rs",
        contents: include_str!("../../../goaria-extractor-sdk/src/broker.rs"),
    },
    EmbeddedFile {
        rel_path: "src/error.rs",
        contents: include_str!("../../../goaria-extractor-sdk/src/error.rs"),
    },
    EmbeddedFile {
        rel_path: "src/host.rs",
        contents: include_str!("../../../goaria-extractor-sdk/src/host.rs"),
    },
    EmbeddedFile {
        rel_path: "src/lib.rs",
        contents: include_str!("../../../goaria-extractor-sdk/src/lib.rs"),
    },
    EmbeddedFile {
        rel_path: "src/prelude.rs",
        contents: include_str!("../../../goaria-extractor-sdk/src/prelude.rs"),
    },
    EmbeddedFile {
        rel_path: "src/traits.rs",
        contents: include_str!("../../../goaria-extractor-sdk/src/traits.rs"),
    },
    EmbeddedFile {
        rel_path: "src/types.rs",
        contents: include_str!("../../../goaria-extractor-sdk/src/types.rs"),
    },
];

pub const RUST_MACRO_FILES: &[EmbeddedFile] = &[EmbeddedFile {
    rel_path: "src/lib.rs",
    contents: include_str!("../../../goaria-extractor-macro/src/lib.rs"),
}];

pub const ZIG_SDK_FILES: &[EmbeddedFile] = &[
    EmbeddedFile {
        rel_path: "build.zig",
        contents: include_str!("../../../../sdk/zig/build.zig"),
    },
    EmbeddedFile {
        rel_path: "build.zig.zon",
        contents: include_str!("../../../../sdk/zig/build.zig.zon"),
    },
    EmbeddedFile {
        rel_path: "src/abi.zig",
        contents: include_str!("../../../../sdk/zig/src/abi.zig"),
    },
    EmbeddedFile {
        rel_path: "src/host.zig",
        contents: include_str!("../../../../sdk/zig/src/host.zig"),
    },
    EmbeddedFile {
        rel_path: "src/root.zig",
        contents: include_str!("../../../../sdk/zig/src/root.zig"),
    },
    EmbeddedFile {
        rel_path: "src/types.zig",
        contents: include_str!("../../../../sdk/zig/src/types.zig"),
    },
];

pub const VENDORED_SDK_CARGO_TOML: &str = r#"[package]
name = "goaria-extractor-sdk"
version = "{version}"
edition = "2021"
license = "MIT OR Apache-2.0"
repository = "https://github.com/superGekFordJ/goaria-extractor-sdk"
description = "Core Rust SDK for authoring GoAria WebAssembly extractor packs"

[dependencies]
serde = { version = "1.0", default-features = false, features = ["derive", "alloc"] }
serde_json = { version = "1.0", default-features = false, features = ["alloc"] }
base64 = { version = "0.22", default-features = false, features = ["alloc"] }
goaria-extractor-macro = { path = "../goaria-extractor-macro", version = "{version}" }
"#;

pub const VENDORED_MACRO_CARGO_TOML: &str = r#"[package]
name = "goaria-extractor-macro"
version = "{version}"
edition = "2021"
license = "MIT OR Apache-2.0"
repository = "https://github.com/superGekFordJ/goaria-extractor-sdk"
description = "Procedural macro generating C-ABI exports for GoAria extractor packs"

[lib]
proc-macro = true

[dependencies]
proc-macro2 = "1.0"
quote = "1.0"
syn = { version = "2.0", features = ["full", "extra-traits"] }
"#;

// zig 0.16 fingerprint: high 32 bits = CRC32-IEEE of the zon package name,
// low 32 = random id.
pub fn zig_fingerprint(zon_name: &str) -> u64 {
    ((crc32fast::hash(zon_name.as_bytes()) as u64) << 32) | (rand::random::<u32>() as u64)
}

// Normalize a pack name into a valid bare zig identifier for zon `.name`.
// Bare identifiers cannot be quoted, so names that start with a digit or
// collide with a keyword get a `pack_` prefix.
pub fn zig_package_name(pack_name: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "addrspace",
        "align",
        "allowzero",
        "and",
        "anyframe",
        "anytype",
        "asm",
        "async",
        "await",
        "break",
        "callconv",
        "catch",
        "comptime",
        "const",
        "continue",
        "defer",
        "else",
        "enum",
        "errdefer",
        "error",
        "export",
        "extern",
        "fn",
        "for",
        "if",
        "inline",
        "linksection",
        "noalias",
        "nosuspend",
        "opaque",
        "or",
        "orelse",
        "packed",
        "pub",
        "resume",
        "return",
        "struct",
        "suspend",
        "switch",
        "test",
        "threadlocal",
        "try",
        "union",
        "unreachable",
        "var",
        "volatile",
        "while",
    ];

    let normalized = pack_name.replace('-', "_");
    let first_ok = normalized
        .chars()
        .next()
        .map(|c| c.is_ascii_lowercase() || c == '_')
        .unwrap_or(false);
    if first_ok && !KEYWORDS.contains(&normalized.as_str()) {
        normalized
    } else {
        format!("pack_{normalized}")
    }
}

// PascalCase identifier for the extractor struct in generated zig source.
pub fn zig_struct_name(pack_name: &str) -> String {
    let mut out = String::new();
    for segment in pack_name.split(['-', '_']) {
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.extend(chars);
        }
    }
    if out
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic() || c == '_')
        .unwrap_or(false)
    {
        out
    } else {
        format!("Pack{out}")
    }
}
