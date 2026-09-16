use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Language {
    Rust,
    Zig,
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Rust => write!(f, "rust"),
            Language::Zig => write!(f, "zig"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SdkSource {
    Vendor,
    Git,
    Crates,
}

impl std::fmt::Display for SdkSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkSource::Vendor => write!(f, "vendor"),
            SdkSource::Git => write!(f, "git"),
            SdkSource::Crates => write!(f, "crates"),
        }
    }
}

/// GoAria Extractor Pack SDK Toolchain & CLI
#[derive(Parser, Debug)]
#[command(
    name = "cargo-goaria-pack",
    bin_name = "cargo goaria-pack",
    version,
    about = "CLI toolchain and local WASM runner for GoAria extractor packs",
    long_about = "Develop, build, test, sign, and package WebAssembly extractor packs for the GoAria download manager."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scaffold a new extractor pack project
    New(NewArgs),
    /// Build the extractor WebAssembly binary
    Build(BuildArgs),
    /// Statically analyze WASM exports, imports, and validate manifest.json
    Check(CheckArgs),
    /// Execute unit test fixtures in the local WASM interpreter sandbox
    Test(TestArgs),
    /// Run extractor matching and extraction interactively on a URL
    Run(RunArgs),
    /// Generate a new Ed25519 signing keypair for developer pack signing
    Keygen(KeygenArgs),
    /// Sign manifest.json with an Ed25519 private key to produce manifest.sig
    Sign(SignArgs),
    /// Build, check, sign, and package a deterministic .pack.zip archive and lockfile
    Pack(PackArgs),
}

#[derive(Args, Debug)]
pub struct NewArgs {
    /// Name of the extractor pack (e.g. 'fixture-extractor')
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Implementation language ('rust' or 'zig')
    #[arg(short, long, value_enum, default_value_t = Language::Rust)]
    pub lang: Language,

    /// SDK dependency source: 'vendor' embeds SDK sources into the project (default),
    /// 'git' depends on the GitHub repo, 'crates' uses the crates.io version
    #[arg(long, value_enum, value_name = "SOURCE")]
    pub sdk: Option<SdkSource>,

    /// Git revision (commit SHA, tag, or branch) for '--sdk git'
    #[arg(long, value_name = "REF")]
    pub sdk_ref: Option<String>,

    /// Path to a local goaria SDK package directory (mutually exclusive with --sdk;
    /// rust: dir containing the SDK Cargo.toml; zig: dir containing sdk/zig's build.zig.zon)
    #[arg(long, value_name = "DIR")]
    pub sdk_path: Option<PathBuf>,

    /// Target directory for project generation (defaults to ./<name>)
    #[arg(short, long, value_name = "PATH")]
    pub path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct BuildArgs {
    /// Target project directory (defaults to current directory)
    #[arg(short, long, value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,

    /// Build in release mode with optimizations
    #[arg(long, default_value_t = true)]
    pub release: bool,
}

#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Target project directory (defaults to current directory)
    #[arg(short, long, value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,

    /// Explicit path to compiled .wasm binary (optional)
    #[arg(short, long, value_name = "PATH")]
    pub wasm: Option<PathBuf>,

    /// Explicit path to manifest.json (optional)
    #[arg(short, long, value_name = "PATH")]
    pub manifest: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// Target project directory (defaults to current directory)
    #[arg(short, long, value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,

    /// Explicit path to compiled .wasm binary (optional)
    #[arg(short, long, value_name = "PATH")]
    pub wasm: Option<PathBuf>,

    /// Explicit path to manifest.json (optional)
    #[arg(short, long, value_name = "PATH")]
    pub manifest: Option<PathBuf>,

    /// Enable live network requests (by default tests run with MockBroker)
    #[arg(long)]
    pub live: bool,

    /// Path to custom test fixtures directory (optional)
    #[arg(long, value_name = "DIR")]
    pub fixtures: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Target URL to evaluate and extract
    #[arg(value_name = "URL")]
    pub url: String,

    /// Target project directory (defaults to current directory)
    #[arg(short, long, value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,

    /// Explicit path to compiled .wasm binary (optional)
    #[arg(short, long, value_name = "PATH")]
    pub wasm: Option<PathBuf>,

    /// Explicit path to manifest.json (optional)
    #[arg(short, long, value_name = "PATH")]
    pub manifest: Option<PathBuf>,

    /// Enable live HTTP network calls via LiveBroker
    #[arg(long)]
    pub live: bool,

    /// Auth profile identifier to simulate (optional)
    #[arg(long, value_name = "ID")]
    pub auth_profile: Option<String>,

    /// Auth secret value or token to inject for the profile (optional)
    #[arg(long, value_name = "SECRET")]
    pub auth_secret: Option<String>,
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// New path for the private signing key seed hex; existing files are never overwritten
    #[arg(long, value_name = "PATH", required = true)]
    pub out_seed: Option<PathBuf>,

    /// Path to write public key hex (optional)
    #[arg(long, value_name = "PATH")]
    pub out_pub: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    /// 32-byte seed hex string (64 hex chars) or path to private key file
    #[arg(short, long, value_name = "KEY_OR_PATH")]
    pub key: String,

    /// Path to manifest.json file to sign
    #[arg(short, long, value_name = "PATH", default_value = "manifest.json")]
    pub manifest: PathBuf,

    /// Path to output signature file (defaults to manifest.sig next to manifest)
    #[arg(short, long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct PackArgs {
    /// Target project directory (defaults to current directory)
    #[arg(short, long, value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,

    /// Output directory for .pack.zip and .lock.json (defaults to dist/)
    #[arg(short, long, value_name = "DIR", default_value = "dist")]
    pub out_dir: PathBuf,

    /// Ed25519 signing key seed hex or key file (optional; generates ephemeral key if omitted)
    #[arg(short = 'k', long, value_name = "KEY_OR_PATH")]
    pub sign_key: Option<String>,

    /// Custom output asset archive name (defaults to <pack_id>-<pack_version>.pack.zip)
    #[arg(long, value_name = "NAME")]
    pub asset_name: Option<String>,

    /// Skip compiling WASM if binary is already up-to-date
    #[arg(long)]
    pub skip_build: bool,
}
