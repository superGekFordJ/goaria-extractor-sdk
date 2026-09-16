use crate::cli::NewArgs;
use crate::scaffold::sdk_assets::{EMBEDDED_SDK_VERSION, SDK_GIT_URL};
use crate::scaffold::{resolve_sdk_spec, scaffold_project, ScaffoldError, SdkSpec};
use colored::Colorize;
use std::path::PathBuf;

fn describe_sdk_spec(spec: &SdkSpec) -> String {
    match spec {
        SdkSpec::Vendor => {
            format!("vendored goaria SDK {EMBEDDED_SDK_VERSION} (vendor/)")
        }
        SdkSpec::Git { git_ref } => match git_ref {
            Some(git_ref) => format!("git {SDK_GIT_URL} @ {git_ref}"),
            None => format!("git {SDK_GIT_URL}"),
        },
        SdkSpec::Crates => format!("crates.io goaria-extractor-sdk {EMBEDDED_SDK_VERSION}"),
        SdkSpec::Path(dir) => {
            format!("local path {}", crate::scaffold::forward_slash_path(dir))
        }
    }
}

pub fn handle_new(args: NewArgs) -> Result<(), ScaffoldError> {
    let target_dir = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from(&args.name));
    let spec = resolve_sdk_spec(args.lang, args.sdk, args.sdk_ref, args.sdk_path)?;

    println!(
        "{} new {} extractor pack in {}",
        "Creating".green().bold(),
        args.lang.to_string().cyan(),
        target_dir.display()
    );
    println!(
        "  {} {}",
        "SDK source:".cyan().bold(),
        describe_sdk_spec(&spec)
    );

    scaffold_project(&args.name, args.lang, &target_dir, &spec)?;

    println!(
        "{} Created pack project '{}'",
        "Success:".green().bold(),
        args.name
    );
    println!("\nNext steps:");
    println!("  cd {}", target_dir.display());
    println!("  cargo goaria-pack build");
    println!("  cargo goaria-pack check");
    println!("  cargo goaria-pack test");
    Ok(())
}
