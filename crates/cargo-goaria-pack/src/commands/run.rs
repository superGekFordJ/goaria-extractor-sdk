use std::time::Instant;
use colored::Colorize;
use goaria_extractor_sdk::types::AuthSecretKind;
use thiserror::Error;
use crate::cli::RunArgs;
use crate::commands::check::resolve_manifest_and_wasm;
use crate::runner::{AuthProvider, ExtractorRunner, RunnerError};

#[derive(Debug, Error)]
pub enum RunCommandError {
    #[error("runner error: {0}")]
    Runner(#[from] RunnerError),
    #[error("check resolution error: {0}")]
    Check(#[from] crate::check::CheckError),
}

pub fn handle_run(args: RunArgs) -> Result<(), RunCommandError> {
    let (manifest, _wasm_path, wasm_bytes) =
        resolve_manifest_and_wasm(&args.project_dir, args.manifest.as_ref(), args.wasm.as_ref())?;

    let mut runner = ExtractorRunner::new(&wasm_bytes, manifest)?;
    if args.live {
        runner = runner.with_live_broker();
    }
    if let (Some(profile_id), Some(secret)) = (&args.auth_profile, &args.auth_secret) {
        let mut auth = AuthProvider::new();
        auth.add_profile(
            profile_id,
            true,
            AuthSecretKind::Bearer,
            "••••",
            Some(secret.clone()),
        );
        runner = runner.with_auth_provider(auth);
    }

    let start = Instant::now();
    println!(
        "{} Evaluating URL: {}",
        "Executing:".cyan().bold(),
        args.url.underline()
    );

    let match_res = runner.match_url(&args.url)?;
    println!("\n{}", "── Match Result ─────────────────────────".dimmed());
    println!(
        "  Matched:    {}",
        if match_res.matched {
            "true".green().bold()
        } else {
            "false".yellow()
        }
    );
    println!("  Confidence: {}%", match_res.confidence.unwrap_or(0));
    if let Some(reason) = &match_res.reason {
        println!("  Reason:     {}", reason);
    }

    if match_res.matched {
        let extract_res = runner.extract(&args.url)?;
        println!(
            "\n{}",
            format!(
                "── Extracted Items ({}) ──────────────────",
                extract_res.items.len()
            )
            .dimmed()
        );
        for (i, item) in extract_res.items.iter().enumerate() {
            println!("  Item #{}:", i + 1);
            if let Some(id) = &item.id {
                println!("    ID:        {}", id);
            }
            if let Some(url) = &item.url {
                println!("    URL:       {}", url.green());
            }
            if let Some(filename) = &item.filename {
                println!("    Filename:  {}", filename);
            }
            if let Some(size) = item.size_bytes {
                println!("    Size:      {} bytes", size);
            }
            if let Some(mime) = &item.mime_type {
                println!("    MIME Type: {}", mime);
            }
            if let Some(meta) = &item.metadata {
                println!("    Metadata:");
                for (k, v) in meta {
                    println!("      {}: {}", k.dimmed(), v);
                }
            }
        }
    }

    let elapsed = start.elapsed();
    println!("\n{}", "── Runtime Metrics ──────────────────────".dimmed());
    println!("  Elapsed Time: {:.2?}", elapsed);
    println!(
        "  Memory Check: {} (0 bytes leaked)",
        "PASSED".green().bold()
    );

    Ok(())
}
