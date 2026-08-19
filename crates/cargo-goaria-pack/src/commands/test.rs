use std::time::Instant;
use colored::Colorize;
use thiserror::Error;
use crate::cli::TestArgs;
use crate::commands::check::resolve_manifest_and_wasm;
use crate::runner::{ExtractorRunner, RunnerError};

#[derive(Debug, Error)]
pub enum TestCommandError {
    #[error("runner error: {0}")]
    Runner(#[from] RunnerError),
    #[error("check resolution error: {0}")]
    Check(#[from] crate::check::CheckError),
    #[error("test failure: {0}")]
    TestFailed(String),
}

pub fn handle_test(args: TestArgs) -> Result<(), TestCommandError> {
    let (manifest, wasm_path, wasm_bytes) =
        resolve_manifest_and_wasm(&args.project_dir, args.manifest.as_ref(), args.wasm.as_ref())?;

    println!(
        "{} running test suite on {} (pack_id: '{}')...\n",
        "Testing:".cyan().bold(),
        wasm_path.display(),
        manifest.pack_id
    );

    let start = Instant::now();
    let runner = ExtractorRunner::new(&wasm_bytes, manifest.clone())?;
    let runner = if args.live {
        runner.with_live_broker()
    } else {
        runner
    };

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: ABI Version Check
    print!("  test abi_version negotiation ... ");
    match runner.check_abi() {
        Ok(ver) => {
            println!("{} (ABI v{})", "ok".green(), ver);
            passed += 1;
        }
        Err(e) => {
            println!("{} ({})", "FAILED".red().bold(), e);
            failed += 1;
        }
    }

    // Test 2: Domain matching & extraction tests from manifest domains
    for domain in &manifest.domains {
        let test_url = format!("https://{}/test-resource-001", domain.host);
        print!("  test match_url('{}') ... ", test_url);
        match runner.match_url(&test_url) {
            Ok(match_out) => {
                if match_out.matched {
                    println!(
                        "{} (confidence: {}%)",
                        "ok".green(),
                        match_out.confidence.unwrap_or(0)
                    );
                    passed += 1;

                    // Test extract
                    print!("  test extract('{}') ... ", test_url);
                    match runner.extract(&test_url) {
                        Ok(extract_out) => {
                            println!("{} (items: {})", "ok".green(), extract_out.items.len());
                            passed += 1;
                        }
                        Err(e) => {
                            println!("{} ({})", "FAILED".red().bold(), e);
                            failed += 1;
                        }
                    }
                } else {
                    println!("{} (unmatched)", "ok".yellow());
                    passed += 1;
                }
            }
            Err(e) => {
                println!("{} ({})", "FAILED".red().bold(), e);
                failed += 1;
            }
        }
    }

    // Test 3: Negative match URL
    let negative_url = "https://unrelated.example.invalid/path";
    print!("  test negative match_url('{}') ... ", negative_url);
    match runner.match_url(negative_url) {
        Ok(match_out) => {
            if !match_out.matched {
                println!("{}", "ok".green());
                passed += 1;
            } else {
                println!(
                    "{} (unexpected match on foreign domain)",
                    "FAILED".red().bold()
                );
                failed += 1;
            }
        }
        Err(e) => {
            println!("{} ({})", "FAILED".red().bold(), e);
            failed += 1;
        }
    }

    let duration = start.elapsed();
    println!(
        "\nTest result: {}. {} passed; {} failed; finished in {:.2?}",
        if failed == 0 {
            "ok".green().bold()
        } else {
            "FAILED".red().bold()
        },
        passed,
        failed,
        duration
    );

    if failed > 0 {
        Err(TestCommandError::TestFailed(format!(
            "{} test(s) failed",
            failed
        )))
    } else {
        Ok(())
    }
}
