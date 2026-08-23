use crate::cli::NewArgs;
use crate::scaffold::{scaffold_project, ScaffoldError};
use colored::Colorize;
use std::path::PathBuf;

pub fn handle_new(args: NewArgs) -> Result<(), ScaffoldError> {
    let target_dir = args.path.unwrap_or_else(|| PathBuf::from(&args.name));
    println!(
        "{} new {} extractor pack in {}",
        "Creating".green().bold(),
        args.lang.to_string().cyan(),
        target_dir.display()
    );

    scaffold_project(&args.name, args.lang, &target_dir)?;

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
