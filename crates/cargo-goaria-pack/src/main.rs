use clap::Parser;
use colored::Colorize;
use cargo_goaria_pack::cli::{Cli, Command};
use cargo_goaria_pack::commands::*;

fn main() {
    // Handle cargo invoking us as `cargo goaria-pack ...`
    let mut args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "goaria-pack" {
        args.remove(1);
    }

    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            e.exit();
        }
    };

    let result = match cli.command {
        Command::New(args) => handle_new(args).map_err(|e| e.to_string()),
        Command::Build(args) => handle_build(args).map(|_| ()).map_err(|e| e.to_string()),
        Command::Check(args) => handle_check(args).map_err(|e| e.to_string()),
        Command::Test(args) => handle_test(args).map_err(|e| e.to_string()),
        Command::Run(args) => handle_run(args).map_err(|e| e.to_string()),
        Command::Keygen(args) => handle_keygen(args).map_err(|e| e.to_string()),
        Command::Sign(args) => handle_sign(args).map(|_| ()).map_err(|e| e.to_string()),
        Command::Pack(args) => handle_pack(args).map(|_| ()).map_err(|e| e.to_string()),
    };

    if let Err(err) = result {
        eprintln!("{} {}", "Error:".red().bold(), err);
        std::process::exit(1);
    }
}
