use std::io::Write;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use update_informer::{Check, registry};

use quest_cli::QuestCli;

fn main() -> Result<()> {
    let name = env!("CARGO_PKG_NAME");
    let current = env!("CARGO_PKG_VERSION");
    let informer = update_informer::new(registry::Crates, name, current);
    let cli = QuestCli::parse().init_logging();

    let result = cli.execute();
    if let Ok(Some(version)) = informer.check_version() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr);
        let _ = writeln!(stderr, "{}\n", "New version available!".yellow().bold());
        let _ = writeln!(
            stderr,
            "{} {} {}",
            format!("v{current}").red(),
            "->".bright_black(),
            version.to_string().green().bold()
        );
        let _ = writeln!(stderr);
        let _ = writeln!(stderr, "{} cargo install quest-cli", "Run:".cyan());
        let _ = writeln!(stderr);
    }

    result
}
