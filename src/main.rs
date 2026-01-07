use anyhow::Result;
use clap::Parser;

use quest_cli::QuestCli;

fn main() -> Result<()> {
    let cli = QuestCli::parse().init_logging();

    cli.execute()
}
