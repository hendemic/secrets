// Entry point - CLI parsing and wiring



use clap::Parser;

mod app;
mod backend;
mod command;
mod config;
mod error;

use crate::app::App;
use crate::command::Command;

#[derive(Parser)]
#[command(name = "secrets")]
#[command(about = "Manage encrypted secrets")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), error::Error> {
    dotenvy::dotenv().ok();
    
    let cli = Cli::parse();
    let config = config::Config::load()?;
    let mut app = App::new(config);
    app.run(cli.command)
}
