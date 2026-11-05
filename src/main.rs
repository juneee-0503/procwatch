//! procwatch: see `docs/README.md`, and `docs/architecture.md` for how the
//! modules below fit together.

mod activity;
mod app;
mod cli;
mod common;
mod defense;
mod detection;
mod engine;
mod files;
mod forensics;
mod host;
mod kernel;
mod network;
mod performance;
mod process;
mod response;
mod ui;
#[cfg(test)]
mod architecture;
#[cfg(test)]
mod fuzz;

fn main() -> anyhow::Result<()> {
    cli::main()
}
