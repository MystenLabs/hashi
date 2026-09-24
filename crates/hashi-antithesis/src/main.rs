// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Drivers for the hashi Antithesis environment (`docker/antithesis`): a
//! one-shot `bootstrap` that turns a fresh Sui cluster + bitcoind into a
//! running hashi deployment, a test `guardian`, and the `workload` that
//! exercises deposits and withdrawals under fault injection.

use clap::Parser;
use clap::Subcommand;

mod bootstrap;
mod env;
mod guardian;
mod workload;

#[derive(Parser)]
#[command(name = "hashi-antithesis")]
struct Cli {
    #[command(flatten)]
    common: env::CommonArgs,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish hashi, hand each hashi node its config, launch genesis, and
    /// signal Antithesis that setup is complete.
    Bootstrap(bootstrap::Args),
    /// Serve a test guardian that activates itself once DKG output is on-chain.
    Guardian(guardian::Args),
    /// Mine blocks and drive deposits and withdrawals, asserting invariants.
    Workload(workload::Args),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    antithesis_sdk::antithesis_init();
    hashi_types::telemetry::TelemetryConfig::new()
        .with_default_level(tracing::level_filters::LevelFilter::INFO)
        .with_env()
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Bootstrap(args) => bootstrap::run(&cli.common, args).await,
        Command::Guardian(args) => guardian::run(&cli.common, args).await,
        Command::Workload(args) => workload::run(&cli.common, args).await,
    }
}
