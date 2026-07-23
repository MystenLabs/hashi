// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Drives deposit -> mint -> withdraw -> settle loops against a deployed Hashi
//! bridge, for load testing and post-deploy verification.
//!
//! The bridge work goes through the same library the `hashi` CLI uses. What
//! this owns is everything around it that is easy to get wrong: reading the
//! deployment's real ids, funding many deposit UTXOs without tripping Bitcoin
//! Core's coin selection, retrying PTBs, and knowing when a run has actually
//! finished.

mod bridge;
mod btc;
mod config;
mod run;
mod ui;

use anyhow::Result;
use clap::Parser;
use clap::Subcommand;

use crate::config::CommonOpts;
use crate::run::LoopOpts;
use crate::run::Mode;

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
#[clap(name = "loadtest")]
#[clap(about = "Run deposit/withdraw loops against a deployed Hashi bridge")]
#[clap(styles = hashi::cli::STYLES)]
struct Args {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    common: CommonOpts,
}

#[derive(Subcommand)]
enum Command {
    /// Check that a run would work, without spending anything
    Doctor,

    /// Run the full loop: fund, register, wait for mint, withdraw, settle
    Run(Box<LoopOpts>),

    /// Deposit half only: fund, register, wait for mint
    Deposit(Box<LoopOpts>),

    /// Withdraw half only, against hBTC already held
    Withdraw(Box<LoopOpts>),
}

#[tokio::main]
async fn main() -> Result<()> {
    hashi::init_crypto_provider();
    let args = Args::parse();

    match args.command {
        Command::Doctor => run::doctor(&args.common).await,
        Command::Run(opts) => run::run(&args.common, &opts, Mode::Full).await,
        Command::Deposit(opts) => run::run(&args.common, &opts, Mode::DepositOnly).await,
        Command::Withdraw(opts) => run::run(&args.common, &opts, Mode::WithdrawOnly).await,
    }
}
