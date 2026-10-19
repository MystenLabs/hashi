// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use hashi_guardian_ops::Ctx;
use hashi_guardian_ops::exec::System;
use hashi_guardian_ops::exec::require_programs;
use hashi_guardian_ops::steps::inspect;

#[derive(Parser)]
#[command(name = "hashi-guardian-ops")]
#[command(about = "Run one guardian operator step against the stack an environment file names")]
struct Cli {
    /// Path to the environment file, a copy of crates/hashi-guardian-ops/guardian.env.sample.
    #[arg(long)]
    env_file: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the stack's slots and the proxy, changing nothing.
    Status,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let ctx = Ctx::new(&cli.env_file, &System)?;
    require_programs(&System)?;
    match cli.command {
        Command::Status => inspect::status(&ctx),
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn env_file_is_required() {
        assert!(Cli::try_parse_from(["hashi-guardian-ops", "status"]).is_err());
        let cli =
            Cli::try_parse_from(["hashi-guardian-ops", "--env-file", "testnet.env", "status"])
                .unwrap();
        assert_eq!(cli.env_file, PathBuf::from("testnet.env"));
        assert!(matches!(cli.command, Command::Status));
    }
}
