// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use hashi_guardian_ops::Ctx;
use hashi_guardian_ops::exec::System;
use hashi_guardian_ops::exec::require_programs;
use hashi_guardian_ops::stack::Slot;
use hashi_guardian_ops::steps::configs;
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
    /// Print the stack's slots, the proxy and the relay, changing nothing.
    Status,
    /// Print a slot's guardian through its tunnel, once the proxy is shown to lead to it.
    Info {
        /// The slot, which a stack with two slots requires.
        #[arg(long)]
        slot: Option<Slot>,
    },
    /// Print a slot's host: the end of its boot log, its enclave and its units.
    Host {
        /// The slot, which a stack with two slots requires.
        #[arg(long)]
        slot: Option<Slot>,
    },
    /// Forward a local port to a slot's guardian. Leave it running in its own terminal.
    Tunnel {
        /// The slot, which a stack with two slots requires.
        #[arg(long)]
        slot: Option<Slot>,
    },
    /// Write a slot's configuration for the operator and the key provisioners, and check it with the guardian's tools.
    Render {
        /// The slot, which a stack with two slots requires.
        #[arg(long)]
        slot: Option<Slot>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let ctx = Ctx::new(&cli.env_file, &System)?;
    require_programs(&System)?;
    match cli.command {
        Command::Status => inspect::status(&ctx),
        Command::Info { slot } => inspect::info(&ctx, slot),
        Command::Host { slot } => inspect::host(&ctx, slot),
        Command::Tunnel { slot } => inspect::tunnel(&ctx, slot),
        Command::Render { slot } => configs::render(&ctx, slot),
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

    #[test]
    fn slot_is_a_flag() {
        let cli = Cli::try_parse_from([
            "hashi-guardian-ops",
            "--env-file",
            "e",
            "info",
            "--slot",
            "b",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Info {
                slot: Some(Slot::B)
            }
        ));
        let cli = Cli::try_parse_from(["hashi-guardian-ops", "--env-file", "e", "info"]).unwrap();
        assert!(matches!(cli.command, Command::Info { slot: None }));
        assert!(
            Cli::try_parse_from(["hashi-guardian-ops", "--env-file", "e", "info", "b"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "hashi-guardian-ops",
                "--env-file",
                "e",
                "info",
                "--slot",
                "c"
            ])
            .is_err()
        );
    }
}
