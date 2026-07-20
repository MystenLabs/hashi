// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;

mod config;
mod fetch_info;
mod guardian_info;
mod kp_ceremony;
mod kp_provision;
mod kp_roster;
mod operator_activate;
mod operator_ceremony;
mod operator_provision;

#[derive(Parser)]
#[command(name = "hashi-guardian-init")]
#[command(about = "Off-enclave tooling to initialize a guardian")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Commands run by the guardian operator.
    Operator {
        #[command(subcommand)]
        command: OperatorCommand,
    },
    /// Commands run by a key provisioner.
    KeyProvisioner {
        #[command(subcommand)]
        command: KeyProvisionerCommand,
    },
    /// Guardian helper tooling.
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },
}

#[derive(Subcommand)]
enum OperatorCommand {
    /// Run the one-time production guardian key ceremony.
    Ceremony {
        /// Path to operator ceremony YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Initialize a withdraw-mode guardian with operator-supplied stable config.
    Provision {
        /// Path to operator provision YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Activate a provisioner-initialized withdraw-mode guardian.
    Activate {
        /// Path to operator activate YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyProvisionerCommand {
    /// Verify this KP can fetch and decrypt its encrypted ceremony share from guardian S3.
    Ceremony {
        /// Path to key-provisioner ceremony YAML config file.
        #[arg(long)]
        config: PathBuf,
        /// Path at which to save the ceremony state containing the encrypted shares.
        #[arg(long)]
        encrypted_shares_path: PathBuf,
    },
    /// Run a key provisioner's init checks and submit its share to the relay.
    Provision {
        /// Path to key-provisioner provision YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ToolsCommand {
    /// Fetch deployed guardian public keys.
    FetchInfo {
        #[command(flatten)]
        args: fetch_info::Args,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_target(false)
        .with_env()
        .init();
    hashi::init_crypto_provider();

    match Cli::parse().command {
        Command::Operator { command } => match command {
            OperatorCommand::Ceremony { config } => {
                let cfg = config::Config::load_yaml(&config)?;
                operator_ceremony::run(cfg).await?;
            }
            OperatorCommand::Provision { config } => {
                let cfg = config::Config::load_yaml(&config)?;
                operator_provision::run(cfg).await?;
            }
            OperatorCommand::Activate { config } => {
                let cfg = config::Config::load_yaml(&config)?;
                operator_activate::run(cfg).await?;
            }
        },
        Command::KeyProvisioner { command } => match command {
            KeyProvisionerCommand::Ceremony {
                config,
                encrypted_shares_path,
            } => {
                let cfg = config::Config::load_yaml(&config)?;
                kp_ceremony::run(cfg, &encrypted_shares_path).await?;
            }
            KeyProvisionerCommand::Provision { config } => {
                let cfg = config::Config::load_yaml(&config)?;
                kp_provision::run(cfg).await?;
            }
        },
        Command::Tools { command } => match command {
            ToolsCommand::FetchInfo { args } => fetch_info::run(args).await?,
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_provisioner_ceremony_requires_encrypted_shares_path() {
        let result = Cli::try_parse_from([
            "hashi-guardian-init",
            "key-provisioner",
            "ceremony",
            "--config",
            "config.yaml",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn key_provisioner_ceremony_accepts_encrypted_shares_path() {
        let cli = Cli::try_parse_from([
            "hashi-guardian-init",
            "key-provisioner",
            "ceremony",
            "--config",
            "config.yaml",
            "--encrypted-shares-path",
            "kp-shares.json",
        ])
        .unwrap();

        let Command::KeyProvisioner {
            command:
                KeyProvisionerCommand::Ceremony {
                    config,
                    encrypted_shares_path,
                },
        } = cli.command
        else {
            panic!("expected key-provisioner ceremony command");
        };
        assert_eq!(config, PathBuf::from("config.yaml"));
        assert_eq!(encrypted_shares_path, PathBuf::from("kp-shares.json"));
    }
}
