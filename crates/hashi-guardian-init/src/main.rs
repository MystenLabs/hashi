// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;

mod ceremony;
mod config;
mod fetch_info;
mod guardian_info;
mod kp_ceremony;
mod kp_provision;
mod kp_roster;
mod kp_rotate_cert;
mod kp_rotate_kp_set;
mod operator_activate;
mod operator_ceremony;
mod operator_provision;
mod operator_rotate_kp_set;
mod submission;

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
        /// Explicitly bootstrap the first serving committee during PI.
        #[arg(long)]
        do_genesis: bool,
    },
    /// Activate a provisioner-initialized withdraw-mode guardian.
    Activate {
        /// Path to operator activate YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Re-deal the ceremony key to a new KP set on a fresh ceremony-mode guardian.
    RotateKpSet {
        #[command(subcommand)]
        command: OperatorRotateKpSetCommand,
    },
}

#[derive(Subcommand)]
enum OperatorRotateKpSetCommand {
    /// Operator-initialize the ceremony guardian the current KPs will sign for.
    Init {
        /// Path to operator YAML config file (with new_kp_roster).
        #[arg(long)]
        config: PathBuf,
    },
    /// Submit the current KPs' signed submissions, then wait for every new KP to confirm.
    Submit {
        /// Path to operator YAML config file (with new_kp_roster).
        #[arg(long)]
        config: PathBuf,
        /// A current KP's submission file (key-provisioner rotate-kp-set); repeat per KP.
        #[arg(long = "submission", required = true)]
        submissions: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum KeyProvisionerCommand {
    /// Replace this KP's configured signing certificate.
    RotateCert {
        /// Path to key-provisioner YAML config file.
        #[arg(long)]
        config: PathBuf,
        /// Path to the replacement armored OpenPGP public cert.
        #[arg(long)]
        new_kp_pgp_cert_path: PathBuf,
    },
    /// Verify, save, and confirm this KP's encrypted ceremony share.
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
        /// Explicitly authorize first-deploy genesis in this PI submission.
        #[arg(long)]
        do_genesis: bool,
    },
    /// Sign this KP's share of a proposed KP-set rotation into a submission file.
    RotateKpSet {
        /// Path to key-provisioner YAML config file (with new_kp_roster).
        #[arg(long)]
        config: PathBuf,
        /// Path at which to write the signed submission for the operator.
        #[arg(long)]
        submission_path: PathBuf,
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
            OperatorCommand::Provision { config, do_genesis } => {
                let cfg = config::Config::load_yaml(&config)?;
                operator_provision::run(cfg, do_genesis).await?;
            }
            OperatorCommand::Activate { config } => {
                let cfg = config::Config::load_yaml(&config)?;
                operator_activate::run(cfg).await?;
            }
            OperatorCommand::RotateKpSet { command } => match command {
                OperatorRotateKpSetCommand::Init { config } => {
                    let cfg = config::Config::load_yaml(&config)?;
                    operator_rotate_kp_set::init(cfg).await?;
                }
                OperatorRotateKpSetCommand::Submit {
                    config,
                    submissions,
                } => {
                    let cfg = config::Config::load_yaml(&config)?;
                    operator_rotate_kp_set::submit(cfg, &submissions).await?;
                }
            },
        },
        Command::KeyProvisioner { command } => match command {
            KeyProvisionerCommand::Ceremony {
                config,
                encrypted_shares_path,
            } => {
                let cfg = config::Config::load_yaml(&config)?;
                kp_ceremony::run(cfg, &encrypted_shares_path).await?;
            }
            KeyProvisionerCommand::Provision { config, do_genesis } => {
                let cfg = config::Config::load_yaml(&config)?;
                kp_provision::run(cfg, do_genesis).await?;
            }
            KeyProvisionerCommand::RotateCert {
                config,
                new_kp_pgp_cert_path,
            } => {
                let cfg = config::Config::load_yaml(&config)?;
                kp_rotate_cert::run(cfg, new_kp_pgp_cert_path).await?;
            }
            KeyProvisionerCommand::RotateKpSet {
                config,
                submission_path,
            } => {
                let cfg = config::Config::load_yaml(&config)?;
                kp_rotate_kp_set::run(cfg, &submission_path).await?;
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
    use clap::CommandFactory;

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

    #[test]
    fn key_provisioner_rotate_cert_help_exposes_only_the_singular_cert_path() {
        let mut command = Cli::command();
        let rotate_cert = command
            .find_subcommand_mut("key-provisioner")
            .expect("key-provisioner subcommand")
            .find_subcommand_mut("rotate-cert")
            .expect("rotate-cert subcommand");
        let mut rendered = Vec::new();
        rotate_cert
            .write_long_help(&mut rendered)
            .expect("render rotate-cert help");
        let help = String::from_utf8(rendered).expect("Clap help is UTF-8");

        assert!(help.contains("--new-kp-pgp-cert-path"), "{help}");
        assert!(!help.contains("--target-kp-pgp-fingerprint"), "{help}");
    }

    #[test]
    fn operator_rotate_kp_set_submit_collects_repeated_submissions() {
        let cli = Cli::try_parse_from([
            "hashi-guardian-init",
            "operator",
            "rotate-kp-set",
            "submit",
            "--config",
            "config.yaml",
            "--submission",
            "kp1.rotation",
            "--submission",
            "kp3.rotation",
        ])
        .unwrap();

        let Command::Operator {
            command:
                OperatorCommand::RotateKpSet {
                    command:
                        OperatorRotateKpSetCommand::Submit {
                            config,
                            submissions,
                        },
                },
        } = cli.command
        else {
            panic!("expected operator rotate-kp-set submit command");
        };
        assert_eq!(config, PathBuf::from("config.yaml"));
        assert_eq!(
            submissions,
            vec![PathBuf::from("kp1.rotation"), PathBuf::from("kp3.rotation")]
        );
    }

    #[test]
    fn operator_rotate_kp_set_submit_requires_a_submission() {
        let result = Cli::try_parse_from([
            "hashi-guardian-init",
            "operator",
            "rotate-kp-set",
            "submit",
            "--config",
            "config.yaml",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn key_provisioner_rotate_kp_set_requires_submission_path() {
        let result = Cli::try_parse_from([
            "hashi-guardian-init",
            "key-provisioner",
            "rotate-kp-set",
            "--config",
            "config.yaml",
        ]);

        assert!(result.is_err());
    }
}
