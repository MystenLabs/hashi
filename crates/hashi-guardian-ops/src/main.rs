// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::bail;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use hashi_guardian_ops::Ctx;
use hashi_guardian_ops::ask::Terminal;
use hashi_guardian_ops::exec::System;
use hashi_guardian_ops::exec::require_programs;
use hashi_guardian_ops::stack::Slot;
use hashi_guardian_ops::steps::configs;
use hashi_guardian_ops::steps::deploy;
use hashi_guardian_ops::steps::inspect;
use hashi_guardian_ops::steps::kp_keys;
use hashi_guardian_ops::steps::session;
use hashi_guardian_ops::steps::session::OperatorStep;

/// Runs one operator step against the guardian stack an environment file names. With two guardian slots, name the
/// slot. See operator/deploy.md.
#[derive(Parser)]
#[command(name = "hashi-guardian-ops")]
struct Cli {
    /// The environment file: a copy of operator/guardian.env.sample.
    env_file: PathBuf,
    #[command(subcommand)]
    step: Step,
}

#[derive(Subcommand)]
enum Step {
    /// Print the stack's slots, the proxy, the relay and the Sui epoch, changing nothing.
    Status,
    /// Print a slot's guardian through its tunnel, once the proxy is shown to lead to it.
    Info { slot: Option<Slot> },
    /// Print a slot's host: the end of its boot log, its enclave and its units.
    Host { slot: Option<Slot> },
    /// Forward a local port to a slot's guardian. Leave it running in its own terminal.
    Tunnel { slot: Option<Slot> },
    /// Write a slot's configuration for the operator and the key provisioners, and check it with the guardian's tools.
    Render { slot: Option<Slot> },
    /// Publish a slot's configuration to the key provisioners' bucket: `publish [slot] [rotate-kp-set]`.
    Publish {
        #[arg(value_name = "SLOT] [rotate-kp-set")]
        args: Vec<String>,
    },
    /// Measure a slot's build on GitHub's two runners, or check a run: `measure [slot] [run-id]`.
    Measure {
        #[arg(value_name = "SLOT] [RUN_ID")]
        args: Vec<String>,
    },
    /// Apply the whole enclave stack, for a guardian's first deployment.
    Deploy,
    /// Build the proxy at the active slot's commit and roll it, through sui-operations' workflow.
    Proxy,
    /// Run the key ceremony on a slot's fresh guardian.
    Ceremony { slot: Option<Slot> },
    /// Restart a slot's enclave, so its guardian starts a fresh session.
    NewSession {
        slot: Option<Slot>,
        /// Restart even a ceremony that has dealt shares not every key provisioner has confirmed.
        #[arg(long)]
        abandon: bool,
    },
    /// Initialize a slot's guardian for the key provisioners to provision.
    Provision {
        slot: Option<Slot>,
        /// For the guardian's first deployment only.
        #[arg(long)]
        do_genesis: bool,
    },
    /// Activate a slot's provisioned guardian.
    Activate { slot: Option<Slot> },
    /// Create the key provisioners' upload bucket and an access key that can only upload into it.
    CreateKpUploadBucket,
    /// Delete the upload key once the key provisioners no longer need it.
    RevokeKpUploadKey,
    /// Download and verify every key provisioner's uploaded public key, then write the roster.
    DownloadKpPubkeys {
        /// A directory that doesn't exist yet. Defaults to .hashi/kp-pubkeys/<KP_NAME>-<UTC time>.
        out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("\nERROR: {error}");
            for cause in error.chain().skip(1) {
                eprintln!("  {cause}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let ctx = Ctx::new(&cli.env_file, &System, &Terminal)?;
    require_programs(&System)?;
    match cli.step {
        Step::Status => inspect::status(&ctx),
        Step::Info { slot } => inspect::info(&ctx, slot),
        Step::Host { slot } => inspect::host(&ctx, slot),
        Step::Tunnel { slot } => inspect::tunnel(&ctx, slot),
        Step::Render { slot } => configs::render(&ctx, slot),
        Step::Publish { args } => {
            let (slot, rest) = leading_slot(&args);
            match rest {
                [] => configs::publish(&ctx, slot, false),
                [what] if what == "rotate-kp-set" => configs::publish(&ctx, slot, true),
                _ => bail!("Usage: publish [slot] [rotate-kp-set]"),
            }
        }
        Step::Measure { args } => {
            let (slot, rest) = leading_slot(&args);
            match rest {
                [] => deploy::measure(&ctx, slot, None),
                [run_id] => deploy::measure(&ctx, slot, Some(run_id.clone())),
                _ => bail!("Usage: measure [slot] [run-id]"),
            }
        }
        Step::Deploy => deploy::deploy(&ctx),
        Step::Proxy => deploy::proxy(&ctx),
        Step::Ceremony { slot } => session::operator(&ctx, slot, OperatorStep::Ceremony),
        Step::NewSession { slot, abandon } => session::new_session(&ctx, slot, abandon),
        Step::Provision { slot, do_genesis } => {
            session::operator(&ctx, slot, OperatorStep::Provision { do_genesis })
        }
        Step::Activate { slot } => session::operator(&ctx, slot, OperatorStep::Activate),
        Step::CreateKpUploadBucket => kp_keys::create_kp_upload_bucket(&ctx),
        Step::RevokeKpUploadKey => kp_keys::revoke_kp_upload_key(&ctx),
        Step::DownloadKpPubkeys { out } => kp_keys::download_kp_pubkeys(&ctx, out),
    }
}

/// A step's optional leading slot, which clap can't tell from the positional arguments after it.
fn leading_slot(args: &[String]) -> (Option<Slot>, &[String]) {
    match args.split_first() {
        Some((first, rest)) => match Slot::from_str(first, false) {
            Ok(slot) => (Some(slot), rest),
            Err(_) => (None, args),
        },
        None => (None, args),
    }
}
