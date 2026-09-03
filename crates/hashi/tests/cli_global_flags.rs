// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The global CLI flags parse in any position. `main.rs` flattens
//! `CliGlobalOpts` beside each top-level subcommand, so this mirrors that
//! shape and checks that `-y`, `--dry-run` and friends are accepted after the
//! leaf subcommand as well as before it.

use clap::Parser;
use hashi::cli::CliGlobalOpts;
use hashi::cli::ProposalCommands;

#[derive(Parser)]
struct Shape {
    #[clap(flatten)]
    cli_opts: CliGlobalOpts,
    #[clap(subcommand)]
    action: ProposalCommands,
}

#[test]
fn flags_after_the_leaf_subcommand_are_accepted() {
    let parsed = Shape::try_parse_from(["hashi", "vote", "0x1", "-y", "--dry-run"]).unwrap();
    assert!(parsed.cli_opts.yes);
    assert!(parsed.cli_opts.dry_run);
    assert!(matches!(parsed.action, ProposalCommands::Vote { .. }));
}

#[test]
fn flags_before_the_leaf_subcommand_still_work() {
    let parsed =
        Shape::try_parse_from(["hashi", "--keypair", "/tmp/k.key", "-y", "vote", "0x1"]).unwrap();
    assert!(parsed.cli_opts.yes);
    assert_eq!(
        parsed.cli_opts.keypair.as_deref(),
        Some(std::path::Path::new("/tmp/k.key"))
    );
}

#[test]
fn flags_split_around_the_leaf_subcommand_combine() {
    let parsed = Shape::try_parse_from([
        "hashi",
        "--sui-rpc-url",
        "http://localhost:9000",
        "view",
        "0x1",
        "--verbose",
    ])
    .unwrap();
    assert!(parsed.cli_opts.verbose);
    assert_eq!(
        parsed.cli_opts.sui_rpc_url.as_deref(),
        Some("http://localhost:9000")
    );
}
