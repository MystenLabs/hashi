// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Summarize a guardian init config after loading it the way the production
//! commands do.
//!
//! Rendered configs reach key provisioners as files, and a field the CLI would
//! reject only surfaces when a command first loads it, in the middle of a
//! ceremony. Loading the certificate roster here is the same work
//! `operator ceremony` does.

use anyhow::Result;

use crate::config::Config;

pub fn report(cfg: &Config) -> Result<()> {
    cfg.kp_roster.validate()?;
    let roster = cfg.kp_roster.load_certs_roster()?;
    let deployment = &cfg.deployment;

    println!("guardian endpoint:  {}", cfg.guardian_endpoint);
    println!("relay endpoint:     {}", cfg.relay_endpoint);
    println!("bitcoin network:    {}", deployment.bitcoin_network);
    println!(
        "guardian bucket:    s3://{} ({}, {:?} retention)",
        deployment.bucket_info.name,
        deployment.bucket_info.region,
        deployment.retention_environment
    );
    // Never the values: a config meant for sharing that still carries them is
    // what this line is here to show.
    println!(
        "s3 credentials:     {}",
        if cfg.s3_credentials.is_some() {
            "in the file"
        } else {
            "from the environment"
        }
    );
    println!("sui rpc:            {}", cfg.hashi.sui_rpc);
    println!("hashi package:      {}", cfg.hashi.hashi_ids.package_id);
    println!(
        "hashi object:       {}",
        cfg.hashi.hashi_ids.hashi_object_id
    );
    println!(
        "limiter:            {} sats capacity, {} sats/sec refill",
        cfg.limiter_config.max_bucket_capacity, cfg.limiter_config.refill_rate
    );

    let allowlist = &deployment.pcr_allowlist;
    println!(
        "current build:      {} {}",
        allowlist.current_build().git_revision(),
        hex::encode(allowlist.current_build().pcr0())
    );
    for build in allowlist.prev_builds() {
        println!(
            "previous build:     {} {}",
            build.git_revision(),
            hex::encode(build.pcr0())
        );
    }

    // Fingerprint order, the order a new ceremony assigns share ids in.
    println!(
        "key provisioners:   {} of {}",
        cfg.kp_roster.threshold, cfg.kp_roster.num_shares
    );
    for fingerprint in roster.fingerprints() {
        println!("  {fingerprint}");
    }

    if let Some(new_kp_roster) = &cfg.new_kp_roster {
        new_kp_roster.validate()?;
        let proposed = new_kp_roster.load_certs_roster()?;
        println!(
            "proposed set:       {} of {}",
            new_kp_roster.threshold, new_kp_roster.num_shares
        );
        for fingerprint in proposed.fingerprints() {
            println!("  {fingerprint}");
        }
    }

    match &cfg.kp_pgp_cert_path {
        Some(path) => println!("this key provisioner: {}", path.display()),
        None => println!("this key provisioner: not set (operator commands only)"),
    }
    Ok(())
}
