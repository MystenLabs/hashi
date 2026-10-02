// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Summarize a guardian init config after loading it the way the production
//! commands do.
//!
//! Rendered configs reach key provisioners as files, and a field the CLI would
//! reject only surfaces when that KP runs their step. Loading the certificate
//! roster here is the same work `operator ceremony` does, so a packet that
//! passes this cannot fail on its contents later.

use anyhow::Result;

use crate::config::Config;

pub fn report(cfg: &Config) -> Result<()> {
    cfg.kp_roster.validate()?;
    let roster = cfg.kp_roster.load_certs_roster()?;

    println!("guardian endpoint:  {}", cfg.guardian_endpoint);
    println!("relay endpoint:     {}", cfg.relay_endpoint);
    println!("bitcoin network:    {}", cfg.bitcoin_network);
    println!(
        "guardian bucket:    s3://{} ({}, {:?} retention)",
        cfg.guardian_s3.bucket_info.bucket,
        cfg.guardian_s3.bucket_info.region,
        cfg.guardian_s3.retention_environment
    );
    // Never the values: a rendered config that still carries them is the bug
    // this line exists to show.
    println!(
        "s3 credentials:     {}",
        match (&cfg.guardian_s3.access_key, &cfg.guardian_s3.secret_key) {
            (Some(k), Some(_)) if !k.trim().is_empty() => "in the file",
            _ => "from the environment",
        }
    );
    println!("sui rpc:            {}", cfg.hashi.sui_rpc);
    println!(
        "hashi object:       {}",
        cfg.hashi.hashi_ids.hashi_object_id
    );
    println!(
        "limiter:            {} sats capacity, {} sats/sec refill",
        cfg.limiter_config.max_bucket_capacity, cfg.limiter_config.refill_rate
    );

    let allowlist = cfg.kp_roster.pcr_allowlist();
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

    println!(
        "key provisioners:   {} of {}",
        cfg.kp_roster.threshold, cfg.kp_roster.num_shares
    );
    for (cert, path) in roster.iter().zip(&cfg.kp_roster.kp_pgp_cert_paths) {
        println!("  {}  {}", cert.fingerprint().to_hex(), path.display());
    }

    if let Some(new_kp_roster) = &cfg.new_kp_roster {
        new_kp_roster.validate()?;
        let proposed = new_kp_roster.load_certs_roster()?;
        println!(
            "proposed set:       {} of {}",
            new_kp_roster.threshold, new_kp_roster.num_shares
        );
        for (share_id, cert) in proposed.iter().enumerate() {
            println!("  share {}  {}", share_id + 1, cert.fingerprint().to_hex());
        }
    }

    match &cfg.kp_pgp_cert_path {
        Some(path) => println!("this key provisioner: {}", path.display()),
        None => println!("this key provisioner: not set (operator commands only)"),
    }
    Ok(())
}
