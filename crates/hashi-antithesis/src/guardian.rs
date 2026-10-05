// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The e2e tests' in-process guardian, served on the network. Unlike the real
//! enclave it needs no ceremony or key provisioners: the BTC key comes from
//! the config image, and it initializes itself from on-chain DKG output. A
//! restart therefore rejoins with the same key and the then-current committee;
//! only the rate limiter state resets.

use std::net::SocketAddr;

use anyhow::Result;
use e2e_tests::guardian_harness::GuardianHarness;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;

use crate::env::CommonArgs;
use crate::env::EnvFile;
use crate::env::POLL_INTERVAL;

#[derive(clap::Args)]
pub struct Args {
    #[arg(long, env = "GUARDIAN_LISTEN_ADDR", default_value = "0.0.0.0:3000")]
    listen: SocketAddr,

    /// Sats per second the withdrawal rate limiter refills at. The e2e default
    /// never refills, which would stall withdrawals partway through a long run.
    #[arg(
        long,
        env = "GUARDIAN_LIMITER_REFILL_RATE",
        default_value_t = 100_000_000
    )]
    limiter_refill_rate: u64,

    #[arg(
        long,
        env = "GUARDIAN_LIMITER_CAPACITY",
        default_value_t = 100_000_000_000
    )]
    limiter_capacity: u64,
}

pub async fn run(common: &CommonArgs, args: Args) -> Result<()> {
    let env = EnvFile::load(&common.env_file)?;

    // Serve before activation, as the e2e harness does: nodes that reach an
    // uninitialized guardian get errors and retry.
    let harness = GuardianHarness::start_on(bitcoin::Network::Regtest, args.listen).await?;
    harness.set_btc_keypair(env.guardian_btc_keypair()?)?;
    tracing::info!(listen = %args.listen, "guardian serving");

    let deployment = common.shared().wait_for_deployment().await?;
    let (onchain, _onchain_service) = crate::env::onchain_view(&common.sui_rpc, &deployment).await;
    tracing::info!("waiting for the committee to form");
    while !crate::env::committee_ready(&onchain) {
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    let committee = onchain
        .current_committee()
        .ok_or_else(|| anyhow::anyhow!("committee disappeared"))?;
    let limiter_config = LimiterConfig {
        refill_rate: args.limiter_refill_rate,
        max_bucket_capacity: args.limiter_capacity,
    };
    harness
        .finalize(
            committee,
            onchain.onchain_verifying_key_g()?,
            limiter_config,
            LimiterState::genesis(&limiter_config),
            deployment.hashi_object_id,
        )
        .await?;
    tracing::info!("guardian activated");

    std::future::pending::<()>().await;
    Ok(())
}
