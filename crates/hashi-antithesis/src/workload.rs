// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Long-running load: a regtest miner plus independent users, each looping
//! over deposit (BTC -> hBTC) and withdrawal (hBTC -> BTC) round trips, as
//! `create_deposit_and_wait` / `create_withdrawal_and_wait` do in the e2e
//! tests. Faults make individual operations fail or stall, so failures are
//! logged and retried; only violated invariants are reported as assertions.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use antithesis_sdk::assert_always;
use antithesis_sdk::assert_sometimes;
use antithesis_sdk::random::AntithesisRng;
use anyhow::Context;
use anyhow::Result;
use bitcoin::Amount;
use fastcrypto::hash::HashFunction;
use fastcrypto::hash::Sha256;
use hashi::sui_tx_executor::SuiTxExecutor;
use hashi_types::bitcoin::BitcoinAddress;
use rand::Rng;
use serde_json::json;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::Address;

use crate::env::CommonArgs;
use crate::env::Deployment;
use crate::env::EnvFile;

/// The package's default `bitcoin_deposit_minimum` / `bitcoin_withdrawal_minimum`.
const MIN_AMOUNT_SATS: u64 = 30_000;
const MAX_DEPOSIT_SATS: u64 = 1_000_000;
const USER_FUNDING_MIST: u64 = 1_000 * 1_000_000_000;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const PROGRESS_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(clap::Args)]
pub struct Args {
    /// Independent users, each with its own Sui account, running concurrently.
    #[arg(long, env = "WORKLOAD_USERS", default_value_t = 4)]
    users: usize,

    #[arg(long, env = "WORKLOAD_MIN_BLOCK_INTERVAL_MS", default_value_t = 1_000)]
    min_block_interval_ms: u64,

    #[arg(long, env = "WORKLOAD_MAX_BLOCK_INTERVAL_MS", default_value_t = 10_000)]
    max_block_interval_ms: u64,

    #[arg(long, env = "WORKLOAD_DEPOSIT_TIMEOUT_SECS", default_value_t = 900)]
    deposit_timeout_secs: u64,

    #[arg(
        long,
        env = "WORKLOAD_WITHDRAWAL_TIMEOUT_SECS",
        default_value_t = 1_800
    )]
    withdrawal_timeout_secs: u64,

    /// Survives workload restarts; holds each user's deposit ledger.
    #[arg(long, env = "WORKLOAD_STATE_DIR", default_value = "/state")]
    state_dir: PathBuf,
}

struct Workload {
    common: CommonArgs,
    state_dir: PathBuf,
    deployment: Deployment,
    onchain: hashi::onchain::OnchainState,
    deposit_timeout: Duration,
    withdrawal_timeout: Duration,
}

pub async fn run(common: &CommonArgs, args: Args) -> Result<()> {
    let shared = common.shared();
    crate::env::wait_for_file(&shared.bootstrap_done_path()).await;
    let env = EnvFile::load(&common.env_file)?;
    let deployment = shared.wait_for_deployment().await?;
    let (onchain, _onchain_service) = crate::env::onchain_view(&common.sui_rpc, &deployment).await;

    let users = (0..args.users).map(user_key).collect::<Vec<_>>();
    let funded_key = env.funded_key()?;
    let funding = users
        .iter()
        .map(|key| (key.public_key().derive_address(), USER_FUNDING_MIST))
        .collect::<Vec<_>>();
    // Faults are live from here on. A retry after an ambiguous failure may
    // fund twice, which is harmless.
    crate::env::retry("fund workload users", || {
        let sui_rpc = &common.sui_rpc;
        let funded_key = &funded_key;
        let funding = &funding;
        async move {
            let mut client = sui_rpc::Client::new(sui_rpc)?;
            e2e_tests::sui_network::fund(&mut client, funded_key, funding).await
        }
    })
    .await;
    tracing::info!("funded {} workload users", users.len());

    start_miner(common, &args);

    let ctx = Arc::new(Workload {
        common: common.clone(),
        state_dir: args.state_dir.clone(),
        deployment,
        onchain,
        deposit_timeout: Duration::from_secs(args.deposit_timeout_secs),
        withdrawal_timeout: Duration::from_secs(args.withdrawal_timeout_secs),
    });
    let tasks = users
        .into_iter()
        .enumerate()
        .map(|(index, key)| tokio::spawn(run_user(ctx.clone(), index, key)))
        .collect::<Vec<_>>();
    futures::future::try_join_all(tasks).await?;
    Ok(())
}

/// Deterministic, so a restarted workload picks up the same accounts.
fn user_key(index: usize) -> Ed25519PrivateKey {
    let seed = Sha256::digest(format!("hashi-antithesis-user-{index}").as_bytes());
    Ed25519PrivateKey::new(seed.digest)
}

/// Mines to the shared wallet at random intervals. Runs on its own thread
/// because the bitcoind client is blocking.
fn start_miner(common: &CommonArgs, args: &Args) {
    let common = common.clone();
    let interval_ms = args.min_block_interval_ms..=args.max_block_interval_ms;
    std::thread::spawn(move || {
        let mut rng = AntithesisRng;
        loop {
            let mined = common.btc_wallet().and_then(|wallet| {
                let address = wallet.new_address()?;
                wallet.generate_to_address(1, &address)?;
                Ok(())
            });
            if let Err(e) = mined {
                tracing::warn!("mining failed: {e:#}");
                let _ = crate::env::ensure_wallet(&common);
            }
            std::thread::sleep(Duration::from_millis(rng.gen_range(interval_ms.clone())));
        }
    });
}

struct User {
    index: usize,
    address: Address,
    executor: SuiTxExecutor,
    client: sui_rpc::Client,
    /// Every deposit ever sent for this user, persisted before the BTC is sent
    /// so a restarted workload still counts deposits that credit after it
    /// restarts. Withdrawals are not subtracted, so this stays an upper bound
    /// on the hBTC balance even if one is refunded.
    deposited: u64,
}

impl User {
    fn ledger_path(&self, ctx: &Workload) -> PathBuf {
        ctx.state_dir.join(format!("user-{}-deposited", self.index))
    }

    fn load_deposited(&mut self, ctx: &Workload) -> Result<()> {
        self.deposited = match std::fs::read_to_string(self.ledger_path(ctx)) {
            Ok(raw) => raw.trim().parse()?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        Ok(())
    }

    fn record_deposit(&mut self, ctx: &Workload, amount: u64) -> Result<()> {
        let deposited = self.deposited + amount;
        crate::env::write_atomic(&self.ledger_path(ctx), deposited.to_string().as_bytes())?;
        self.deposited = deposited;
        Ok(())
    }
}

async fn run_user(ctx: Arc<Workload>, index: usize, key: Ed25519PrivateKey) -> Result<()> {
    let address = key.public_key().derive_address();
    let client = sui_rpc::Client::new(&ctx.common.sui_rpc)?;
    let executor = SuiTxExecutor::new(client.clone(), key.into(), ctx.deployment.hashi_ids())
        .with_onchain_state(&ctx.onchain);
    let mut user = User {
        index,
        address,
        executor,
        client,
        deposited: 0,
    };
    std::fs::create_dir_all(&ctx.state_dir)?;
    user.load_deposited(&ctx)?;

    let mut rng = AntithesisRng;
    loop {
        let result = match balance(&ctx, &mut user).await {
            Ok(balance) if balance >= MIN_AMOUNT_SATS && rng.gen_bool(0.5) => {
                let amount = rng.gen_range(MIN_AMOUNT_SATS..=balance);
                withdraw(&ctx, &mut user, amount).await
            }
            Ok(balance) => {
                let amount = rng.gen_range(MIN_AMOUNT_SATS..=MAX_DEPOSIT_SATS);
                deposit(&ctx, &mut user, balance, amount).await
            }
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            tracing::warn!(user = index, "operation failed: {e:#}");
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }
}

/// Reads the user's hBTC balance and checks it against what was deposited.
async fn balance(ctx: &Workload, user: &mut User) -> Result<u64> {
    let balance = e2e_tests::test_helpers::get_hbtc_balance(
        &mut user.client,
        ctx.deployment.package_id,
        user.address,
    )
    .await?;
    assert_always!(
        balance <= user.deposited,
        "hBTC balance never exceeds the BTC deposited for it",
        &json!({
            "user": user.index,
            "balance": balance,
            "deposited": user.deposited,
        })
    );
    Ok(balance)
}

async fn deposit(ctx: &Workload, user: &mut User, balance_before: u64, amount: u64) -> Result<()> {
    let deposit_address = {
        let guardian_pubkey = ctx
            .onchain
            .state()
            .hashi()
            .config
            .guardian_btc_public_key()
            .map(<[u8]>::to_vec)
            .context("guardian BTC pubkey not on-chain")?;
        hashi::cli::commands::deposit::cli_derive_deposit_address(
            &ctx.onchain.mpc_public_key(),
            &guardian_pubkey,
            Some(&user.address),
            bitcoin::Network::Regtest,
        )?
    };

    user.record_deposit(ctx, amount)?;
    let (txid, vout) = send_btc(&ctx.common, &deposit_address, amount)?;
    tracing::info!(user = user.index, %txid, vout, amount, "sent deposit");

    // The BTC is already gone, so push through transient failures rather than
    // strand it.
    let mut attempts = 0;
    let request_id = loop {
        match user
            .executor
            .execute_create_deposit_request(
                e2e_tests::test_helpers::txid_to_address(&txid),
                vout,
                amount,
                Some(user.address),
            )
            .await
        {
            Ok(request_id) => break request_id,
            Err(e) if attempts < 5 => {
                attempts += 1;
                tracing::warn!(user = user.index, "deposit request failed, retrying: {e:#}");
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(e) => return Err(e.context("deposit request kept failing")),
        }
    };
    tracing::info!(user = user.index, %request_id, "created deposit request");

    let started = Instant::now();
    while started.elapsed() < ctx.deposit_timeout {
        tokio::time::sleep(PROGRESS_POLL_INTERVAL).await;
        let Ok(balance) = balance(ctx, user).await else {
            continue;
        };
        if balance >= balance_before + amount {
            assert_sometimes!(true, "deposit credited hBTC", &json!({"amount": amount}));
            tracing::info!(user = user.index, %request_id, elapsed = ?started.elapsed(), "deposit confirmed");
            return Ok(());
        }
    }
    anyhow::bail!(
        "deposit {request_id} not credited within {:?}",
        ctx.deposit_timeout
    )
}

async fn withdraw(ctx: &Workload, user: &mut User, amount: u64) -> Result<()> {
    let destination = ctx.common.btc_wallet()?.new_address()?;
    let request_id = user
        .executor
        .execute_create_withdrawal_request(
            amount,
            e2e_tests::test_helpers::extract_witness_program(&destination)?,
        )
        .await?;
    tracing::info!(user = user.index, %request_id, amount, %destination, "created withdrawal request");

    let started = Instant::now();
    while started.elapsed() < ctx.withdrawal_timeout {
        tokio::time::sleep(PROGRESS_POLL_INTERVAL).await;
        let Ok(received) = received_by(&ctx.common, &destination) else {
            continue;
        };
        if received > Amount::ZERO {
            let details = json!({
                "request_id": request_id.to_string(),
                "requested_sats": amount,
                "received_sats": received.to_sat(),
            });
            assert_always!(
                received.to_sat() <= amount,
                "a withdrawal never pays out more than was requested",
                &details
            );
            assert_sometimes!(true, "withdrawal paid out on bitcoin", &details);
            tracing::info!(user = user.index, %request_id, elapsed = ?started.elapsed(), "withdrawal paid out");
            return Ok(());
        }
    }
    anyhow::bail!(
        "withdrawal {request_id} not paid out within {:?}",
        ctx.withdrawal_timeout
    )
}

fn send_btc(
    common: &CommonArgs,
    address: &BitcoinAddress,
    amount: u64,
) -> Result<(bitcoin::Txid, u32)> {
    let wallet = common.btc_wallet()?;
    let txid = wallet
        .send_to_address(address, Amount::from_sat(amount))?
        .into_model()?
        .txid;
    let tx = wallet.get_raw_transaction(txid)?.transaction()?;
    let vout = tx
        .output
        .iter()
        .position(|output| {
            output.value == Amount::from_sat(amount)
                && output.script_pubkey == address.script_pubkey()
        })
        .context("deposit output missing from the funding transaction")?;
    Ok((txid, vout as u32))
}

/// Confirmed (1+ block) amount the wallet has received at `address`.
fn received_by(common: &CommonArgs, address: &BitcoinAddress) -> Result<Amount> {
    Ok(common
        .btc_wallet()?
        .get_received_by_address(address)?
        .into_model()?
        .0)
}
