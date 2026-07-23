// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Preflight checks and the deposit -> mint -> withdraw -> settle loop.

use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use bitcoin::Address;
use bitcoin::Amount;
use clap::Args;
use hashi_types::bitcoin::BitcoinAddress;
use serde_json::json;

use crate::bridge::Bridge;
use crate::bridge::DEPOSIT_CHUNK;
use crate::bridge::WITHDRAW_CHUNK;
use crate::btc::BitcoinRpc;
use crate::btc::FundingTx;
use crate::config::CommonOpts;
use crate::config::OnchainConfig;
use crate::config::Resolved;
use crate::ui;

/// Attempts per PTB. The peer-gRPC layer drops connections under the load a
/// large run generates, and a retry reconnects.
///
/// A PTB is atomic, so a failed attempt never lands a partial batch. It can
/// still land a whole one: if the transaction executed and only the response
/// was lost, the retry re-submits. That is survivable rather than corrupting —
/// duplicate deposit requests never mint, because `deposit()`'s replay check
/// rejects them once the original's UTXO reaches the pool — but it does mean a
/// retried withdrawal batch can burn hBTC twice. See the README.
const PTB_ATTEMPTS: usize = 5;
const PTB_RETRY_DELAY: Duration = Duration::from_secs(6);

/// Which halves of the loop to run.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Mode {
    Full,
    DepositOnly,
    WithdrawOnly,
}

impl Mode {
    fn deposits(self) -> bool {
        self != Mode::WithdrawOnly
    }

    fn withdrawals(self) -> bool {
        self != Mode::DepositOnly
    }

    fn as_str(self) -> &'static str {
        match self {
            Mode::Full => "full",
            Mode::DepositOnly => "deposit",
            Mode::WithdrawOnly => "withdraw",
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct LoopOpts {
    /// Number of deposit UTXOs to create and register
    #[arg(long, default_value_t = 100)]
    pub deposits: usize,

    /// BTC per deposit
    #[arg(long, default_value_t = 0.1)]
    pub deposit_amount_btc: f64,

    /// Number of withdrawal requests to submit
    #[arg(long, default_value_t = 100)]
    pub withdrawals: usize,

    /// BTC per withdrawal
    #[arg(long, default_value_t = 0.1)]
    pub withdrawal_amount_btc: f64,

    /// Deposit outputs per funding transaction. Larger batches mean fewer
    /// transactions but a fatter one; signet's miner caps blocks near 1M weight
    /// and skips transactions that no longer fit.
    #[arg(long, default_value_t = 250)]
    pub outputs_per_tx: usize,

    /// Funding transaction fee rate (sat/vB)
    #[arg(long, default_value_t = 4.0)]
    pub fee_rate: f64,

    /// BTC address to withdraw to [default: a fresh address from the wallet,
    /// which makes the received total exactly this run's]
    #[arg(long)]
    pub withdraw_dest: Option<String>,

    /// Seconds to wait for deposits to mint
    #[arg(long, default_value_t = 3600)]
    pub mint_timeout: u64,

    /// Seconds to wait for withdrawals to settle on Bitcoin
    #[arg(long, default_value_t = 5400)]
    pub settle_timeout: u64,

    /// Seconds between polls
    #[arg(long, default_value_t = 30)]
    pub poll_interval: u64,

    /// Submit withdrawals but do not wait for Bitcoin settlement
    #[arg(long)]
    pub skip_settle: bool,

    /// Do not scan pod logs for guardian co-signing failures while settling
    #[arg(long)]
    pub no_log_watch: bool,

    /// Write a JSON report here
    #[arg(long)]
    pub report: Option<std::path::PathBuf>,
}

impl LoopOpts {
    fn deposit_amount(&self) -> Result<Amount> {
        Amount::from_btc(self.deposit_amount_btc).context("bad --deposit-amount-btc")
    }

    fn withdrawal_amount(&self) -> Result<Amount> {
        Amount::from_btc(self.withdrawal_amount_btc).context("bad --withdrawal-amount-btc")
    }

    fn deposit_total(&self) -> Result<Amount> {
        Ok(self.deposit_amount()? * self.deposits as u64)
    }

    fn withdrawal_total(&self) -> Result<Amount> {
        Ok(self.withdrawal_amount()? * self.withdrawals as u64)
    }
}

/// Run one fallible step up to [`PTB_ATTEMPTS`] times.
async fn retrying<T, F, Fut>(label: &str, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut last = None;
    for attempt in 1..=PTB_ATTEMPTS {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt < PTB_ATTEMPTS {
                    ui::warn(&format!(
                        "{label} attempt {attempt}/{PTB_ATTEMPTS} failed: {e}"
                    ));
                    tokio::time::sleep(PTB_RETRY_DELAY).await;
                }
                last = Some(e);
            }
        }
    }
    Err(last
        .expect("at least one attempt ran")
        .context(format!("{label} failed after {PTB_ATTEMPTS} attempts")))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------- preflight

pub struct Preflight {
    pub deposit_address: BitcoinAddress,
    pub hbtc_start_sats: u64,
}

/// Verify everything a run depends on, before it spends any BTC.
///
/// `needs` describes the run, to size it against available funds; pass `None`
/// to check reachability only.
pub async fn preflight(r: &Resolved, needs: Option<(&LoopOpts, Mode)>) -> Result<Preflight> {
    let bridge = r.bridge()?;
    let btc = BitcoinRpc::new(
        &r.btc_rpc_url,
        &r.btc_rpc_user,
        &r.btc_rpc_password,
        &r.btc_wallet,
    )?;

    if r.discovered_from_k8s {
        ui::ok(&format!(
            "ids                 read live from {}",
            r.namespace
        ));
    } else {
        // Explicitly-passed ids are the stale-env-file trap: the superseded
        // deployment's Hashi object still exists and still accepts deposits.
        match &r.cluster {
            Some(c) if c.package_id != r.package_id.to_string() => ui::warn(&format!(
                "the package id given is not what {} is running:\n      given   {}\n      \
                 cluster {}\n      The superseded package still exists and still accepts \
                 deposits, so this run would look green while testing nothing.\n      \
                 Unset HASHI_PACKAGE_ID and HASHI_OBJECT_ID (or drop --package-id) to use \
                 the live ones.",
                r.namespace, r.package_id, c.package_id
            )),
            Some(_) => ui::ok(&format!("ids                 match {}", r.namespace)),
            None => ui::info("ids                 taken as given (cluster not reachable)"),
        }
    }

    let info = btc.chain_info()?;
    if info.chain != r.btc_network.to_string() {
        bail!(
            "bitcoind at {} is on `{}` but --btc-network resolves to `{}`",
            r.btc_rpc_url,
            info.chain,
            r.btc_network
        );
    }
    if info.initial_block_download || info.verification_progress < 0.999 {
        bail!(
            "bitcoind is still syncing ({:.2}% at height {}); wait for it to catch up",
            info.verification_progress * 100.0,
            info.blocks
        );
    }
    ui::ok(&format!(
        "bitcoind            {} at height {}",
        info.chain, info.blocks
    ));

    // Both sides must be on the same Bitcoin, and signet in particular is a
    // custom chain per deployment. hashi pins genesis as `bitcoin_chain_id`.
    let genesis = btc.genesis_hash()?;
    match r
        .cluster
        .as_ref()
        .and_then(|c| c.bitcoin_chain_id.as_deref())
    {
        Some(chain_id) if chain_id != genesis => bail!(
            "your bitcoind is a different chain from the bridge's:\n  local genesis   {genesis}\n  \
             bridge chain id {chain_id}\nDeposits made here would never be seen."
        ),
        Some(_) => ui::ok("bitcoin chain       genesis matches the bridge"),
        None => ui::info("bitcoin chain       not verified (bridge chain id unavailable)"),
    }

    let wallet_balance_btc = btc.wallet_balance()?;
    ui::ok(&format!(
        "wallet `{}`     {:.8} BTC",
        r.btc_wallet, wallet_balance_btc
    ));

    let deposit_address = bridge.deposit_address(r.sui_address).await.context(
        "could not derive a deposit address; the package/object ids may be wrong, or the \
         committee may not have completed DKG",
    )?;
    ui::ok(&format!("deposit address     {deposit_address}"));

    let hbtc_start_sats = bridge.balance_sats(r.sui_address).await?;
    ui::ok(&format!(
        "hBTC balance        {} sats ({:.8} BTC)",
        hbtc_start_sats,
        hbtc_start_sats as f64 / 1e8
    ));

    // The onchain config overrides the code defaults, so it is the only
    // authority on what the committee accepts and how long a mint takes.
    match OnchainConfig::read(r.hashi_object_id) {
        Some(cfg) => {
            if cfg.bool("paused") == Some(true) {
                bail!(
                    "the bridge is paused onchain; deposits and withdrawals will be rejected \
                     until governance unpauses it"
                );
            }
            if let Some(url) = cfg.string("guardian_url") {
                ui::ok(&format!("guardian            {url}"));
            }
            if let (Some(confs), Some(delay)) = (
                cfg.u64("bitcoin_confirmation_threshold"),
                cfg.u64("bitcoin_deposit_time_delay_ms"),
            ) {
                ui::ok(&format!(
                    "mint gating         {confs} confirmations + {}s delay",
                    delay / 1000
                ));
            }
            if let Some((opts, mode)) = needs {
                check_capacity(
                    r,
                    opts,
                    mode,
                    Some(&cfg),
                    wallet_balance_btc,
                    hbtc_start_sats,
                )?;
            }
        }
        None => {
            ui::info("onchain config      not read (the `sui` CLI is unavailable)");
            if let Some((opts, mode)) = needs {
                check_capacity(r, opts, mode, None, wallet_balance_btc, hbtc_start_sats)?;
            }
        }
    }

    Ok(Preflight {
        deposit_address,
        hbtc_start_sats,
    })
}

/// Reject runs that cannot finish, before any BTC moves.
fn check_capacity(
    r: &Resolved,
    opts: &LoopOpts,
    mode: Mode,
    cfg: Option<&OnchainConfig>,
    wallet_balance_btc: f64,
    hbtc_start_sats: u64,
) -> Result<()> {
    let held = Amount::from_sat(hbtc_start_sats);
    let deposit_total = if mode.deposits() {
        opts.deposit_total()?
    } else {
        Amount::ZERO
    };
    let withdrawal_total = if mode.withdrawals() {
        opts.withdrawal_total()?
    } else {
        Amount::ZERO
    };

    if deposit_total.to_btc() > wallet_balance_btc {
        bail!(
            "run needs {deposit_total} of deposits but wallet `{}` holds only {:.8} BTC",
            r.btc_wallet,
            wallet_balance_btc
        );
    }

    // hBTC available to withdraw: what is held now, plus whatever this run mints.
    let available = held + deposit_total;
    if withdrawal_total > available {
        bail!(
            "run would withdraw {withdrawal_total} but only {available} of hBTC will exist \
             ({held} already held + {deposit_total} minted by this run)"
        );
    }

    // A per-request amount below the onchain minimum is rejected outright, and
    // by then the deposits would already be funded.
    let mut checks = Vec::new();
    if mode.deposits() {
        checks.push((
            "bitcoin_deposit_minimum",
            opts.deposit_amount()?,
            "--deposit-amount-btc",
        ));
    }
    if mode.withdrawals() {
        checks.push((
            "bitcoin_withdrawal_minimum",
            opts.withdrawal_amount()?,
            "--withdrawal-amount-btc",
        ));
    }
    for (key, amount, flag) in checks {
        if let Some(min) = cfg.and_then(|c| c.u64(key))
            && amount.to_sat() < min
        {
            bail!(
                "{flag} is {} sats, below the onchain {key} of {min} sats",
                amount.to_sat()
            );
        }
    }

    ui::ok(&format!(
        "capacity            {deposit_total} in, {withdrawal_total} out"
    ));
    Ok(())
}

// ------------------------------------------------------------------- phases

fn fund(btc: &BitcoinRpc, address: &Address, opts: &LoopOpts) -> Result<Vec<FundingTx>> {
    let amount = opts.deposit_amount()?;
    let mut remaining = opts.deposits;
    let mut txs = Vec::new();
    let batches = opts.deposits.div_ceil(opts.outputs_per_tx);

    while remaining > 0 {
        let count = remaining.min(opts.outputs_per_tx);
        let idx = txs.len() + 1;
        ui::step(&format!("funding tx {idx}/{batches}: {count} x {amount}"));
        let tx = btc.fund_deposit_outputs(address, count, amount, opts.fee_rate)?;
        ui::ok(&format!(
            "{} ({} outputs, fee {:.8} BTC)",
            tx.txid,
            tx.vouts.len(),
            tx.fee_btc
        ));
        txs.push(tx);
        remaining -= count;
    }
    Ok(txs)
}

/// Register every funded output as a deposit request.
///
/// Registration does not wait for confirmations: the committee enforces
/// `bitcoin_confirmation_threshold` itself, so registering straight from the
/// mempool only starts its watch sooner.
async fn register(
    bridge: &Bridge,
    txs: &[FundingTx],
    recipient: sui_sdk_types::Address,
) -> Result<usize> {
    let total: usize = txs.iter().map(|t| t.vouts.len()).sum();
    let mut registered = 0;

    for tx in txs {
        let outputs: Vec<(u32, u64)> = tx.vouts.iter().map(|v| (*v, tx.amount_sats)).collect();
        for chunk in outputs.chunks(DEPOSIT_CHUNK) {
            registered += retrying("deposit registration", || {
                bridge.register_deposits(tx.txid, chunk, recipient)
            })
            .await?;
            ui::step(&format!("registered {registered}/{total} deposits"));
        }
    }
    Ok(registered)
}

async fn await_mint(
    bridge: &Bridge,
    btc: &BitcoinRpc,
    r: &Resolved,
    txs: &[FundingTx],
    target: Amount,
    opts: &LoopOpts,
) -> Result<u64> {
    let deadline = Instant::now() + Duration::from_secs(opts.mint_timeout);

    loop {
        let balance = bridge.balance_sats(r.sui_address).await?;
        // The least-confirmed funding tx gates the last deposit to mint.
        let confs = txs
            .iter()
            .map(|t| btc.confirmations(&t.txid).unwrap_or(0))
            .min()
            .unwrap_or(0);
        ui::step(&format!(
            "minted {:.8} / {} BTC (funding txs at >={confs} confs)",
            balance as f64 / 1e8,
            target.to_btc()
        ));
        if balance >= target.to_sat() {
            return Ok(balance);
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {}s waiting to mint {target}; reached {:.8} BTC. The funding txs \
                 were at {confs} confirmations — if that is still 0, they never got mined and the \
                 fee rate was likely too low for their size.",
                opts.mint_timeout,
                balance as f64 / 1e8
            );
        }
        tokio::time::sleep(Duration::from_secs(opts.poll_interval)).await;
    }
}

/// Submit withdrawals, one atomic PTB at a time.
///
/// Each batch waits until enough hBTC has minted to cover it, so this also works
/// while deposits are still landing.
async fn withdraw(
    bridge: &Bridge,
    r: &Resolved,
    dest: &BitcoinAddress,
    opts: &LoopOpts,
) -> Result<HashSet<sui_sdk_types::Address>> {
    let amount = opts.withdrawal_amount()?;
    let deadline = Instant::now() + Duration::from_secs(opts.mint_timeout);
    let mut submitted = HashSet::new();

    while submitted.len() < opts.withdrawals {
        let count = (opts.withdrawals - submitted.len()).min(WITHDRAW_CHUNK);
        let need = amount * count as u64;

        let balance = Amount::from_sat(bridge.balance_sats(r.sui_address).await?);
        if balance < need {
            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for hBTC to cover the next batch: have {balance}, need \
                     {need} ({}/{} submitted)",
                    submitted.len(),
                    opts.withdrawals
                );
            }
            ui::step(&format!(
                "waiting for hBTC: have {balance}, need {need} ({}/{} submitted)",
                submitted.len(),
                opts.withdrawals
            ));
            tokio::time::sleep(Duration::from_secs(opts.poll_interval)).await;
            continue;
        }

        let ids = retrying("withdrawal batch", || {
            bridge.request_withdrawals(amount.to_sat(), dest, count)
        })
        .await?;
        submitted.extend(ids);
        ui::step(&format!(
            "submitted {}/{} withdrawals",
            submitted.len(),
            opts.withdrawals
        ));
    }
    Ok(submitted)
}

/// Count guardian co-signing failures across the fleet in the last
/// `since_secs`.
///
/// This is the signal that withdrawals are broken rather than merely slow — both
/// look identical from the queue alone. Best-effort: without kubectl a run still
/// works, it just loses this diagnostic.
fn cosign_failures(namespace: &str, since_secs: u64) -> usize {
    std::process::Command::new("kubectl")
        .args([
            "-n",
            namespace,
            "logs",
            "-l",
            "app=hashi-server",
            &format!("--since={since_secs}s"),
            "--max-log-requests=20",
        ])
        .output()
        .ok()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .matches("Guardian signature verification failed")
                .count()
        })
        .unwrap_or(0)
}

struct Settlement {
    received_btc: f64,
    cosign_failures: usize,
}

/// Wait until every withdrawal in `mine` has been confirmed on Bitcoin.
///
/// Completion is read from onchain state — this run's requests all out of the
/// queue, and none of its transactions still in flight — rather than from the
/// payout total levelling off. A "payouts stopped growing" heuristic would
/// report success during any lull, and lulls are normal here: the guardian's
/// rate limiter makes batches trickle out as its bucket refills.
///
/// Waiting for `confirmed_txns` rather than stopping at the mempool costs the
/// Bitcoin confirmation window, but it is what exercises the last third of the
/// withdrawal lifecycle: broadcast, confirm, and the onchain record that marks
/// the spent UTXOs.
async fn await_settle(
    bridge: &Bridge,
    btc: &BitcoinRpc,
    r: &Resolved,
    dest: &Address,
    mine: &HashSet<sui_sdk_types::Address>,
    opts: &LoopOpts,
) -> Result<Settlement> {
    let deadline = Instant::now() + Duration::from_secs(opts.settle_timeout);
    let mut failures = 0;

    loop {
        let progress = bridge.withdrawal_progress(mine).await?;
        // minconf 0: a payout counts as soon as it hits the mempool.
        let received = btc.received_by_address(dest, 0)?;
        if !opts.no_log_watch {
            failures += cosign_failures(&r.namespace, opts.poll_interval + 10);
        }

        ui::step(&format!(
            "queued={} in-flight_txns={} ({} signed) received={received:.8} BTC{}",
            progress.queued,
            progress.in_flight,
            progress.signed,
            if failures > 0 {
                format!(" cosign_failures={failures}")
            } else {
                String::new()
            }
        ));

        // Confirmed transactions leave `withdrawal_txns` for `confirmed_txns`,
        // so an empty in-flight set means every batch has landed.
        if progress.queued == 0 && progress.in_flight == 0 && received > 0.0 {
            return Ok(Settlement {
                received_btc: received,
                cosign_failures: failures,
            });
        }

        if Instant::now() >= deadline {
            bail!(
                "timed out after {}s: {} of this run's withdrawals still queued, {} of its \
                 transactions in flight, {received:.8} BTC received.{}",
                opts.settle_timeout,
                progress.queued,
                progress.in_flight,
                if failures > 0 {
                    format!(
                        " {failures} guardian co-signing failures were logged — withdrawals are \
                         failing, not merely slow."
                    )
                } else {
                    String::new()
                }
            );
        }
        tokio::time::sleep(Duration::from_secs(opts.poll_interval)).await;
    }
}

// -------------------------------------------------------------- entrypoints

pub async fn doctor(common: &CommonOpts) -> Result<()> {
    let r = common.resolve()?;
    ui::header("Preflight");
    ui::info(&format!("package  {}", r.package_id));
    ui::info(&format!("object   {}", r.hashi_object_id));
    ui::info(&format!("sui rpc  {}", r.sui_rpc_url));
    ui::info(&format!("sui addr {}", r.sui_address));
    eprintln!();
    preflight(&r, None).await?;
    eprintln!();
    ui::ok("ready");
    Ok(())
}

pub async fn run(common: &CommonOpts, opts: &LoopOpts, mode: Mode) -> Result<()> {
    if mode.deposits() && opts.deposits == 0 {
        bail!("--deposits must be at least 1");
    }
    if mode.withdrawals() && opts.withdrawals == 0 {
        bail!("--withdrawals must be at least 1");
    }
    let started = Instant::now();
    let started_at = now_secs();
    let r = common.resolve()?;

    ui::header("Preflight");
    ui::info(&format!("package  {}", r.package_id));
    ui::info(&format!("object   {}", r.hashi_object_id));
    ui::info(&format!("sui addr {}", r.sui_address));
    eprintln!();
    let pre = preflight(&r, Some((opts, mode))).await?;

    let bridge = r.bridge()?;
    let btc = BitcoinRpc::new(
        &r.btc_rpc_url,
        &r.btc_rpc_user,
        &r.btc_rpc_password,
        &r.btc_wallet,
    )?;

    let mut txs = Vec::new();
    let mut registered = 0;
    let mut minted = pre.hbtc_start_sats;

    if mode.deposits() {
        ui::header(&format!(
            "Funding {} deposits of {} BTC",
            opts.deposits, opts.deposit_amount_btc
        ));
        txs = fund(&btc, &pre.deposit_address, opts)?;

        ui::header("Registering deposits");
        registered = register(&bridge, &txs, r.sui_address).await?;

        ui::header("Waiting for mint");
        let target = Amount::from_sat(pre.hbtc_start_sats) + opts.deposit_total()?;
        minted = await_mint(&bridge, &btc, &r, &txs, target, opts).await?;
        ui::ok(&format!(
            "minted; hBTC balance {:.8} BTC",
            minted as f64 / 1e8
        ));
    }

    let mut submitted = 0;
    let mut settlement = None;
    let mut dest = None;

    if mode.withdrawals() {
        let address = match &opts.withdraw_dest {
            Some(d) => d
                .parse::<BitcoinAddress<bitcoin::address::NetworkUnchecked>>()
                .with_context(|| format!("invalid --withdraw-dest `{d}`"))?
                .require_network(r.btc_network)
                .context("--withdraw-dest is not valid on this network")?,
            // A fresh address makes `getreceivedbyaddress` measure exactly this run.
            None => btc
                .new_address("hashi-loadtest")?
                .parse::<BitcoinAddress<bitcoin::address::NetworkUnchecked>>()?
                .require_network(r.btc_network)?,
        };

        ui::header(&format!(
            "Withdrawing {} x {} BTC to {address}",
            opts.withdrawals, opts.withdrawal_amount_btc
        ));
        let ids = withdraw(&bridge, &r, &address, opts).await?;
        submitted = ids.len();

        if !opts.skip_settle {
            ui::header("Waiting for settlement");
            let s = await_settle(&bridge, &btc, &r, &address, &ids, opts).await?;
            ui::ok(&format!(
                "settled; {:.8} BTC received at {address}",
                s.received_btc
            ));
            if s.cosign_failures > 0 {
                ui::warn(&format!(
                    "{} guardian co-signing failures were logged during the run",
                    s.cosign_failures
                ));
            }
            settlement = Some(s);
        }
        dest = Some(address);
    }

    let elapsed = started.elapsed();
    ui::header("Done");
    ui::ok(&format!(
        "{registered} deposits registered, {submitted} withdrawals submitted in {:.1} min",
        elapsed.as_secs_f64() / 60.0
    ));

    if let Some(path) = &opts.report {
        // Only report on halves that actually ran; a `deposits` block in a
        // withdraw-only run would report flag defaults as if they had happened.
        let deposits = mode.deposits().then(|| {
            json!({
                "requested": opts.deposits,
                "registered": registered,
                "amount_btc": opts.deposit_amount_btc,
                "funding_txids": txs.iter().map(|t| t.txid.to_string()).collect::<Vec<_>>(),
                "funding_fee_btc": txs.iter().map(|t| t.fee_btc).sum::<f64>(),
            })
        });
        let withdrawals = mode.withdrawals().then(|| {
            json!({
                "submitted": submitted,
                "amount_btc": opts.withdrawal_amount_btc,
                "destination": dest.as_ref().map(ToString::to_string),
                "received_btc": settlement.as_ref().map(|s| s.received_btc),
                "cosign_failures": settlement.as_ref().map(|s| s.cosign_failures),
            })
        });
        let report = json!({
            "started_at": started_at,
            "elapsed_secs": elapsed.as_secs(),
            "mode": mode.as_str(),
            "package_id": r.package_id.to_string(),
            "hashi_object_id": r.hashi_object_id.to_string(),
            "sui_address": r.sui_address.to_string(),
            "deposit_address": pre.deposit_address.to_string(),
            "deposits": deposits,
            "withdrawals": withdrawals,
            "hbtc_sats": { "before": pre.hbtc_start_sats, "after_mint": minted },
        });
        std::fs::write(path, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("failed to write {}", path.display()))?;
        ui::ok(&format!("report written to {}", path.display()));
    }
    Ok(())
}
