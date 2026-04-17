// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Long-horizon simulation of the UTXO pool under realistic deposit and
//! withdrawal traffic.
//!
//! The goal of this sim is to observe pool-level statistics that are
//! hard to predict from unit tests alone:
//!
//! - Distribution of pool size over time (min / avg / max / p50 / p95).
//! - Mix of deposit-origin vs change-origin UTXOs in the pool.
//! - Age distribution of UTXOs (both deposits and change) at the
//!   moment they are spent, and of the living pool at steady state.
//! - Per-batch metrics: batch size, fee-per-request, consolidation
//!   depth, skipped batches due to empty queue / insufficient funds.
//! - Orphaned dust (change that was created but would be unspendable
//!   at prevailing fee rates).
//!
//! The sim is **discrete-time** with a fixed batch interval (5 minutes
//! by default). Between ticks:
//!
//! 1. Poisson-distributed deposit arrivals add new confirmed UTXOs.
//! 2. Poisson-distributed withdrawal requests join the queue.
//! 3. The current fee rate is sampled from a time-varying distribution.
//! 4. `select_coins` is called against the current pool + queue.
//! 5. Selected inputs are removed; a new `Pending` change UTXO is
//!    added; served requests are popped; the change UTXO transitions
//!    to `Confirmed` after a maturation delay.
//!
//! This reuses the real `select_coins` implementation, so behavioural
//! changes to coin selection are reflected in the sim immediately.
//!
//! The sim is deterministic given a seed. The default scenarios are
//! sized so that **one simulated week completes in well under a minute
//! of wall time** on a modern laptop.

use super::*;
use bitcoin::blockdata::script::witness_program::WitnessProgram;
use bitcoin::blockdata::script::witness_version::WitnessVersion;
use colored::Color;
use colored::Colorize;
use hashi_types::bitcoin_txid::BitcoinTxid;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

// ── Scenario configuration ──────────────────────────────────────────────

/// A named simulation scenario.
///
/// All rates are "events per batch interval". The batch interval is
/// fixed at 5 minutes (see `BATCH_INTERVAL_MS`), so a rate of 1.0 means
/// "one event per 5 minutes on average".
#[derive(Clone, Debug)]
struct Scenario {
    /// Human-readable scenario name, used in reports.
    name: &'static str,
    /// Seed for the PRNG. Using the same seed reproduces a run exactly.
    seed: u64,
    /// Total simulated duration, in batch intervals.
    ticks: u64,
    /// Mean deposits arriving per batch interval.
    deposit_rate: f64,
    /// Mean withdrawal requests arriving per batch interval.
    withdrawal_rate: f64,
    /// Log-normal mean (log-space) for deposit amounts in sats.
    deposit_amount_mu: f64,
    /// Log-normal sigma for deposit amounts.
    deposit_amount_sigma: f64,
    /// Log-normal mean (log-space) for withdrawal amounts in sats.
    withdrawal_amount_mu: f64,
    /// Log-normal sigma for withdrawal amounts.
    withdrawal_amount_sigma: f64,
    /// Mean fee rate in sat/vB (around which the time-varying rate
    /// fluctuates).
    mean_fee_rate_sat_vb: f64,
    /// Standard deviation of the fee rate's random walk, in sat/vB per tick.
    fee_rate_volatility: f64,
    /// Ticks before a pending change UTXO transitions to confirmed.
    /// Represents the time for a Bitcoin block to include the batch
    /// and reach the finality threshold.
    change_confirmation_delay_ticks: u32,
    /// Ticks before a newly-arrived deposit is considered confirmed.
    deposit_confirmation_delay_ticks: u32,
}

impl Scenario {
    /// Default simulated duration for each scenario.
    const DEFAULT_DAYS: u64 = 30;

    /// "Steady-state" scenario: balanced deposit and withdrawal traffic,
    /// with matched event rates AND matched mean amounts so the pool
    /// neither grows nor drains in expectation. This is the baseline
    /// against which the other scenarios should be compared.
    fn steady_state() -> Self {
        Self {
            name: "steady_state",
            seed: 0xC0FFEE,
            ticks: ticks_for_duration_days(Self::DEFAULT_DAYS),
            // Equal event rates, equal mean amounts → zero-drift pool.
            deposit_rate: 5.0,
            withdrawal_rate: 5.0,
            // ~0.01 BTC (1e6 sat) for both sides.
            deposit_amount_mu: (1_000_000f64).ln(),
            deposit_amount_sigma: 0.9,
            withdrawal_amount_mu: (1_000_000f64).ln(),
            withdrawal_amount_sigma: 0.9,
            mean_fee_rate_sat_vb: 5.0,
            fee_rate_volatility: 0.4,
            change_confirmation_delay_ticks: 2,
            deposit_confirmation_delay_ticks: 2,
        }
    }

    /// Deposit-heavy scenario: many small deposits, few large withdrawals.
    /// Stresses the pool-size-growth direction.
    fn deposit_heavy() -> Self {
        Self {
            name: "deposit_heavy",
            seed: 0xDEAD_BEEF,
            ticks: ticks_for_duration_days(Self::DEFAULT_DAYS),
            deposit_rate: 8.0,
            withdrawal_rate: 2.0,
            deposit_amount_mu: (2_000_000f64).ln(),
            deposit_amount_sigma: 0.9,
            withdrawal_amount_mu: (3_000_000f64).ln(),
            withdrawal_amount_sigma: 0.6,
            mean_fee_rate_sat_vb: 5.0,
            fee_rate_volatility: 0.3,
            change_confirmation_delay_ticks: 2,
            deposit_confirmation_delay_ticks: 2,
        }
    }

    /// Withdrawal-heavy scenario: few large deposits, many small withdrawals.
    /// Stresses the pool-shrinking and consolidation paths.
    fn withdrawal_heavy() -> Self {
        Self {
            name: "withdrawal_heavy",
            seed: 0xFEED_FACE,
            ticks: ticks_for_duration_days(Self::DEFAULT_DAYS),
            deposit_rate: 1.5,
            withdrawal_rate: 15.0,
            deposit_amount_mu: (20_000_000f64).ln(),
            deposit_amount_sigma: 0.8,
            withdrawal_amount_mu: (500_000f64).ln(),
            withdrawal_amount_sigma: 0.8,
            mean_fee_rate_sat_vb: 5.0,
            fee_rate_volatility: 0.3,
            change_confirmation_delay_ticks: 2,
            deposit_confirmation_delay_ticks: 2,
        }
    }

    /// High-fee scenario: sustained elevated fee rates, where the
    /// algorithm switches to "minimize inputs" and stops consolidating.
    /// Highlights how the pool behaves when consolidation is disabled.
    /// Uses the same balanced arrival pattern as `steady_state` so the
    /// comparison isolates the fee-rate regime effect.
    fn high_fee_period() -> Self {
        Self {
            name: "high_fee_period",
            seed: 0xBADD_CAFE,
            ticks: ticks_for_duration_days(Self::DEFAULT_DAYS),
            deposit_rate: 5.0,
            withdrawal_rate: 5.0,
            deposit_amount_mu: (1_000_000f64).ln(),
            deposit_amount_sigma: 0.9,
            withdrawal_amount_mu: (1_000_000f64).ln(),
            withdrawal_amount_sigma: 0.9,
            mean_fee_rate_sat_vb: 40.0,
            fee_rate_volatility: 1.0,
            change_confirmation_delay_ticks: 2,
            deposit_confirmation_delay_ticks: 2,
        }
    }
}

/// A 5-minute batch interval — the default cadence the leader uses.
const BATCH_INTERVAL_MS: u64 = 5 * 60 * 1000;

fn ticks_for_duration_days(days: u64) -> u64 {
    (days * 24 * 60) / 5
}

// ── Simulation state ────────────────────────────────────────────────────

/// Origin of a UTXO as tracked by the simulation.
///
/// This is sim-only metadata; the real `UtxoCandidate` doesn't carry
/// this information. We use it to report the mix of deposit-origin vs
/// change-origin UTXOs in the pool.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Origin {
    Deposit,
    Change,
}

/// A UTXO in the simulation, wrapping `UtxoCandidate` with extra
/// metadata needed for metrics and confirmation transitions.
#[derive(Clone, Debug)]
struct SimUtxo {
    candidate: UtxoCandidate,
    origin: Origin,
    /// Tick at which this UTXO entered the pool.
    created_at_tick: u64,
    /// Tick at which this UTXO's status should flip to `Confirmed`.
    /// `None` means it's already confirmed.
    confirms_at_tick: Option<u64>,
}

impl SimUtxo {
    /// Age in ticks relative to `now`.
    fn age(&self, now: u64) -> u64 {
        now.saturating_sub(self.created_at_tick)
    }
}

/// A pending withdrawal request.
#[derive(Clone, Debug)]
struct SimRequest {
    request: WithdrawalRequest,
    /// Tick at which this request arrived, for queue-age metrics.
    #[allow(dead_code)]
    created_at_tick: u64,
}

// ── Metrics ─────────────────────────────────────────────────────────────

/// Per-tick snapshot captured after each batch attempt.
#[derive(Clone, Debug)]
struct TickSample {
    tick: u64,
    pool_size: usize,
    deposit_pool_size: usize,
    change_pool_size: usize,
    pending_pool_size: usize,
    queue_size: usize,
    fee_rate_sat_vb: u64,
    /// `None` when no batch was produced this tick (empty queue or
    /// insufficient funds).
    batch: Option<BatchSample>,
}

#[derive(Clone, Debug)]
struct BatchSample {
    inputs: usize,
    requests: usize,
    consolidation_inputs: usize,
    fee_per_request: u64,
    /// Total miner fee (sat) paid by this tx.
    miner_fee: u64,
    /// Target fee rate in sat/vB passed to `select_coins` for this tx.
    target_fee_rate_sat_vb: u64,
    /// Realised fee rate in sat/vB, computed as `miner_fee / vsize`.
    /// Will equal or slightly exceed the target due to ceil-rounding
    /// and any CPFP deficit added for unconfirmed ancestors.
    realised_fee_rate_sat_vb: u64,
    /// Virtual size of the produced tx in vbytes.
    vsize: u64,
    change: Option<u64>,
    deposit_inputs: usize,
    change_inputs: usize,
    /// Sum of ages of the inputs that were spent in this batch.
    #[allow(dead_code)]
    sum_input_age: u64,
}

#[derive(Default)]
struct SpendEventAges {
    deposit_ages: Vec<u64>,
    change_ages: Vec<u64>,
}

/// Running counters + samples collected during a sim run.
#[derive(Default)]
struct Metrics {
    samples: Vec<TickSample>,
    spend_event_ages: SpendEventAges,
    batches_attempted: u64,
    batches_produced: u64,
    batches_skipped_empty_queue: u64,
    batches_skipped_insufficient_funds: u64,
    batches_skipped_other_err: u64,
    total_deposits: u64,
    total_withdrawal_requests: u64,
    total_withdrawals_served: u64,
    total_sats_deposited: u64,
    total_sats_withdrawn: u64,
    total_sats_fees: u64,
    /// Orphaned dust: tracks change outputs that, after creation, would
    /// cost more to spend than their value at the prevailing fee rate
    /// (rough heuristic — input weight × mean_fee_rate_sat_vb > amount).
    orphaned_dust_utxos: u64,
    orphaned_dust_sats: u64,
}

/// Summary statistics computed at the end of a run.
#[derive(Debug)]
struct Summary {
    scenario: &'static str,
    ticks: u64,
    wall_time_ms: u128,
    pool_size: Percentiles,
    deposit_pool_size: Percentiles,
    change_pool_size: Percentiles,
    pending_pool_size: Percentiles,
    queue_size: Percentiles,
    batches_attempted: u64,
    batches_produced: u64,
    batches_skipped_empty_queue: u64,
    batches_skipped_insufficient_funds: u64,
    batches_skipped_other_err: u64,
    mean_batch_inputs: f64,
    mean_batch_requests: f64,
    mean_consolidation_inputs: f64,
    fee_per_request: Percentiles,
    /// Total miner fee per produced tx (sat).
    miner_fee_per_tx: Percentiles,
    /// Realised fee rate per produced tx (sat/vB = miner_fee / vsize).
    realised_fee_rate_sat_vb: Percentiles,
    /// Target fee rate passed to `select_coins` for each produced tx.
    target_fee_rate_sat_vb: Percentiles,
    /// Virtual size (vbytes) per produced tx.
    tx_vsize: Percentiles,
    change_ratio_mean: f64,
    spent_deposit_age: Percentiles,
    spent_change_age: Percentiles,
    living_pool_age_at_end: Percentiles,
    total_deposits: u64,
    total_withdrawal_requests: u64,
    total_withdrawals_served: u64,
    total_sats_deposited: u64,
    total_sats_withdrawn: u64,
    total_sats_fees: u64,
    orphaned_dust_utxos: u64,
    orphaned_dust_sats: u64,
}

#[derive(Debug, Default, Clone)]
struct Percentiles {
    min: u64,
    p50: u64,
    mean: f64,
    p95: u64,
    max: u64,
    #[allow(dead_code)]
    n: usize,
}

impl Percentiles {
    fn from_u64(mut v: Vec<u64>) -> Self {
        if v.is_empty() {
            return Self::default();
        }
        v.sort_unstable();
        let n = v.len();
        let sum: u128 = v.iter().map(|&x| x as u128).sum();
        Self {
            min: v[0],
            p50: v[n / 2],
            mean: sum as f64 / n as f64,
            p95: v[(n * 95 / 100).min(n - 1)],
            max: v[n - 1],
            n,
        }
    }
}

// ── RNG helpers ─────────────────────────────────────────────────────────

/// Inverse-CDF Poisson count: given expected rate λ, return an integer
/// count drawn from Poisson(λ). Uses Knuth's algorithm — fine for
/// small rates (<30).
fn poisson(rng: &mut StdRng, lambda: f64) -> u32 {
    if lambda <= 0.0 {
        return 0;
    }
    let l = (-lambda).exp();
    let mut k = 0u32;
    let mut p = 1.0;
    loop {
        k += 1;
        p *= rng.r#gen::<f64>();
        if p <= l {
            return k - 1;
        }
        // Defensive cap; Knuth's algorithm is O(λ) expected.
        if k > 10_000 {
            return k;
        }
    }
}

/// Box–Muller standard-normal sample.
fn std_normal(rng: &mut StdRng) -> f64 {
    let u1 = rng.r#gen::<f64>().max(f64::MIN_POSITIVE);
    let u2 = rng.r#gen::<f64>();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

/// Log-normal sample with given log-space mean and sigma.
fn log_normal(rng: &mut StdRng, mu: f64, sigma: f64) -> f64 {
    (mu + sigma * std_normal(rng)).exp()
}

/// Virtual size in vbytes of a batched withdrawal tx, given the
/// selected inputs, recipient outputs, and whether a change output is
/// present. Mirrors the weight computation in
/// `TransactionBuilder::weight` so the realised fee rate reported by
/// the sim matches what the algorithm actually pays per vbyte.
fn tx_vsize(
    inputs: &[UtxoCandidate],
    outputs: &[WithdrawalOutput],
    has_change: bool,
    change_script_len: u64,
) -> u64 {
    // Non-witness fixed fields: nVersion(4) + nLockTime(4) = 32 WU.
    // Segwit marker + flag = 2 WU.
    let mut wu: u64 = 32 + 2;

    // Varint sizes for input and output counts.
    let n_out = outputs.len() as u64 + if has_change { 1 } else { 0 };
    let varint = |n: u64| -> u64 {
        let bytes = match n {
            0..=252 => 1,
            253..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        };
        bytes * 4
    };
    wu += varint(inputs.len() as u64);
    wu += varint(n_out);

    // Inputs.
    for i in inputs {
        wu += i.spend_path.input_weight().to_wu();
    }

    // Recipient outputs.
    for o in outputs {
        // 36 WU (amount+len) + scriptPubKey bytes × 4.
        let script_len: u64 = match o.recipient.len() {
            20 => 22, // P2WPKH
            _ => 34,  // P2TR (default)
        };
        wu += 36 + script_len * 4;
    }

    // Change output.
    if has_change {
        wu += 36 + change_script_len * 4;
    }

    // vbytes = ceil(wu / 4).
    wu.div_ceil(4)
}

// ── Simulator ───────────────────────────────────────────────────────────

struct Simulator {
    scenario: Scenario,
    rng: StdRng,
    tick: u64,
    pool: Vec<SimUtxo>,
    queue: Vec<SimRequest>,
    next_id: u64,
    #[allow(dead_code)]
    change_address: BitcoinAddress,
    params: CoinSelectionParams,
    metrics: Metrics,
    current_fee_rate_sat_vb: f64,
}

impl Simulator {
    fn new(scenario: Scenario) -> Self {
        let change_address = make_change_address();
        let params = CoinSelectionParams::new(change_address.clone());
        let rng = StdRng::seed_from_u64(scenario.seed);
        let current_fee_rate_sat_vb = scenario.mean_fee_rate_sat_vb;
        Self {
            scenario,
            rng,
            tick: 0,
            pool: Vec::new(),
            queue: Vec::new(),
            next_id: 1,
            change_address,
            params,
            metrics: Metrics::default(),
            current_fee_rate_sat_vb,
        }
    }

    fn fresh_utxo_id(&mut self) -> UtxoId {
        let n = self.next_id;
        self.next_id += 1;
        // Pack the counter into the 32-byte txid so that every UTXO
        // has a unique ID.
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_be_bytes());
        UtxoId {
            txid: BitcoinTxid::new(bytes),
            vout: 0,
        }
    }

    fn fresh_request_id(&mut self) -> Address {
        let n = self.next_id;
        self.next_id += 1;
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_be_bytes());
        Address::new(bytes)
    }

    /// Advance the fee rate as a clamped random walk around the mean.
    fn step_fee_rate(&mut self) {
        let volatility = self.scenario.fee_rate_volatility;
        let mean = self.scenario.mean_fee_rate_sat_vb;
        // Ornstein–Uhlenbeck-like pull toward the mean, plus noise.
        let drift = 0.1 * (mean - self.current_fee_rate_sat_vb);
        let noise = volatility * std_normal(&mut self.rng);
        self.current_fee_rate_sat_vb =
            (self.current_fee_rate_sat_vb + drift + noise).clamp(1.0, 500.0);
    }

    /// Transition pending UTXOs to confirmed when their maturation
    /// delay elapses.
    fn mature_pending(&mut self) {
        let now = self.tick;
        for u in self.pool.iter_mut() {
            if let Some(t) = u.confirms_at_tick
                && now >= t
            {
                u.candidate.status = UtxoStatus::Confirmed;
                u.confirms_at_tick = None;
            }
        }
    }

    /// Generate new Poisson-distributed deposit arrivals. Deposits
    /// start pending and become confirmed after
    /// `deposit_confirmation_delay_ticks`.
    fn arrive_deposits(&mut self) {
        let n = poisson(&mut self.rng, self.scenario.deposit_rate);
        for _ in 0..n {
            let amount = log_normal(
                &mut self.rng,
                self.scenario.deposit_amount_mu,
                self.scenario.deposit_amount_sigma,
            ) as u64;
            // Skip implausibly tiny deposits below the deposit minimum.
            if amount < 10_000 {
                continue;
            }
            let id = self.fresh_utxo_id();
            let candidate = UtxoCandidate {
                id,
                amount,
                spend_path: SpendPath::TaprootScriptPath2of2,
                status: UtxoStatus::Pending {
                    chain: vec![AncestorTx {
                        confirmations: 0,
                        tx_weight: Weight::from_wu(800),
                        tx_fee: 500,
                    }],
                },
            };
            self.pool.push(SimUtxo {
                candidate,
                origin: Origin::Deposit,
                created_at_tick: self.tick,
                confirms_at_tick: Some(
                    self.tick + self.scenario.deposit_confirmation_delay_ticks as u64,
                ),
            });
            self.metrics.total_deposits += 1;
            self.metrics.total_sats_deposited += amount;
        }
    }

    /// Generate new Poisson-distributed withdrawal requests.
    fn arrive_withdrawals(&mut self) {
        let n = poisson(&mut self.rng, self.scenario.withdrawal_rate);
        for _ in 0..n {
            let amount = log_normal(
                &mut self.rng,
                self.scenario.withdrawal_amount_mu,
                self.scenario.withdrawal_amount_sigma,
            ) as u64;
            // Skip requests below a safe floor to avoid `RequestAmountTooSmall`
            // dominating the metrics — in practice the hashi UI would
            // reject these too.
            if amount < 50_000 {
                continue;
            }
            let id = self.fresh_request_id();
            let request = WithdrawalRequest {
                id,
                recipient: p2tr_recipient(),
                amount,
                timestamp_ms: self.tick * BATCH_INTERVAL_MS,
            };
            self.queue.push(SimRequest {
                request,
                created_at_tick: self.tick,
            });
            self.metrics.total_withdrawal_requests += 1;
        }
    }

    /// Try to produce a batch: call `select_coins` with the current
    /// pool and queue, apply the result, and record metrics.
    fn try_batch(&mut self) -> Option<BatchSample> {
        self.metrics.batches_attempted += 1;
        if self.queue.is_empty() {
            self.metrics.batches_skipped_empty_queue += 1;
            return None;
        }

        let candidates: Vec<UtxoCandidate> =
            self.pool.iter().map(|u| u.candidate.clone()).collect();
        let requests: Vec<WithdrawalRequest> =
            self.queue.iter().map(|r| r.request.clone()).collect();

        let fee_rate = FeeRate::from_sat_per_vb_unchecked(
            self.current_fee_rate_sat_vb.round().max(1.0) as u64,
        );

        let result = select_coins(&candidates, &requests, &self.params, fee_rate);

        let result = match result {
            Ok(r) => r,
            Err(CoinSelectionError::InsufficientFunds { .. }) => {
                self.metrics.batches_skipped_insufficient_funds += 1;
                return None;
            }
            Err(CoinSelectionError::NoRequests | CoinSelectionError::EmptyPool) => {
                self.metrics.batches_skipped_empty_queue += 1;
                return None;
            }
            Err(_) => {
                self.metrics.batches_skipped_other_err += 1;
                return None;
            }
        };

        self.metrics.batches_produced += 1;

        // Compute batch-level metrics before mutating state.
        let n_inputs = result.inputs.len();
        let n_requests = result.selected_requests.len();
        // Consolidation inputs: anything beyond what was needed to
        // cover the requests is considered consolidation. We approximate
        // this by counting how many inputs could have been dropped
        // while still covering the request sum.
        let total_requested: u64 = result.selected_requests.iter().map(|r| r.amount).sum();
        let mut sorted_input_amounts: Vec<u64> = result.inputs.iter().map(|u| u.amount).collect();
        sorted_input_amounts.sort_unstable_by(|a, b| b.cmp(a));
        let mut running = 0u64;
        let mut min_inputs_needed = 0usize;
        for amt in &sorted_input_amounts {
            running += *amt;
            min_inputs_needed += 1;
            if running >= total_requested {
                break;
            }
        }
        let consolidation_inputs = n_inputs.saturating_sub(min_inputs_needed);

        let fee_per_request = if n_requests > 0 {
            result.fee / n_requests as u64
        } else {
            0
        };

        // Realised fee rate = miner_fee / vsize. May exceed the target
        // rate due to ceil-division rounding and CPFP deficit added
        // for unconfirmed ancestors.
        let change_script_len = self.change_address.script_pubkey().len() as u64;
        let vsize = tx_vsize(
            &result.inputs,
            &result.withdrawal_outputs,
            result.change.is_some(),
            change_script_len,
        );
        let target_fee_rate_sat_vb = fee_rate.to_sat_per_vb_ceil();
        let realised_fee_rate_sat_vb = if vsize > 0 {
            result.fee.div_ceil(vsize)
        } else {
            0
        };

        // Tally deposit vs change origin for the spent inputs, and ages.
        let spent_ids: std::collections::HashSet<UtxoId> =
            result.inputs.iter().map(|u| u.id).collect();

        let mut deposit_inputs = 0usize;
        let mut change_inputs = 0usize;
        let mut sum_input_age = 0u64;
        for u in self.pool.iter() {
            if spent_ids.contains(&u.candidate.id) {
                match u.origin {
                    Origin::Deposit => {
                        deposit_inputs += 1;
                        self.metrics
                            .spend_event_ages
                            .deposit_ages
                            .push(u.age(self.tick));
                    }
                    Origin::Change => {
                        change_inputs += 1;
                        self.metrics
                            .spend_event_ages
                            .change_ages
                            .push(u.age(self.tick));
                    }
                }
                sum_input_age += u.age(self.tick);
            }
        }

        // Remove spent inputs from the pool.
        self.pool.retain(|u| !spent_ids.contains(&u.candidate.id));

        // Remove served requests from the queue.
        let served_ids: std::collections::HashSet<Address> =
            result.selected_requests.iter().map(|r| r.id).collect();
        let served_count = self
            .queue
            .iter()
            .filter(|r| served_ids.contains(&r.request.id))
            .count();
        self.queue.retain(|r| !served_ids.contains(&r.request.id));
        self.metrics.total_withdrawals_served += served_count as u64;
        self.metrics.total_sats_withdrawn += result
            .withdrawal_outputs
            .iter()
            .map(|o| o.amount)
            .sum::<u64>();
        self.metrics.total_sats_fees += result.fee;

        // Add change UTXO back to the pool as pending.
        if let Some(change) = result.change {
            // Orphaned-dust heuristic: if the rough cost to spend this
            // change output at the mean fee rate exceeds its value,
            // mark it as orphaned.
            let spend_weight_vb = SpendPath::TaprootScriptPath2of2
                .input_weight()
                .to_vbytes_ceil();
            let spend_cost = (spend_weight_vb as f64 * self.scenario.mean_fee_rate_sat_vb) as u64;
            if spend_cost >= change {
                self.metrics.orphaned_dust_utxos += 1;
                self.metrics.orphaned_dust_sats += change;
            }

            let id = self.fresh_utxo_id();
            let candidate = UtxoCandidate {
                id,
                amount: change,
                spend_path: SpendPath::TaprootScriptPath2of2,
                status: UtxoStatus::Pending {
                    chain: vec![AncestorTx {
                        confirmations: 0,
                        tx_weight: Weight::from_wu(result.inputs.len() as u64 * 300 + 500),
                        tx_fee: result.fee,
                    }],
                },
            };
            self.pool.push(SimUtxo {
                candidate,
                origin: Origin::Change,
                created_at_tick: self.tick,
                confirms_at_tick: Some(
                    self.tick + self.scenario.change_confirmation_delay_ticks as u64,
                ),
            });
        }

        Some(BatchSample {
            inputs: n_inputs,
            requests: n_requests,
            consolidation_inputs,
            fee_per_request,
            miner_fee: result.fee,
            target_fee_rate_sat_vb,
            realised_fee_rate_sat_vb,
            vsize,
            change: result.change,
            deposit_inputs,
            change_inputs,
            sum_input_age,
        })
    }

    fn sample(&self, batch: Option<BatchSample>) -> TickSample {
        let mut deposit_pool_size = 0usize;
        let mut change_pool_size = 0usize;
        let mut pending_pool_size = 0usize;
        for u in &self.pool {
            match u.origin {
                Origin::Deposit => deposit_pool_size += 1,
                Origin::Change => change_pool_size += 1,
            }
            if !matches!(u.candidate.status, UtxoStatus::Confirmed) {
                pending_pool_size += 1;
            }
        }
        TickSample {
            tick: self.tick,
            pool_size: self.pool.len(),
            deposit_pool_size,
            change_pool_size,
            pending_pool_size,
            queue_size: self.queue.len(),
            fee_rate_sat_vb: self.current_fee_rate_sat_vb.round() as u64,
            batch,
        }
    }

    fn step(&mut self) {
        self.step_fee_rate();
        self.mature_pending();
        self.arrive_deposits();
        self.arrive_withdrawals();
        let batch = self.try_batch();
        let sample = self.sample(batch);
        self.metrics.samples.push(sample);
        self.tick += 1;
    }

    fn run(&mut self) {
        for _ in 0..self.scenario.ticks {
            self.step();
        }
    }

    fn summarize(&self, wall_time_ms: u128) -> Summary {
        let m = &self.metrics;

        let pool_size =
            Percentiles::from_u64(m.samples.iter().map(|s| s.pool_size as u64).collect());
        let deposit_pool_size = Percentiles::from_u64(
            m.samples
                .iter()
                .map(|s| s.deposit_pool_size as u64)
                .collect(),
        );
        let change_pool_size = Percentiles::from_u64(
            m.samples
                .iter()
                .map(|s| s.change_pool_size as u64)
                .collect(),
        );
        let pending_pool_size = Percentiles::from_u64(
            m.samples
                .iter()
                .map(|s| s.pending_pool_size as u64)
                .collect(),
        );
        let queue_size =
            Percentiles::from_u64(m.samples.iter().map(|s| s.queue_size as u64).collect());

        let batches: Vec<&BatchSample> =
            m.samples.iter().filter_map(|s| s.batch.as_ref()).collect();
        let mean_batch_inputs = mean(batches.iter().map(|b| b.inputs as f64));
        let mean_batch_requests = mean(batches.iter().map(|b| b.requests as f64));
        let mean_consolidation_inputs = mean(batches.iter().map(|b| b.consolidation_inputs as f64));
        let fee_per_request =
            Percentiles::from_u64(batches.iter().map(|b| b.fee_per_request).collect());
        let miner_fee_per_tx = Percentiles::from_u64(batches.iter().map(|b| b.miner_fee).collect());
        let realised_fee_rate_sat_vb =
            Percentiles::from_u64(batches.iter().map(|b| b.realised_fee_rate_sat_vb).collect());
        let target_fee_rate_sat_vb =
            Percentiles::from_u64(batches.iter().map(|b| b.target_fee_rate_sat_vb).collect());
        let tx_vsize = Percentiles::from_u64(batches.iter().map(|b| b.vsize).collect());

        // Pool-level deposit vs change ratio (fraction of change UTXOs).
        let change_ratio_mean = mean(m.samples.iter().map(|s| {
            if s.pool_size == 0 {
                0.0
            } else {
                s.change_pool_size as f64 / s.pool_size as f64
            }
        }));

        let spent_deposit_age = Percentiles::from_u64(m.spend_event_ages.deposit_ages.clone());
        let spent_change_age = Percentiles::from_u64(m.spend_event_ages.change_ages.clone());

        let now = self.tick;
        let living_ages: Vec<u64> = self.pool.iter().map(|u| u.age(now)).collect();
        let living_pool_age_at_end = Percentiles::from_u64(living_ages);

        Summary {
            scenario: self.scenario.name,
            ticks: self.scenario.ticks,
            wall_time_ms,
            pool_size,
            deposit_pool_size,
            change_pool_size,
            pending_pool_size,
            queue_size,
            batches_attempted: m.batches_attempted,
            batches_produced: m.batches_produced,
            batches_skipped_empty_queue: m.batches_skipped_empty_queue,
            batches_skipped_insufficient_funds: m.batches_skipped_insufficient_funds,
            batches_skipped_other_err: m.batches_skipped_other_err,
            mean_batch_inputs,
            mean_batch_requests,
            mean_consolidation_inputs,
            fee_per_request,
            miner_fee_per_tx,
            realised_fee_rate_sat_vb,
            target_fee_rate_sat_vb,
            tx_vsize,
            change_ratio_mean,
            spent_deposit_age,
            spent_change_age,
            living_pool_age_at_end,
            total_deposits: m.total_deposits,
            total_withdrawal_requests: m.total_withdrawal_requests,
            total_withdrawals_served: m.total_withdrawals_served,
            total_sats_deposited: m.total_sats_deposited,
            total_sats_withdrawn: m.total_sats_withdrawn,
            total_sats_fees: m.total_sats_fees,
            orphaned_dust_utxos: m.orphaned_dust_utxos,
            orphaned_dust_sats: m.orphaned_dust_sats,
        }
    }
}

fn mean<I: Iterator<Item = f64>>(iter: I) -> f64 {
    let mut n = 0usize;
    let mut sum = 0.0;
    for x in iter {
        n += 1;
        sum += x;
    }
    if n == 0 { 0.0 } else { sum / n as f64 }
}

// ── Test-fixture helpers (copied from tests.rs to avoid cross-module
// visibility noise). ────────────────────────────────────────────────────

fn p2tr_recipient() -> Vec<u8> {
    vec![0x02u8; 32]
}

fn make_change_address() -> BitcoinAddress {
    let wp = WitnessProgram::new(WitnessVersion::V1, &[0x04u8; 32]).unwrap();
    let script = bitcoin::ScriptBuf::new_witness_program(&wp);
    BitcoinAddress::from_script(&script, bitcoin::Network::Bitcoin).unwrap()
}

// ── Report rendering ────────────────────────────────────────────────────

/// Format a whole-sat value as a BTC string (8 decimal places), useful
/// when totals get large enough that raw sat counts are hard to read.
fn fmt_btc(sats: u64) -> String {
    let whole = sats / 100_000_000;
    let frac = sats % 100_000_000;
    format!("{whole}.{frac:08} BTC")
}

/// Insert thousands separators into a u64.
fn fmt_int(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, &b) in bytes.iter().enumerate() {
        // A comma goes before every digit whose position-from-the-end
        // is a non-zero multiple of 3.
        let pos_from_end = len - i;
        if i > 0 && pos_from_end.is_multiple_of(3) {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

fn render_summary(s: &Summary) -> String {
    // Force colour on even when stderr is captured by the test harness
    // — this makes `cargo test -- --nocapture` print coloured output
    // to the terminal. Respects NO_COLOR via an explicit check.
    if std::env::var_os("NO_COLOR").is_none() {
        colored::control::set_override(true);
    }

    use std::fmt::Write;
    let mut out = String::new();

    let days = s.ticks * 5 / (24 * 60);
    let days_f = days as f64;

    // ── Header ────────────────────────────────────────────────────────
    let _ = writeln!(out);
    let header = format!(" UTXO-pool simulation — {} ", s.scenario.to_uppercase(),);
    let bar = "━".repeat(header.chars().count() + 4);
    let _ = writeln!(out, "{}", bar.bright_cyan());
    let _ = writeln!(out, "  {}", header.bright_white().bold().on_blue());
    let _ = writeln!(
        out,
        "  {} {} ticks · {} days · wall {} ms",
        "run:".dimmed(),
        fmt_int(s.ticks).bright_white(),
        days.to_string().bright_white(),
        s.wall_time_ms.to_string().bright_white(),
    );
    let _ = writeln!(out, "{}", bar.bright_cyan());
    let _ = writeln!(out);

    // ── Distributional metrics table ──────────────────────────────────
    let _ = writeln!(out, "{}", "  Distributional metrics".bright_yellow().bold());
    let _ = writeln!(
        out,
        "  {:<30} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "metric".bright_white().bold(),
        "min".bright_white().bold(),
        "p50".bright_white().bold(),
        "mean".bright_white().bold(),
        "p95".bright_white().bold(),
        "max".bright_white().bold(),
    );
    let row = |label: &str, p: &Percentiles, colour: Color, indent: bool| -> String {
        let lbl = if indent {
            format!("  {label}")
        } else {
            label.to_string()
        };
        format!(
            "  {:<30} {:>10} {:>10} {:>10} {:>10} {:>10}\n",
            lbl.color(colour),
            fmt_int(p.min).color(colour),
            fmt_int(p.p50).color(colour),
            format!("{:.2}", p.mean).color(colour),
            fmt_int(p.p95).color(colour),
            fmt_int(p.max).color(colour),
        )
    };
    out.push_str(&row("pool_size", &s.pool_size, Color::BrightGreen, false));
    out.push_str(&row(
        "deposit_origin",
        &s.deposit_pool_size,
        Color::Green,
        true,
    ));
    out.push_str(&row(
        "change_origin",
        &s.change_pool_size,
        Color::Green,
        true,
    ));
    out.push_str(&row("pending", &s.pending_pool_size, Color::Green, true));
    out.push_str(&row(
        "queue_size",
        &s.queue_size,
        Color::BrightMagenta,
        false,
    ));
    out.push_str(&row(
        "miner_fee_per_tx (sat)",
        &s.miner_fee_per_tx,
        Color::BrightCyan,
        false,
    ));
    out.push_str(&row(
        "fee_per_request (sat)",
        &s.fee_per_request,
        Color::Cyan,
        true,
    ));
    out.push_str(&row(
        "target_fee_rate (sat/vB)",
        &s.target_fee_rate_sat_vb,
        Color::BrightCyan,
        false,
    ));
    out.push_str(&row(
        "realised_fee_rate (sat/vB)",
        &s.realised_fee_rate_sat_vb,
        Color::Cyan,
        true,
    ));
    out.push_str(&row("tx_vsize (vbytes)", &s.tx_vsize, Color::Cyan, false));
    out.push_str(&row(
        "spent_deposit_age (ticks)",
        &s.spent_deposit_age,
        Color::Cyan,
        false,
    ));
    out.push_str(&row(
        "spent_change_age (ticks)",
        &s.spent_change_age,
        Color::Cyan,
        false,
    ));
    out.push_str(&row(
        "living_pool_age (ticks)",
        &s.living_pool_age_at_end,
        Color::Cyan,
        false,
    ));
    let _ = writeln!(out);

    // ── Batch summary ─────────────────────────────────────────────────
    let _ = writeln!(out, "{}", "  Batches".bright_yellow().bold());
    let _ = writeln!(
        out,
        "  {:<30} {}",
        "attempted".white(),
        fmt_int(s.batches_attempted).bright_white(),
    );
    let _ = writeln!(
        out,
        "  {:<30} {}",
        "produced".white(),
        fmt_int(s.batches_produced).bright_green(),
    );
    let _ = writeln!(
        out,
        "  {:<30} {}",
        "skipped (empty queue)".white(),
        fmt_int(s.batches_skipped_empty_queue).yellow(),
    );
    let _ = writeln!(
        out,
        "  {:<30} {}",
        "skipped (insufficient funds)".white(),
        fmt_int(s.batches_skipped_insufficient_funds).red(),
    );
    let _ = writeln!(
        out,
        "  {:<30} {}",
        "skipped (other error)".white(),
        fmt_int(s.batches_skipped_other_err).red(),
    );
    let _ = writeln!(
        out,
        "  {:<30} inputs={:.2}  requests={:.2}  consolidation_inputs={:.2}  change_ratio={:.3}",
        "mean per batch".white(),
        s.mean_batch_inputs,
        s.mean_batch_requests,
        s.mean_consolidation_inputs,
        s.change_ratio_mean,
    );
    let _ = writeln!(out);

    // ── Totals ────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}", "  Totals".bright_yellow().bold());
    let per_day = |n: u64| -> String {
        if days_f > 0.0 {
            format!("{:.1}/day", n as f64 / days_f)
        } else {
            String::from("n/a")
        }
    };
    let _ = writeln!(
        out,
        "  {:<30} {}  ({}) · {}",
        "deposits".white(),
        fmt_int(s.total_deposits).bright_green(),
        per_day(s.total_deposits).bright_green(),
        fmt_btc(s.total_sats_deposited).bright_green(),
    );
    let _ = writeln!(
        out,
        "  {:<30} {}  ({})",
        "withdrawal requests".white(),
        fmt_int(s.total_withdrawal_requests).bright_magenta(),
        per_day(s.total_withdrawal_requests).bright_magenta(),
    );
    let _ = writeln!(
        out,
        "  {:<30} {}  ({}) · {}",
        "withdrawals served".white(),
        fmt_int(s.total_withdrawals_served).bright_magenta(),
        per_day(s.total_withdrawals_served).bright_magenta(),
        fmt_btc(s.total_sats_withdrawn).bright_magenta(),
    );
    let unserved = s
        .total_withdrawal_requests
        .saturating_sub(s.total_withdrawals_served);
    if unserved > 0 {
        let _ = writeln!(
            out,
            "  {:<30} {}",
            "  unserved at end".white(),
            fmt_int(unserved).red(),
        );
    }
    let _ = writeln!(
        out,
        "  {:<30} {}",
        "miner fees paid".white(),
        fmt_btc(s.total_sats_fees).bright_cyan(),
    );

    // Balance hint: deposits vs withdrawals + fees.
    let deposited = s.total_sats_deposited as i128;
    let drained = s.total_sats_withdrawn as i128 + s.total_sats_fees as i128;
    let net = deposited - drained;
    let net_str = if net >= 0 {
        fmt_btc(net as u64).bright_green()
    } else {
        format!("-{}", fmt_btc((-net) as u64)).bright_red()
    };
    let _ = writeln!(
        out,
        "  {:<30} {} (pool holdings change)",
        "net flow".white(),
        net_str,
    );

    // Rate balance hint: flag if deposit/withdrawal rates are
    // meaningfully imbalanced for a scenario labelled "steady_state".
    if s.scenario == "steady_state" && s.total_deposits > 0 && s.total_withdrawals_served > 0 {
        let ratio = s.total_deposits as f64 / s.total_withdrawals_served as f64;
        let label = if (0.9..=1.1).contains(&ratio) {
            "BALANCED".green()
        } else {
            "IMBALANCED".red()
        };
        let _ = writeln!(
            out,
            "  {:<30} dep/wd ratio = {:.3}   {}",
            "rate check".white(),
            ratio,
            label,
        );
    }
    let _ = writeln!(out);

    // ── Orphaned dust ─────────────────────────────────────────────────
    let dust_colour = if s.orphaned_dust_utxos == 0 {
        Color::BrightGreen
    } else {
        Color::BrightRed
    };
    let _ = writeln!(
        out,
        "  {} {} utxos · {}",
        "Orphaned dust:".bright_yellow().bold(),
        fmt_int(s.orphaned_dust_utxos).color(dust_colour),
        fmt_btc(s.orphaned_dust_sats).color(dust_colour),
    );

    out
}

fn render_csv(samples: &[TickSample]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "tick,pool_size,deposit_pool_size,change_pool_size,pending_pool_size,queue_size,fee_rate_sat_vb,batch_inputs,batch_requests,consolidation_inputs,fee_per_request,miner_fee,tx_vsize,realised_fee_rate_sat_vb,target_fee_rate_sat_vb,change,deposit_inputs,change_inputs"
    );
    for s in samples {
        if let Some(b) = &s.batch {
            let _ = writeln!(
                out,
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                s.tick,
                s.pool_size,
                s.deposit_pool_size,
                s.change_pool_size,
                s.pending_pool_size,
                s.queue_size,
                s.fee_rate_sat_vb,
                b.inputs,
                b.requests,
                b.consolidation_inputs,
                b.fee_per_request,
                b.miner_fee,
                b.vsize,
                b.realised_fee_rate_sat_vb,
                b.target_fee_rate_sat_vb,
                b.change.unwrap_or(0),
                b.deposit_inputs,
                b.change_inputs,
            );
        } else {
            let _ = writeln!(
                out,
                "{},{},{},{},{},{},{},,,,,,,,,,,",
                s.tick,
                s.pool_size,
                s.deposit_pool_size,
                s.change_pool_size,
                s.pending_pool_size,
                s.queue_size,
                s.fee_rate_sat_vb,
            );
        }
    }
    out
}

/// Optionally dump a per-tick CSV to a file when the environment
/// variable `UTXO_SIM_CSV_DIR` is set. This lets developers capture
/// detailed data for plotting without making CI noisy.
fn maybe_dump_csv(scenario: &str, samples: &[TickSample]) {
    let Ok(dir) = std::env::var("UTXO_SIM_CSV_DIR") else {
        return;
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("utxo_sim: failed to create {dir}: {e}");
        return;
    }
    let path = format!("{dir}/{scenario}.csv");
    match std::fs::write(&path, render_csv(samples)) {
        Ok(()) => eprintln!("utxo_sim: wrote {path}"),
        Err(e) => eprintln!("utxo_sim: failed to write {path}: {e}"),
    }
}

// ── Assertions ──────────────────────────────────────────────────────────

/// Invariants every scenario must satisfy. These are intentionally
/// loose — the point of the sim is observation, not tight bounds.
fn assert_invariants(s: &Summary) {
    // The sim must actually run long enough to be statistically meaningful.
    assert!(s.ticks > 100, "sim too short to draw conclusions");

    // Accounting: every served request should come with some deducted fee.
    if s.total_withdrawals_served > 0 {
        assert!(s.total_sats_fees > 0, "served withdrawals but no fees");
    }

    // Sanity: we must have at least attempted batches.
    assert!(s.batches_attempted > 0);

    // Guard against truly unbounded growth. The high-fee scenario
    // legitimately grows to several thousand UTXOs (that's the whole
    // point of measuring it), so this ceiling only catches a
    // pathological leak — e.g., the sim failing to remove spent
    // inputs and growing monotonically with every batch.
    assert!(
        s.pool_size.max < 100_000,
        "pool grew pathologically large (likely a bug in the sim, \
         not the algorithm): max={}",
        s.pool_size.max,
    );

    // Conservation: total deposited should exceed total withdrawn +
    // fees by any residual in the pool (we don't try to reconstruct
    // the residual here, just assert an upper bound).
    assert!(
        s.total_sats_deposited + 1_000_000 >= s.total_sats_withdrawn + s.total_sats_fees,
        "withdrawn+fees ({} + {}) exceed deposited ({}) — something leaked \
         sats into the pool",
        s.total_sats_withdrawn,
        s.total_sats_fees,
        s.total_sats_deposited,
    );
}

// ── Test entries ────────────────────────────────────────────────────────

fn run_scenario(scenario: Scenario) -> Summary {
    let name = scenario.name;
    let start = std::time::Instant::now();
    let mut sim = Simulator::new(scenario);
    sim.run();
    let wall_time_ms = start.elapsed().as_millis();
    let summary = sim.summarize(wall_time_ms);

    // Print to stderr so the output is visible with `cargo test --
    // --nocapture` but doesn't clutter `cargo test` by default.
    eprintln!("{}", render_summary(&summary));
    maybe_dump_csv(name, &sim.metrics.samples);

    assert_invariants(&summary);
    summary
}

#[test]
fn sim_steady_state() {
    run_scenario(Scenario::steady_state());
}

#[test]
fn sim_deposit_heavy() {
    run_scenario(Scenario::deposit_heavy());
}

#[test]
fn sim_withdrawal_heavy() {
    run_scenario(Scenario::withdrawal_heavy());
}

#[test]
fn sim_high_fee_period() {
    run_scenario(Scenario::high_fee_period());
}

/// Determinism check: two runs with the same seed produce identical
/// summary statistics.
#[test]
fn sim_is_deterministic() {
    let a = Simulator::new(Scenario {
        ticks: 200,
        ..Scenario::steady_state()
    });
    let b = Simulator::new(Scenario {
        ticks: 200,
        ..Scenario::steady_state()
    });

    let mut a = a;
    let mut b = b;
    a.run();
    b.run();

    let sa = a.summarize(0);
    let sb = b.summarize(0);

    assert_eq!(sa.total_deposits, sb.total_deposits);
    assert_eq!(sa.total_withdrawal_requests, sb.total_withdrawal_requests);
    assert_eq!(sa.total_withdrawals_served, sb.total_withdrawals_served);
    assert_eq!(sa.total_sats_deposited, sb.total_sats_deposited);
    assert_eq!(sa.total_sats_withdrawn, sb.total_sats_withdrawn);
    assert_eq!(sa.total_sats_fees, sb.total_sats_fees);
    assert_eq!(sa.batches_produced, sb.batches_produced);
}
