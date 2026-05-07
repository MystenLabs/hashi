// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Read-only reconciler that compares the local-limiter snapshot
//! against the guardian's authoritative `LimiterState` on a fixed
//! interval. Surfaces drift as metrics + logs; never mutates state.
//!
//! The watcher's gap-fill (`crate::onchain::watcher::replay_gap`) is
//! the actual recovery path for missed events — this module is the
//! integrity check that makes a stuck or invisible drift detectable.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use hashi_types::guardian::LimiterState;
use sui_futures::service::Service;
use tokio::time::MissedTickBehavior;
use tokio::time::interval;

use crate::Hashi;
use crate::guardian_limiter::LocalLimiter;
use crate::metrics;

/// Result of comparing a `(local, guardian)` snapshot pair. Drives the
/// reconciler's metric labels and log severity. Stays an enum (not a
/// struct of nullable fields) so adding a new outcome forces every
/// match site to consider the new case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Local and guardian agree (`next_seq` equal).
    Healthy,
    /// Guardian is ahead of local by `drift_seq`, but within
    /// `tolerance` — expected window for in-flight withdrawals
    /// approved by the guardian but not yet committed on-chain.
    LaggingWithinTolerance { drift_seq: u64 },
    /// Guardian is ahead of local by more than `tolerance`. The
    /// watcher's gap-fill should close this on the next reconnect;
    /// if it persists, we've genuinely lost sync.
    Lagging { drift_seq: u64 },
    /// Local has advanced past the guardian. Impossible during normal
    /// operation: every local advance is caused by a chain event that
    /// the guardian had already approved (and incremented its own
    /// counter for). Always indicates a bug or a guardian rollback.
    Ahead { drift_seq: u64 },
}

/// Pure comparison of two `LimiterState` snapshots. `tolerance` is the
/// number of `next_seq` units guardian is allowed to lead local by
/// before it counts as drift — typically the in-flight cap (1) plus a
/// little slack for clock/checkpoint propagation.
pub fn classify(local: &LimiterState, guardian: &LimiterState, tolerance: u64) -> Outcome {
    if guardian.next_seq < local.next_seq {
        return Outcome::Ahead {
            drift_seq: local.next_seq - guardian.next_seq,
        };
    }
    let drift_seq = guardian.next_seq - local.next_seq;
    if drift_seq == 0 {
        Outcome::Healthy
    } else if drift_seq <= tolerance {
        Outcome::LaggingWithinTolerance { drift_seq }
    } else {
        Outcome::Lagging { drift_seq }
    }
}

impl Outcome {
    /// Stable label for `guardian_reconciler_outcomes_total`.
    fn metric_label(&self) -> &'static str {
        match self {
            Outcome::Healthy => metrics::GUARDIAN_RECONCILER_OUTCOME_HEALTHY,
            Outcome::LaggingWithinTolerance { .. } => {
                metrics::GUARDIAN_RECONCILER_OUTCOME_LAGGING_WITHIN_TOLERANCE
            }
            Outcome::Lagging { .. } => metrics::GUARDIAN_RECONCILER_OUTCOME_LAGGING,
            Outcome::Ahead { .. } => metrics::GUARDIAN_RECONCILER_OUTCOME_AHEAD,
        }
    }
}

/// Periodic poll service. One instance per node. Runs as long as the
/// guardian client is configured AND the local limiter has been seeded
/// — both gates are checked once at startup; the service exits cleanly
/// if either is absent.
pub fn start_reconciler(hashi: Arc<Hashi>) -> Service {
    let interval_dur = hashi.config.guardian_reconciliation_interval();
    let drift_alert_after = hashi.config.guardian_reconciliation_drift_alert();
    let tolerance_seq = hashi.config.guardian_reconciliation_tolerance_seq();

    Service::new().spawn_aborting(async move {
        // No work to do without a guardian client.
        if hashi.guardian_client().is_none() {
            tracing::debug!("guardian reconciler: no guardian client; service exiting");
            return Ok(());
        }

        // Wait for bootstrap to seed the limiter. We poll on the same
        // cadence as the reconciler tick to avoid a busy loop.
        let limiter = wait_for_local_limiter(&hashi, interval_dur).await;

        let mut tick = interval(interval_dur);
        // After a long backpressure window, fire once and resume the
        // schedule rather than firing back-to-back.
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Skip the immediate-fire first tick: bootstrap already left
        // us in lockstep, and rapid-firing the RPC at boot adds no
        // signal beyond what the bootstrap RPC already produced.
        tick.tick().await;

        let mut first_drift_seen_at: Option<Instant> = None;
        loop {
            tick.tick().await;
            run_tick(
                &hashi,
                &limiter,
                tolerance_seq,
                drift_alert_after,
                &mut first_drift_seen_at,
            )
            .await;
        }
    })
}

async fn wait_for_local_limiter(hashi: &Arc<Hashi>, poll: Duration) -> Arc<LocalLimiter> {
    loop {
        if let Some(limiter) = hashi.local_limiter() {
            return limiter;
        }
        tokio::time::sleep(poll).await;
    }
}

/// One reconciler tick. Pulled out of the loop so tests can drive the
/// drift-timer logic without having to fake a `tokio::time::interval`.
async fn run_tick(
    hashi: &Arc<Hashi>,
    limiter: &Arc<LocalLimiter>,
    tolerance_seq: u64,
    drift_alert_after: Duration,
    first_drift_seen_at: &mut Option<Instant>,
) {
    let Some(client) = hashi.guardian_client() else {
        return;
    };
    let metrics = &hashi.metrics;

    let rpc_started = Instant::now();
    let info_pb = match client.get_guardian_info().await {
        Ok(info) => {
            metrics.record_guardian_rpc(
                metrics::GUARDIAN_RPC_METHOD_GET_GUARDIAN_INFO,
                metrics::GUARDIAN_RPC_OUTCOME_OK,
                rpc_started.elapsed().as_secs_f64(),
            );
            info
        }
        Err(e) => {
            metrics.record_guardian_rpc(
                metrics::GUARDIAN_RPC_METHOD_GET_GUARDIAN_INFO,
                metrics::GUARDIAN_RPC_OUTCOME_UNAVAILABLE,
                rpc_started.elapsed().as_secs_f64(),
            );
            metrics.record_reconciliation_rpc_failure();
            tracing::warn!("guardian reconciler: GetGuardianInfo failed: {e}");
            return;
        }
    };

    let info = match hashi_types::guardian::GetGuardianInfoResponse::try_from(info_pb) {
        Ok(info) => info,
        Err(e) => {
            metrics.record_reconciliation_rpc_failure();
            tracing::warn!("guardian reconciler: GetGuardianInfo parse failed: {e:?}");
            return;
        }
    };
    let Some(guardian_state) = info.limiter_state else {
        // Guardian has no limiter yet — the bootstrap loop will keep
        // retrying on its own. Don't flap reconciler counters during
        // that window; treat as RPC-unavailable for accounting.
        metrics.record_reconciliation_rpc_failure();
        return;
    };

    let local_state = limiter.snapshot();
    let outcome = classify(&local_state, &guardian_state, tolerance_seq);
    metrics.record_reconciliation_tick(
        local_state.next_seq,
        guardian_state.next_seq,
        outcome.metric_label(),
    );

    match outcome {
        Outcome::Healthy => {
            *first_drift_seen_at = None;
            tracing::debug!(
                local_seq = local_state.next_seq,
                guardian_seq = guardian_state.next_seq,
                "guardian reconciler: healthy"
            );
        }
        Outcome::LaggingWithinTolerance { drift_seq } => {
            *first_drift_seen_at = None;
            tracing::debug!(
                drift_seq,
                local_seq = local_state.next_seq,
                guardian_seq = guardian_state.next_seq,
                "guardian reconciler: in-flight tolerance window"
            );
        }
        Outcome::Lagging { drift_seq } => {
            let started = first_drift_seen_at.get_or_insert_with(Instant::now);
            let elapsed = started.elapsed();
            if elapsed >= drift_alert_after {
                metrics.guardian_limiter_drifted.set(1);
                tracing::error!(
                    drift_seq,
                    local_seq = local_state.next_seq,
                    guardian_seq = guardian_state.next_seq,
                    elapsed_secs = elapsed.as_secs(),
                    "guardian reconciler: local limiter has been lagging beyond tolerance \
                     for too long; watcher gap-fill has not closed it — this is a paged alert"
                );
            } else {
                tracing::warn!(
                    drift_seq,
                    local_seq = local_state.next_seq,
                    guardian_seq = guardian_state.next_seq,
                    elapsed_secs = elapsed.as_secs(),
                    "guardian reconciler: lag observed; watcher gap-fill should close this on \
                     next reconnect"
                );
            }
        }
        Outcome::Ahead { drift_seq } => {
            // Local advancing past the guardian is impossible during
            // normal operation. Flip the sticky bit immediately —
            // there's no plausible self-healing path.
            metrics.guardian_limiter_drifted.set(1);
            tracing::error!(
                drift_seq,
                local_seq = local_state.next_seq,
                guardian_seq = guardian_state.next_seq,
                "guardian reconciler: local limiter is ahead of the guardian — \
                 this is a paged alert (bug or guardian rollback)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(next_seq: u64) -> LimiterState {
        LimiterState {
            num_tokens_available: 0,
            last_updated_at: 0,
            next_seq,
        }
    }

    #[test]
    fn healthy_when_seqs_match() {
        assert_eq!(classify(&st(7), &st(7), 2), Outcome::Healthy);
    }

    #[test]
    fn lagging_within_tolerance_at_boundary() {
        assert_eq!(
            classify(&st(7), &st(9), 2),
            Outcome::LaggingWithinTolerance { drift_seq: 2 }
        );
    }

    #[test]
    fn lagging_one_past_tolerance() {
        assert_eq!(classify(&st(7), &st(10), 2), Outcome::Lagging { drift_seq: 3 });
    }

    #[test]
    fn lagging_far_behind() {
        assert_eq!(
            classify(&st(0), &st(5_000), 2),
            Outcome::Lagging { drift_seq: 5_000 }
        );
    }

    #[test]
    fn ahead_when_local_runs_past_guardian() {
        assert_eq!(classify(&st(10), &st(7), 2), Outcome::Ahead { drift_seq: 3 });
    }

    #[test]
    fn zero_tolerance_treats_any_lag_as_lagging() {
        assert_eq!(classify(&st(7), &st(8), 0), Outcome::Lagging { drift_seq: 1 });
    }

    #[test]
    fn equal_with_zero_tolerance_is_healthy() {
        assert_eq!(classify(&st(7), &st(7), 0), Outcome::Healthy);
    }

    #[test]
    fn metric_labels_match_metrics_module_constants() {
        assert_eq!(
            Outcome::Healthy.metric_label(),
            metrics::GUARDIAN_RECONCILER_OUTCOME_HEALTHY
        );
        assert_eq!(
            Outcome::LaggingWithinTolerance { drift_seq: 1 }.metric_label(),
            metrics::GUARDIAN_RECONCILER_OUTCOME_LAGGING_WITHIN_TOLERANCE
        );
        assert_eq!(
            Outcome::Lagging { drift_seq: 5 }.metric_label(),
            metrics::GUARDIAN_RECONCILER_OUTCOME_LAGGING
        );
        assert_eq!(
            Outcome::Ahead { drift_seq: 5 }.metric_label(),
            metrics::GUARDIAN_RECONCILER_OUTCOME_AHEAD
        );
    }
}
