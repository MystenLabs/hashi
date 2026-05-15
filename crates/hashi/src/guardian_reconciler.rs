// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Periodic read-only check that the local limiter agrees with the
//! guardian's `LimiterState`. Watcher gap-fill is the recovery path;
//! this module only emits metrics + logs.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Healthy,
    LaggingWithinTolerance { drift_seq: u64 },
    Lagging { drift_seq: u64 },
    Ahead { drift_seq: u64 },
}

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

pub fn start_reconciler(hashi: Arc<Hashi>) -> Service {
    let interval_dur = hashi.config.guardian_reconciliation_interval();
    let drift_alert_after = hashi.config.guardian_reconciliation_drift_alert();
    let tolerance_seq = hashi.config.guardian_reconciliation_tolerance_seq();

    Service::new().spawn_aborting(async move {
        if hashi.guardian_client().is_none() {
            return Ok(());
        }
        let limiter = wait_for_local_limiter(&hashi, interval_dur).await;

        let mut tick = interval(interval_dur);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Skip the immediate-fire first tick — bootstrap already
        // covered that observation.
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

    let started = Instant::now();
    let info_pb = match client.get_guardian_info().await {
        Ok(info) => {
            metrics.record_guardian_rpc(
                metrics::GUARDIAN_RPC_METHOD_GET_GUARDIAN_INFO,
                metrics::GUARDIAN_RPC_OUTCOME_OK,
                started.elapsed().as_secs_f64(),
            );
            info
        }
        Err(e) => {
            metrics.record_guardian_rpc(
                metrics::GUARDIAN_RPC_METHOD_GET_GUARDIAN_INFO,
                metrics::GUARDIAN_RPC_OUTCOME_UNAVAILABLE,
                started.elapsed().as_secs_f64(),
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
            tracing::warn!("guardian reconciler: parse failed: {e:?}");
            return;
        }
    };
    let Some(guardian_state) = info.limiter_state else {
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
        Outcome::Healthy | Outcome::LaggingWithinTolerance { .. } => {
            *first_drift_seen_at = None;
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
                    "guardian reconciler: lag past tolerance not closing"
                );
            } else {
                tracing::warn!(
                    drift_seq,
                    local_seq = local_state.next_seq,
                    guardian_seq = guardian_state.next_seq,
                    "guardian reconciler: lag observed"
                );
            }
        }
        Outcome::Ahead { drift_seq } => {
            // Impossible during normal operation: the guardian advances
            // before the chain. Flip the sticky bit on first sight.
            metrics.guardian_limiter_drifted.set(1);
            tracing::error!(
                drift_seq,
                local_seq = local_state.next_seq,
                guardian_seq = guardian_state.next_seq,
                "guardian reconciler: local ahead of guardian (bug or rollback)"
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
    fn classify_branches() {
        assert_eq!(classify(&st(7), &st(7), 2), Outcome::Healthy);
        assert_eq!(
            classify(&st(7), &st(9), 2),
            Outcome::LaggingWithinTolerance { drift_seq: 2 },
        );
        assert_eq!(
            classify(&st(7), &st(10), 2),
            Outcome::Lagging { drift_seq: 3 },
        );
        assert_eq!(
            classify(&st(0), &st(5_000), 2),
            Outcome::Lagging { drift_seq: 5_000 },
        );
        assert_eq!(
            classify(&st(10), &st(7), 2),
            Outcome::Ahead { drift_seq: 3 },
        );
        assert_eq!(classify(&st(7), &st(7), 0), Outcome::Healthy);
        assert_eq!(
            classify(&st(7), &st(8), 0),
            Outcome::Lagging { drift_seq: 1 },
        );
    }

    #[test]
    fn metric_labels_match_constants() {
        assert_eq!(
            Outcome::Healthy.metric_label(),
            metrics::GUARDIAN_RECONCILER_OUTCOME_HEALTHY,
        );
        assert_eq!(
            Outcome::LaggingWithinTolerance { drift_seq: 1 }.metric_label(),
            metrics::GUARDIAN_RECONCILER_OUTCOME_LAGGING_WITHIN_TOLERANCE,
        );
        assert_eq!(
            Outcome::Lagging { drift_seq: 5 }.metric_label(),
            metrics::GUARDIAN_RECONCILER_OUTCOME_LAGGING,
        );
        assert_eq!(
            Outcome::Ahead { drift_seq: 5 }.metric_label(),
            metrics::GUARDIAN_RECONCILER_OUTCOME_AHEAD,
        );
    }
}
