// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::metrics::Metrics;
use sui_futures::service::Service;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NetworkSample {
    rx_bytes: u64,
    tx_bytes: u64,
}

impl NetworkSample {
    fn delta_since(self, previous: Self) -> Self {
        Self {
            rx_bytes: self.rx_bytes.saturating_sub(previous.rx_bytes),
            tx_bytes: self.tx_bytes.saturating_sub(previous.tx_bytes),
        }
    }
}

pub fn start(metrics: Arc<Metrics>) -> Service {
    Service::new().spawn_aborting(async move {
        tracing::debug!(interval = ?SAMPLE_INTERVAL, "started hashi network metrics sampler");

        let mut networks = sysinfo::Networks::new_with_refreshed_list();
        let mut previous: Option<NetworkSample> = None;
        let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            networks.refresh(true);

            let current = sample_networks(&networks);
            if let Some(previous) = previous {
                let delta = current.delta_since(previous);
                metrics.network_rx_bytes_total.inc_by(delta.rx_bytes);
                metrics.network_tx_bytes_total.inc_by(delta.tx_bytes);
            }
            previous = Some(current);
        }
    })
}

fn sample_networks(networks: &sysinfo::Networks) -> NetworkSample {
    aggregate_sample(networks.iter().map(|(name, data)| {
        (
            name.as_str(),
            data.total_received(),
            data.total_transmitted(),
        )
    }))
}

fn aggregate_sample<I, N>(interfaces: I) -> NetworkSample
where
    I: IntoIterator<Item = (N, u64, u64)>,
    N: AsRef<str>,
{
    interfaces
        .into_iter()
        .filter(|(name, _, _)| !is_loopback_interface(name.as_ref()))
        .fold(
            NetworkSample::default(),
            |mut total, (_, rx_bytes, tx_bytes)| {
                total.rx_bytes = total.rx_bytes.saturating_add(rx_bytes);
                total.tx_bytes = total.tx_bytes.saturating_add(tx_bytes);
                total
            },
        )
}

fn is_loopback_interface(name: &str) -> bool {
    name == "lo"
        || name.starts_with("lo:")
        || name
            .strip_prefix("lo")
            .is_some_and(|suffix| suffix.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_sample_excludes_loopback_interfaces() {
        let sample = aggregate_sample([
            ("lo", 1_000, 2_000),
            ("lo0", 4_000, 8_000),
            ("eth0", 10, 20),
            ("wlan0", 30, 40),
        ]);

        assert_eq!(
            sample,
            NetworkSample {
                rx_bytes: 40,
                tx_bytes: 60,
            }
        );
    }

    #[test]
    fn aggregate_sample_saturates_on_overflow() {
        let sample = aggregate_sample([("eth0", u64::MAX, u64::MAX), ("wlan0", 1, 1)]);

        assert_eq!(
            sample,
            NetworkSample {
                rx_bytes: u64::MAX,
                tx_bytes: u64::MAX,
            }
        );
    }

    #[test]
    fn delta_since_skips_counter_resets() {
        let previous = NetworkSample {
            rx_bytes: 1_000,
            tx_bytes: 2_000,
        };
        let current = NetworkSample {
            rx_bytes: 900,
            tx_bytes: 2_050,
        };

        assert_eq!(
            current.delta_since(previous),
            NetworkSample {
                rx_bytes: 0,
                tx_bytes: 50,
            }
        );
    }
}
