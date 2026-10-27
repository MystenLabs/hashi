// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use prometheus::IntCounter;
use prometheus::IntGauge;
use sui_sdk_types::Address;
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::Semaphore;

use crate::metrics::Metrics;

const PLACES: usize = 192;
const CALLS: usize = 16;
const DISCOVERIES: usize = 64;
const FETCH_SLOTS: usize = 1;

#[derive(Debug, thiserror::Error)]
#[error("per-caller Bitcoin monitor queue is full")]
pub struct BitcoindBusy;

#[derive(Clone)]
pub(crate) struct BitcoindLimiter {
    callers: Arc<Mutex<HashMap<Address, Arc<CallerLimits>>>>,
    metrics: Arc<Metrics>,
}

struct CallerLimits {
    caller: Address,
    places: Arc<Semaphore>,
    calls: Arc<Semaphore>,
    discoveries: Arc<Semaphore>,
    fetch_slots: Arc<Semaphore>,
    places_in_use: IntGauge,
    calls_in_use: IntGauge,
    discoveries_in_use: IntGauge,
    shed: IntCounter,
    discoveries_refused: IntCounter,
}

impl BitcoindLimiter {
    pub(crate) fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            callers: Default::default(),
            metrics,
        }
    }

    pub(crate) fn gate(&self, caller: Address, deadline: tokio::time::Instant) -> BitcoindGate {
        let limits = self
            .callers
            .lock()
            .unwrap()
            .entry(caller)
            .or_insert_with(|| {
                let label = caller.to_string();
                let metrics = &self.metrics;
                Arc::new(CallerLimits {
                    caller,
                    places: Arc::new(Semaphore::new(PLACES)),
                    calls: Arc::new(Semaphore::new(CALLS)),
                    discoveries: Arc::new(Semaphore::new(DISCOVERIES)),
                    fetch_slots: Arc::new(Semaphore::new(FETCH_SLOTS)),
                    places_in_use: metrics
                        .peer_bitcoind_places_in_use
                        .with_label_values(&[&label]),
                    calls_in_use: metrics
                        .peer_bitcoind_calls_in_use
                        .with_label_values(&[&label]),
                    discoveries_in_use: metrics
                        .peer_bitcoind_discoveries_in_use
                        .with_label_values(&[&label]),
                    shed: metrics
                        .peer_bitcoind_requests_shed_total
                        .with_label_values(&[&label]),
                    discoveries_refused: metrics
                        .peer_bitcoind_discoveries_refused_total
                        .with_label_values(&[&label]),
                })
            })
            .clone();
        BitcoindGate(Some((limits, deadline)))
    }
}

pub struct BitcoindGate(Option<(Arc<CallerLimits>, tokio::time::Instant)>);

impl BitcoindGate {
    pub fn local() -> Self {
        Self(None)
    }

    pub(crate) async fn take_place(&self) -> Result<BitcoindCharge, BitcoindBusy> {
        let Some((limits, deadline)) = &self.0 else {
            return Ok(None);
        };
        let place = tokio::time::timeout_at(*deadline, limits.places.clone().acquire_owned())
            .await
            .map_err(|_| {
                limits.shed.inc();
                BitcoindBusy
            })?
            .expect("bitcoind place semaphores are never closed");
        Ok(Some(Arc::new(CallerCharge {
            limits: limits.clone(),
            _place: Held::new(place, &limits.places_in_use),
        })))
    }
}

pub type BitcoindCharge = Option<Arc<CallerCharge>>;

pub struct CallerCharge {
    limits: Arc<CallerLimits>,
    _place: Held,
}

impl CallerCharge {
    pub(crate) fn caller(&self) -> Address {
        self.limits.caller
    }

    pub(crate) async fn call(&self) -> Held {
        let call = self
            .limits
            .calls
            .clone()
            .acquire_owned()
            .await
            .expect("bitcoind call semaphores are never closed");
        Held::new(call, &self.limits.calls_in_use)
    }

    pub(crate) async fn fetch_slot(&self) -> OwnedSemaphorePermit {
        self.limits
            .fetch_slots
            .clone()
            .acquire_owned()
            .await
            .expect("Kyoto fetch slot semaphores are never closed")
    }

    pub(crate) fn try_discovery(&self) -> Option<Held> {
        match self.limits.discoveries.clone().try_acquire_owned() {
            Ok(discovery) => Some(Held::new(discovery, &self.limits.discoveries_in_use)),
            Err(_) => {
                self.limits.discoveries_refused.inc();
                None
            }
        }
    }
}

impl std::fmt::Debug for CallerCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallerCharge")
            .field("caller", &self.limits.caller)
            .finish()
    }
}

pub(crate) struct Held {
    _permit: OwnedSemaphorePermit,
    in_use: IntGauge,
}

impl Held {
    fn new(permit: OwnedSemaphorePermit, in_use: &IntGauge) -> Self {
        in_use.inc();
        Self {
            _permit: permit,
            in_use: in_use.clone(),
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.in_use.dec();
    }
}
