use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;
use sui_sdk_types::Address;
use tracing::error;

pub(crate) trait RetryPolicy {
    fn retry_base_delay_ms(self) -> u64;
    fn max_delay_ms(self) -> u64;
    fn max_retries(self) -> u32;

    fn retry_delay_ms(self, attempt: u32) -> u64
    where
        Self: Copy,
    {
        let exponent = attempt.saturating_sub(1).min(63);
        let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
        self.retry_base_delay_ms()
            .saturating_mul(multiplier)
            .min(self.max_delay_ms())
    }
}

#[derive(Clone)]
pub(super) struct RetryTracker<K> {
    state: Arc<Mutex<HashMap<Address, RetryState<K>>>>,
}

#[derive(Clone, Copy, Debug)]
struct RetryState<K> {
    attempt: u32,
    next_retry_at_ms: u64,
    last_error_kind: K,
}

impl<K> RetryTracker<K>
where
    K: RetryPolicy + Copy + Eq + Debug,
{
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(super) fn prune(&self, active_ids: &[Address]) {
        let active: HashSet<Address> = active_ids.iter().copied().collect();
        self.state
            .lock()
            .unwrap()
            .retain(|request_id, _| active.contains(request_id));
    }

    pub(super) fn should_skip(&self, request_id: &Address, checkpoint_timestamp_ms: u64) -> bool {
        let states = self.state.lock().unwrap();
        match states.get(request_id) {
            Some(state) => {
                state.attempt >= state.last_error_kind.max_retries()
                    || state.next_retry_at_ms > checkpoint_timestamp_ms
            }
            None => false,
        }
    }

    pub(super) fn clear(&self, request_id: &Address) {
        self.state.lock().unwrap().remove(request_id);
    }

    pub(super) fn in_backoff_count(&self, checkpoint_timestamp_ms: u64) -> usize {
        let states = self.state.lock().unwrap();
        states
            .values()
            .filter(|s| {
                s.attempt < s.last_error_kind.max_retries()
                    && s.next_retry_at_ms > checkpoint_timestamp_ms
            })
            .count()
    }

    pub(super) fn record_failure(
        &self,
        error_kind: K,
        request_id: Address,
        checkpoint_timestamp_ms: u64,
    ) {
        let mut states = self.state.lock().unwrap();
        let previous = states.get(&request_id).copied();

        let attempt = match previous {
            Some(state) if state.last_error_kind == error_kind => state.attempt.saturating_add(1),
            _ => 1,
        };
        let next_retry_at_ms = if attempt >= error_kind.max_retries() {
            checkpoint_timestamp_ms
        } else {
            let delay_ms = error_kind.retry_delay_ms(attempt);
            checkpoint_timestamp_ms.saturating_add(delay_ms)
        };
        let state = RetryState {
            attempt,
            next_retry_at_ms,
            last_error_kind: error_kind,
        };
        states.insert(request_id, state);

        if state.attempt >= error_kind.max_retries() {
            error!(
                "Request {:?} failed validation ({error_kind:?}). Reached max retries ({}), no further retries",
                request_id, state.attempt,
            );
        } else {
            let retry_delay_ms = state
                .next_retry_at_ms
                .saturating_sub(checkpoint_timestamp_ms);
            error!(
                "Request {:?} failed validation ({error_kind:?}). Next retry in {} ms (attempt {})",
                request_id, retry_delay_ms, state.attempt,
            );
        }
    }
}
