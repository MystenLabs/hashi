// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! In-memory channel implementations for testing

use crate::communication::interfaces::ChannelResult;
use crate::communication::interfaces::OrderedBroadcastChannel;
use async_trait::async_trait;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use sui_sdk_types::Address;
use tokio::sync::Mutex;

const RECEIVE_POLL_INTERVAL_MS: u64 = 10;
const INITIAL_READ_POSITION: usize = 0;

// TODO: Replacing in-memory implementation with RPC-based loopback testing
type MessageQueue<M> = Arc<Mutex<VecDeque<M>>>;

/// In-memory ordered broadcast channel for testing
///
/// This implementation simulates consensus-ordered broadcast where all validators
/// see messages in the same order.
#[derive(Clone)]
pub struct InMemoryOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    shared_queue: MessageQueue<M>,
    read_position: Arc<Mutex<usize>>,
}

impl<M> InMemoryOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    pub fn new_network(validator_addresses: Vec<Address>) -> HashMap<Address, Self> {
        let shared_queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut channels = HashMap::new();
        for addr in validator_addresses {
            channels.insert(
                addr,
                Self {
                    shared_queue: shared_queue.clone(),
                    read_position: Arc::new(Mutex::new(INITIAL_READ_POSITION)),
                },
            );
        }
        channels
    }
}

#[async_trait]
impl<M> OrderedBroadcastChannel<M> for InMemoryOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    async fn publish(&self, message: M) -> ChannelResult<()> {
        // In a real implementation, this would go through consensus to establish ordering
        // For testing, we simulate ordering by adding to a single shared queue
        let mut queue = self.shared_queue.lock().await;
        queue.push_back(message);
        Ok(())
    }

    async fn receive(&mut self) -> ChannelResult<M> {
        loop {
            let queue = self.shared_queue.lock().await;
            let mut pos = self.read_position.lock().await;
            if *pos < queue.len() {
                let msg = queue[*pos].clone();
                *pos += 1;
                return Ok(msg);
            }
            drop(queue);
            drop(pos);
            // Sleep briefly to avoid busy-waiting
            tokio::time::sleep(Duration::from_millis(RECEIVE_POLL_INTERVAL_MS)).await;
        }
    }

    async fn certified_dealers(&mut self) -> Vec<Address> {
        vec![]
    }
}

impl<M> InMemoryOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    pub fn pending_messages(&self) -> Option<usize> {
        let queue = self.shared_queue.try_lock().ok()?;
        let pos = self.read_position.try_lock().ok()?;
        Some(queue.len().saturating_sub(*pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    struct TestMessage {
        id: u32,
        data: String,
    }

    fn create_validator_addresses(count: usize) -> Vec<Address> {
        (1..=count).map(|i| Address::new([i as u8; 32])).collect()
    }

    #[tokio::test]
    async fn test_ordered_broadcast_total_order() {
        const NUM_VALIDATORS: usize = 3;
        let validators = create_validator_addresses(NUM_VALIDATORS);
        let mut channels = InMemoryOrderedBroadcastChannel::new_network(validators.clone());

        // Each validator broadcasts messages
        for (i, sender) in validators.iter().enumerate() {
            let msg = TestMessage {
                id: i as u32,
                data: format!("message from {}", i),
            };
            channels.get(sender).unwrap().publish(msg).await.unwrap();
        }

        // All validators should receive messages in the same order
        let mut first_order = vec![];
        for _i in 0..NUM_VALIDATORS {
            let msg = channels
                .get_mut(&validators[0])
                .unwrap()
                .receive()
                .await
                .unwrap();
            first_order.push(msg.id);
        }

        // Check all other validators see the same order
        for validator in &validators[1..] {
            for expected_id in &first_order {
                let msg = channels
                    .get_mut(validator)
                    .unwrap()
                    .receive()
                    .await
                    .unwrap();
                assert_eq!(msg.id, *expected_id);
            }
        }
    }

    #[tokio::test]
    async fn test_ordered_broadcast_pending_messages() {
        let validators = create_validator_addresses(2);
        let channels = InMemoryOrderedBroadcastChannel::new_network(validators.clone());

        let msg = TestMessage {
            id: 1,
            data: "test".to_string(),
        };

        channels
            .get(&validators[0])
            .unwrap()
            .publish(msg)
            .await
            .unwrap();

        // Both validators should see 1 pending message
        for addr in &validators {
            assert_eq!(channels.get(addr).unwrap().pending_messages(), Some(1));
        }
    }
}
