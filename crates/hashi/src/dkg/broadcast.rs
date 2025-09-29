//! Broadcast channel implementations for DKG message passing

use crate::dkg::interfaces::BroadcastChannel;
use crate::dkg::types::{DkgMessage, DkgResult, ValidatorId};
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;

const RECEIVE_POLL_INTERVAL_MS: u64 = 10;

type MessageQueue = Arc<Mutex<VecDeque<DkgMessage>>>;
type SharedMessageQueues = Arc<RwLock<HashMap<ValidatorId, MessageQueue>>>;

/// In-memory broadcast channel for testing
///
/// This implementation simulates a network where all validators can broadcast
/// messages to each other. Messages are stored in per-validator queues.
pub struct InMemoryBroadcastChannel {
    validator_id: ValidatorId,
    message_queues: SharedMessageQueues,
    my_queue: MessageQueue,
}

impl InMemoryBroadcastChannel {
    pub fn new_network(validator_ids: Vec<ValidatorId>) -> HashMap<ValidatorId, Self> {
        let mut queues = HashMap::new();
        for id in &validator_ids {
            queues.insert(id.clone(), Self::create_queue());
        }
        let message_queues = Arc::new(RwLock::new(queues.clone()));
        let mut channels = HashMap::new();
        for id in validator_ids {
            let my_queue = queues.get(&id).unwrap().clone();
            channels.insert(
                id.clone(),
                Self {
                    validator_id: id.clone(),
                    message_queues: message_queues.clone(),
                    my_queue,
                },
            );
        }
        channels
    }

    pub async fn new(validator_id: ValidatorId, message_queues: SharedMessageQueues) -> Self {
        let my_queue = {
            let queues = message_queues.read().await;
            queues.get(&validator_id).cloned()
        }
        .unwrap_or_else(Self::create_queue);
        {
            let mut queues = message_queues.write().await;
            queues
                .entry(validator_id.clone())
                .or_insert_with(|| my_queue.clone());
        }
        Self {
            validator_id,
            message_queues,
            my_queue,
        }
    }

    fn create_queue() -> MessageQueue {
        Arc::new(Mutex::new(VecDeque::new()))
    }
}

#[async_trait]
impl BroadcastChannel for InMemoryBroadcastChannel {
    async fn broadcast(&self, message: DkgMessage) -> DkgResult<()> {
        let queues = self.message_queues.read().await;
        for (id, queue) in queues.iter() {
            if *id != self.validator_id {
                let mut q = queue.lock().await;
                q.push_back(message.clone());
            }
        }
        Ok(())
    }

    async fn receive(&mut self) -> DkgResult<(ValidatorId, DkgMessage)> {
        loop {
            let mut queue = self.my_queue.lock().await;
            if let Some(msg) = queue.pop_front() {
                return Ok((msg.sender().clone(), msg));
            }
            drop(queue);
            // Sleep briefly to avoid busy-waiting
            tokio::time::sleep(Duration::from_millis(RECEIVE_POLL_INTERVAL_MS)).await;
        }
    }

    async fn try_receive_timeout(
        &mut self,
        duration: Duration,
    ) -> DkgResult<Option<(ValidatorId, DkgMessage)>> {
        match timeout(duration, self.receive()).await {
            Ok(Ok(msg)) => Ok(Some(msg)),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(None),
        }
    }

    // We can provide this information since it is in-memory
    fn pending_messages(&self) -> Option<usize> {
        if let Ok(queue) = self.my_queue.try_lock() {
            Some(queue.len())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::types::MessageApproval;

    #[tokio::test]
    async fn test_in_memory_broadcast() {
        let validator_ids = vec![
            ValidatorId([1; 32]),
            ValidatorId([2; 32]),
            ValidatorId([3; 32]),
        ];
        let mut channels = InMemoryBroadcastChannel::new_network(validator_ids.clone());

        // Validator 1 broadcasts a message
        let msg = DkgMessage::Approval(MessageApproval {
            message_hash: [0; 32],
            approver: validator_ids[0].clone(),
            signature: vec![1, 2, 3],
            timestamp: 100,
        });

        channels
            .get(&validator_ids[0])
            .unwrap()
            .broadcast(msg.clone())
            .await
            .unwrap();

        // Validators 2 and 3 should receive it
        for id in &validator_ids[1..] {
            let channel = channels.get_mut(id).unwrap();
            let (sender, received_msg) = channel.receive().await.unwrap();
            assert_eq!(sender, validator_ids[0]);
            match received_msg {
                DkgMessage::Approval(approval) => {
                    assert_eq!(approval.approver, validator_ids[0]);
                }
                _ => panic!("Wrong message type"),
            }
        }
    }

    #[tokio::test]
    async fn test_timeout_receive() {
        let validator_ids = vec![ValidatorId([1; 32])];
        let mut channels = InMemoryBroadcastChannel::new_network(validator_ids.clone());
        let channel = channels.get_mut(&validator_ids[0]).unwrap();
        let result = channel
            .try_receive_timeout(Duration::from_millis(100))
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_pending_messages() {
        let validator_ids = vec![ValidatorId([1; 32]), ValidatorId([2; 32])];
        let channels = InMemoryBroadcastChannel::new_network(validator_ids.clone());

        // Initially no pending messages
        assert_eq!(
            channels.get(&validator_ids[1]).unwrap().pending_messages(),
            Some(0)
        );

        // Broadcast 3 messages
        for i in 0..3 {
            let msg = DkgMessage::Approval(MessageApproval {
                message_hash: [i; 32],
                approver: validator_ids[0].clone(),
                signature: vec![i],
                timestamp: i as u64,
            });
            channels
                .get(&validator_ids[0])
                .unwrap()
                .broadcast(msg)
                .await
                .unwrap();
        }

        // Should have 3 pending messages
        tokio::time::sleep(Duration::from_millis(50)).await; // Let messages propagate
        assert_eq!(
            channels.get(&validator_ids[1]).unwrap().pending_messages(),
            Some(3)
        );
    }

    #[tokio::test]
    async fn test_new_single_validator() {
        let message_queues = Arc::new(RwLock::new(HashMap::new()));
        let validator1 = ValidatorId([1; 32]);
        let validator2 = ValidatorId([2; 32]);
        let channel1 =
            InMemoryBroadcastChannel::new(validator1.clone(), message_queues.clone()).await;
        let mut channel2 =
            InMemoryBroadcastChannel::new(validator2.clone(), message_queues.clone()).await;

        // Validator 1 broadcasts a message
        let message_hash = [42; 32];
        let msg = DkgMessage::Approval(MessageApproval {
            message_hash,
            approver: validator1.clone(),
            signature: vec![1, 2, 3],
            timestamp: 100,
        });

        channel1.broadcast(msg.clone()).await.unwrap();

        // Validator 2 should receive it
        let (sender, received_msg) = channel2.receive().await.unwrap();
        assert_eq!(sender, validator1);
        match received_msg {
            DkgMessage::Approval(approval) => {
                assert_eq!(approval.message_hash, message_hash);
                assert_eq!(approval.approver, validator1);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
