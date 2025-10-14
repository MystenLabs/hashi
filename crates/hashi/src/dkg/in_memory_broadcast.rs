//! In-memory broadcast channel implementations for DKG message passing

use crate::dkg::interfaces::{OrderedBroadcastChannel, P2PChannel};
use crate::dkg::types::{DkgResult, OrderedBroadcastMessage, P2PMessage, ValidatorAddress};
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;

const RECEIVE_POLL_INTERVAL_MS: u64 = 10;

type P2PMessageQueue = Arc<Mutex<VecDeque<P2PMessage>>>;
type SharedP2PQueues = Arc<RwLock<HashMap<ValidatorAddress, P2PMessageQueue>>>;
type OrderedMessageQueue = Arc<Mutex<VecDeque<OrderedBroadcastMessage>>>;

fn get_pending_count<T>(queue: &Arc<Mutex<VecDeque<T>>>) -> Option<usize> {
    queue.try_lock().ok().map(|q| q.len())
}

async fn try_receive_with_timeout<T, F, Fut>(
    duration: Duration,
    receive_fn: F,
) -> DkgResult<Option<T>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = DkgResult<T>>,
{
    match timeout(duration, receive_fn()).await {
        Ok(Ok(msg)) => Ok(Some(msg)),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(None),
    }
}

/// In-memory P2P channel for testing
///
/// This implementation simulates direct validator-to-validator messaging.
/// Messages are stored in per-validator queues without ordering guarantees.
#[derive(Clone)]
pub struct InMemoryP2PChannel {
    validator_address: ValidatorAddress,
    message_queues: SharedP2PQueues,
    my_queue: P2PMessageQueue,
}

/// In-memory ordered broadcast channel for testing
///
/// This implementation simulates consensus-ordered broadcast where all validators
/// see messages in the same order.
#[derive(Clone)]
pub struct InMemoryOrderedBroadcastChannel {
    shared_queue: OrderedMessageQueue,
    read_position: Arc<Mutex<usize>>,
}

impl InMemoryP2PChannel {
    pub fn new_network(validator_addresses: Vec<ValidatorAddress>) -> HashMap<ValidatorAddress, Self> {
        let mut queues = HashMap::new();
        for addr in &validator_addresses {
            queues.insert(addr.clone(), Arc::new(Mutex::new(VecDeque::new())));
        }
        let message_queues = Arc::new(RwLock::new(queues.clone()));
        let mut channels = HashMap::new();
        for addr in validator_addresses {
            let my_queue = queues.get(&addr).unwrap().clone();
            channels.insert(
                addr.clone(),
                Self {
                    validator_address: addr.clone(),
                    message_queues: message_queues.clone(),
                    my_queue,
                },
            );
        }
        channels
    }

    pub async fn new(validator_address: ValidatorAddress, message_queues: SharedP2PQueues) -> Self {
        let my_queue = {
            let queues = message_queues.read().await;
            queues.get(&validator_address).cloned()
        }
        .unwrap_or_else(|| Arc::new(Mutex::new(VecDeque::new())));
        {
            let mut queues = message_queues.write().await;
            queues
                .entry(validator_address.clone())
                .or_insert_with(|| my_queue.clone());
        }
        Self {
            validator_address,
            message_queues,
            my_queue,
        }
    }
}

#[async_trait]
impl P2PChannel for InMemoryP2PChannel {
    async fn send_to(&self, recipient: &ValidatorAddress, message: P2PMessage) -> DkgResult<()> {
        let queues = self.message_queues.read().await;
        if let Some(queue) = queues.get(recipient) {
            let mut q = queue.lock().await;
            q.push_back(message);
        }
        Ok(())
    }

    async fn broadcast(&self, message: P2PMessage) -> DkgResult<()> {
        let queues = self.message_queues.read().await;
        for (addr, queue) in queues.iter() {
            if *addr != self.validator_address {
                let mut q = queue.lock().await;
                q.push_back(message.clone());
            }
        }
        Ok(())
    }

    async fn receive(&mut self) -> DkgResult<P2PMessage> {
        loop {
            let mut queue = self.my_queue.lock().await;
            if let Some(msg) = queue.pop_front() {
                return Ok(msg);
            }
            drop(queue);
            // Sleep briefly to avoid busy-waiting
            tokio::time::sleep(Duration::from_millis(RECEIVE_POLL_INTERVAL_MS)).await;
        }
    }

    async fn try_receive_timeout(&mut self, duration: Duration) -> DkgResult<Option<P2PMessage>> {
        try_receive_with_timeout(duration, || self.receive()).await
    }

    fn pending_messages(&self) -> Option<usize> {
        get_pending_count(&self.my_queue)
    }
}

impl InMemoryOrderedBroadcastChannel {
    pub fn new_network(validator_addresses: Vec<ValidatorAddress>) -> HashMap<ValidatorAddress, Self> {
        let shared_queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut channels = HashMap::new();
        for addr in validator_addresses {
            channels.insert(
                addr.clone(),
                Self {
                    shared_queue: shared_queue.clone(),
                    read_position: Arc::new(Mutex::new(0)),
                },
            );
        }
        channels
    }
}

#[async_trait]
impl OrderedBroadcastChannel for InMemoryOrderedBroadcastChannel {
    async fn broadcast(&self, message: OrderedBroadcastMessage) -> DkgResult<()> {
        // In a real implementation, this would go through consensus to establish ordering
        // For testing, we simulate ordering by adding to a single shared queue
        let mut queue = self.shared_queue.lock().await;
        queue.push_back(message);
        Ok(())
    }

    async fn receive(&mut self) -> DkgResult<OrderedBroadcastMessage> {
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

    async fn try_receive_timeout(
        &mut self,
        duration: Duration,
    ) -> DkgResult<Option<OrderedBroadcastMessage>> {
        try_receive_with_timeout(duration, || self.receive()).await
    }

    fn pending_messages(&self) -> Option<usize> {
        let queue = self.shared_queue.try_lock().ok()?;
        let pos = self.read_position.try_lock().ok()?;
        Some(queue.len().saturating_sub(*pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::types::{
        DkgCertificate, MessageApproval, ProtocolType, SessionContext,
    };

    fn create_validator_addresses(count: usize) -> Vec<ValidatorAddress> {
        (1..=count).map(|i| ValidatorAddress([i as u8; 32])).collect()
    }

    fn create_approval_message(approver: &ValidatorAddress, hash_byte: u8) -> P2PMessage {
        P2PMessage::ApprovalV1(MessageApproval {
            message_hash: [hash_byte; 32],
            approver: approver.clone(),
            signature: vec![hash_byte, hash_byte + 1, hash_byte + 2],
            timestamp: 100 + hash_byte as u64,
        })
    }

    fn create_test_certificate(dealer: &ValidatorAddress, hash_byte: u8) -> DkgCertificate {
        DkgCertificate {
            dealer: dealer.clone(),
            message_hash: [hash_byte; 32],
            data_availability_signatures: vec![],
            dkg_signatures: vec![],
            session_context: SessionContext::new(42, ProtocolType::DkgKeyGeneration, "testnet".to_string()),
        }
    }

    #[tokio::test]
    async fn test_p2p_broadcast() {
        let validator_addresses = create_validator_addresses(3);
        let mut channels = InMemoryP2PChannel::new_network(validator_addresses.clone());

        // Validator 1 broadcasts a P2P message
        let msg = create_approval_message(&validator_addresses[0], 0);

        channels
            .get(&validator_addresses[0])
            .unwrap()
            .broadcast(msg.clone())
            .await
            .unwrap();

        // Validators 2 and 3 should receive it
        for addr in &validator_addresses[1..] {
            let channel = channels.get_mut(addr).unwrap();
            let received_msg = channel.receive().await.unwrap();
            match received_msg {
                P2PMessage::ApprovalV1(approval) => {
                    assert_eq!(approval.approver, validator_addresses[0]);
                }
                _ => panic!("Wrong message type"),
            }
        }
    }

    #[tokio::test]
    async fn test_p2p_send_to() {
        let validator_addresses = create_validator_addresses(2);
        let channels = InMemoryP2PChannel::new_network(validator_addresses.clone());

        // Validator 1 sends a message to Validator 2
        let msg = P2PMessage::ApprovalV1(MessageApproval {
            message_hash: [42; 32],
            approver: validator_addresses[0].clone(),
            signature: vec![1, 2, 3],
            timestamp: 100,
        });

        channels
            .get(&validator_addresses[0])
            .unwrap()
            .send_to(&validator_addresses[1], msg.clone())
            .await
            .unwrap();

        // Only Validator 2 should receive it
        let channel2 = channels.get(&validator_addresses[1]).unwrap();
        assert_eq!(channel2.pending_messages(), Some(1));
    }

    #[tokio::test]
    async fn test_p2p_timeout_receive_no_message() {
        let validator_addresses = vec![ValidatorAddress([1; 32])];
        let mut channels = InMemoryP2PChannel::new_network(validator_addresses.clone());
        let channel = channels.get_mut(&validator_addresses[0]).unwrap();
        let result = channel
            .try_receive_timeout(Duration::from_millis(100))
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_p2p_timeout_receive_with_message() {
        let validator_addresses = create_validator_addresses(2);
        let mut channels = InMemoryP2PChannel::new_network(validator_addresses.clone());
        let msg = create_approval_message(&validator_addresses[0], 42);
        channels
            .get(&validator_addresses[0])
            .unwrap()
            .send_to(&validator_addresses[1], msg.clone())
            .await
            .unwrap();

        // Should receive immediately without waiting for full timeout
        let start = std::time::Instant::now();
        let result = channels
            .get_mut(&validator_addresses[1])
            .unwrap()
            .try_receive_timeout(Duration::from_millis(1000))
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert!(result.is_some());
        assert!(elapsed < Duration::from_millis(100)); // Should be much faster than timeout
        if let Some(P2PMessage::ApprovalV1(approval)) = result {
            assert_eq!(approval.message_hash[0], 42);
        }
    }

    #[tokio::test]
    async fn test_p2p_timeout_receive_delayed_message() {
        let validator_addresses = create_validator_addresses(2);
        let channels = Arc::new(InMemoryP2PChannel::new_network(validator_addresses.clone()));
        let channels_clone = channels.clone();
        let validator_addresses_clone = validator_addresses.clone();

        // Spawn a task to send a message after a delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let msg = create_approval_message(&validator_addresses_clone[0], 99);
            channels_clone
                .get(&validator_addresses_clone[0])
                .unwrap()
                .send_to(&validator_addresses_clone[1], msg)
                .await
                .unwrap();
        });

        // Should receive the message when it arrives (before timeout)
        let start = std::time::Instant::now();
        let mut receiver = channels.get(&validator_addresses[1]).unwrap().clone();

        let result = receiver
            .try_receive_timeout(Duration::from_millis(200))
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert!(result.is_some());
        assert!(elapsed >= Duration::from_millis(50)); // Message sent after 50ms
        assert!(elapsed < Duration::from_millis(150)); // But received before timeout
        if let Some(P2PMessage::ApprovalV1(approval)) = result {
            assert_eq!(approval.message_hash[0], 99);
        }
    }

    #[tokio::test]
    async fn test_p2p_pending_messages() {
        let validator_addresses = create_validator_addresses(2);
        let channels = InMemoryP2PChannel::new_network(validator_addresses.clone());
        const MESSAGE_COUNT: usize = 3;

        assert_eq!(
            channels.get(&validator_addresses[1]).unwrap().pending_messages(),
            Some(0)
        );

        for i in 0..MESSAGE_COUNT {
            let msg = create_approval_message(&validator_addresses[0], i as u8);
            channels
                .get(&validator_addresses[0])
                .unwrap()
                .broadcast(msg)
                .await
                .unwrap();
        }

        tokio::time::sleep(Duration::from_millis(50)).await; // Let messages propagate
        assert_eq!(
            channels.get(&validator_addresses[1]).unwrap().pending_messages(),
            Some(MESSAGE_COUNT)
        );
    }

    #[tokio::test]
    async fn test_p2p_new_single_validator() {
        let message_queues = Arc::new(RwLock::new(HashMap::new()));
        let validator1 = ValidatorAddress([1; 32]);
        let validator2 = ValidatorAddress([2; 32]);
        let channel1 = InMemoryP2PChannel::new(validator1.clone(), message_queues.clone()).await;
        let mut channel2 =
            InMemoryP2PChannel::new(validator2.clone(), message_queues.clone()).await;

        // Validator 1 broadcasts a message
        let message_hash = [42; 32];
        let msg = P2PMessage::ApprovalV1(MessageApproval {
            message_hash,
            approver: validator1.clone(),
            signature: vec![1, 2, 3],
            timestamp: 100,
        });

        channel1.broadcast(msg.clone()).await.unwrap();

        // Validator 2 should receive it
        let received_msg = channel2.receive().await.unwrap();
        match received_msg {
            P2PMessage::ApprovalV1(approval) => {
                assert_eq!(approval.message_hash, message_hash);
                assert_eq!(approval.approver, validator1);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[tokio::test]
    async fn test_p2p_approval_message() {
        // Test Approval message type specifically since it's simpler
        let validator_addresses = create_validator_addresses(2);
        let mut channels = InMemoryP2PChannel::new_network(validator_addresses.clone());
        for i in 0..3 {
            let msg = create_approval_message(&validator_addresses[0], i);
            channels
                .get(&validator_addresses[0])
                .unwrap()
                .send_to(&validator_addresses[1], msg)
                .await
                .unwrap();
        }

        for i in 0..3 {
            let received = channels
                .get_mut(&validator_addresses[1])
                .unwrap()
                .receive()
                .await
                .unwrap();
            match received {
                P2PMessage::ApprovalV1(approval) => {
                    assert_eq!(approval.message_hash[0], i);
                    assert_eq!(approval.approver, validator_addresses[0]);
                    assert_eq!(approval.timestamp, 100 + i as u64);
                }
                _ => panic!("Wrong message type"),
            }
        }
    }

    #[tokio::test]
    async fn test_p2p_no_self_broadcast() {
        let validator_addresses = create_validator_addresses(2);
        let channels = InMemoryP2PChannel::new_network(validator_addresses.clone());
        let msg = create_approval_message(&validator_addresses[0], 0);
        channels
            .get(&validator_addresses[0])
            .unwrap()
            .broadcast(msg)
            .await
            .unwrap();

        // Validator 1 should not receive its own broadcast
        assert_eq!(
            channels.get(&validator_addresses[0]).unwrap().pending_messages(),
            Some(0)
        );
        // Validator 2 should receive it
        assert_eq!(
            channels.get(&validator_addresses[1]).unwrap().pending_messages(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_ordered_broadcast_all_receive() {
        let validator_addresses = create_validator_addresses(3);
        let channels = InMemoryOrderedBroadcastChannel::new_network(validator_addresses.clone());
        let cert = create_test_certificate(&validator_addresses[0], 0);
        let msg = OrderedBroadcastMessage::CertificateV1(cert);
        channels
            .get(&validator_addresses[0])
            .unwrap()
            .broadcast(msg.clone())
            .await
            .unwrap();

        for addr in &validator_addresses {
            assert_eq!(channels.get(addr).unwrap().pending_messages(), Some(1));
        }
    }

    #[tokio::test]
    async fn test_ordered_broadcast_ordering() {
        const NUM_VALIDATORS: usize = 3;
        let validator_addresses = create_validator_addresses(NUM_VALIDATORS);
        let mut channels = InMemoryOrderedBroadcastChannel::new_network(validator_addresses.clone());
        for (i, sender_addr) in validator_addresses.iter().enumerate() {
            let cert = create_test_certificate(sender_addr, i as u8);
            channels
                .get(sender_addr)
                .unwrap()
                .broadcast(OrderedBroadcastMessage::CertificateV1(cert))
                .await
                .unwrap();
        }

        let mut received_order = vec![];
        for _ in 0..NUM_VALIDATORS {
            let msg = channels
                .get_mut(&validator_addresses[0])
                .unwrap()
                .receive()
                .await
                .unwrap();
            if let OrderedBroadcastMessage::CertificateV1(cert) = msg {
                received_order.push(cert.message_hash[0]);
            }
        }

        // Check that all other validators receive in the same order
        for validator_addr in &validator_addresses[1..] {
            for expected_hash in &received_order {
                let msg = channels
                    .get_mut(validator_addr)
                    .unwrap()
                    .receive()
                    .await
                    .unwrap();
                if let OrderedBroadcastMessage::CertificateV1(cert) = msg {
                    assert_eq!(cert.message_hash[0], *expected_hash);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_ordered_broadcast_presignature() {
        let validator_addresses = create_validator_addresses(2);
        let mut channels = InMemoryOrderedBroadcastChannel::new_network(validator_addresses.clone());
        let msg = OrderedBroadcastMessage::PresignatureV1 {
            sender: validator_addresses[0].clone(),
            session_context: crate::dkg::types::SessionContext::new(
                42,
                crate::dkg::types::ProtocolType::NonceGeneration(1),
                "testnet".to_string(),
            ),
            data: vec![1, 2, 3, 4],
        };
        channels
            .get(&validator_addresses[0])
            .unwrap()
            .broadcast(msg.clone())
            .await
            .unwrap();

        // Both validators should receive it
        for addr in &validator_addresses {
            let channel = channels.get_mut(addr).unwrap();
            let received = channel.receive().await.unwrap();
            match received {
                OrderedBroadcastMessage::PresignatureV1 { sender, data, .. } => {
                    assert_eq!(sender, validator_addresses[0]);
                    assert_eq!(data, vec![1, 2, 3, 4]);
                }
                _ => panic!("Wrong message type"),
            }
        }
    }

    #[tokio::test]
    async fn test_p2p_send_to_nonexistent() {
        let validator_addresses = vec![ValidatorAddress([1; 32])];
        let channels = InMemoryP2PChannel::new_network(validator_addresses.clone());
        let nonexistent = ValidatorAddress([99; 32]);
        let msg = create_approval_message(&validator_addresses[0], 0);

        // Should not panic, just silently not deliver
        channels
            .get(&validator_addresses[0])
            .unwrap()
            .send_to(&nonexistent, msg)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_multiple_messages_fifo() {
        const NUM_MESSAGES: u8 = 5;
        let validator_addresses = create_validator_addresses(2);
        let mut channels = InMemoryP2PChannel::new_network(validator_addresses.clone());
        // Send multiple messages
        for i in 0..NUM_MESSAGES {
            let msg = create_approval_message(&validator_addresses[0], i);
            channels
                .get(&validator_addresses[0])
                .unwrap()
                .send_to(&validator_addresses[1], msg)
                .await
                .unwrap();
        }

        // Receive and verify order
        for i in 0..NUM_MESSAGES {
            let received = channels
                .get_mut(&validator_addresses[1])
                .unwrap()
                .receive()
                .await
                .unwrap();
            if let P2PMessage::ApprovalV1(approval) = received {
                assert_eq!(approval.message_hash[0], i);
                assert_eq!(approval.timestamp, 100 + i as u64);
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_broadcasts() {
        let validator_addresses = create_validator_addresses(3);
        let channels = Arc::new(InMemoryP2PChannel::new_network(validator_addresses.clone()));
        let mut handles = vec![];
        for (i, sender_addr) in validator_addresses.iter().enumerate() {
            let channels_clone = channels.clone();
            let sender = sender_addr.clone();
            let handle = tokio::spawn(async move {
                let msg = create_approval_message(&sender, i as u8);
                channels_clone.get(&sender).unwrap().broadcast(msg).await
            });
            handles.push(handle);
        }
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Each validator should have received messages from the other two
        for addr in &validator_addresses {
            assert_eq!(channels.get(addr).unwrap().pending_messages(), Some(2));
        }
    }
}
