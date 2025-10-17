//! In-memory channel implementations for testing

use crate::communication::interfaces::{
    AuthenticatedMessage, ChannelResult, OrderedBroadcastChannel, P2PChannel,
};
use crate::types::ValidatorAddress;
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;

const RECEIVE_POLL_INTERVAL_MS: u64 = 10;
const INITIAL_READ_POSITION: usize = 0;

// TODO: Replacing in-memory implementation with RPC-based loopback testing
type MessageQueue<M> = Arc<Mutex<VecDeque<AuthenticatedMessage<M>>>>;
type SharedP2PQueues<M> = Arc<RwLock<HashMap<ValidatorAddress, MessageQueue<M>>>>;

fn get_pending_count<T>(queue: &MessageQueue<T>) -> Option<usize> {
    queue.try_lock().ok().map(|q| q.len())
}

async fn try_receive_with_timeout<T, F, Fut>(
    duration: Duration,
    receive_fn: F,
) -> ChannelResult<Option<T>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ChannelResult<T>>,
{
    match timeout(duration, receive_fn()).await {
        Ok(Ok(msg)) => Ok(Some(msg)),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(None),
    }
}

/// In-memory P2P channels for testing
///
/// This implementation simulates direct validator-to-validator messaging.
/// Messages are stored in per-validator queues without ordering guarantees.
#[derive(Clone)]
pub struct InMemoryP2PChannels<M>
where
    M: Clone + Send + Sync + 'static,
{
    validator_address: ValidatorAddress,
    message_queues: SharedP2PQueues<M>,
    my_queue: MessageQueue<M>,
}

impl<M> InMemoryP2PChannels<M>
where
    M: Clone + Send + Sync + 'static,
{
    pub fn new(validator_address: ValidatorAddress) -> Self {
        let mut queues = HashMap::new();
        queues.insert(
            validator_address.clone(),
            Arc::new(Mutex::new(VecDeque::new())),
        );
        let message_queues = Arc::new(RwLock::new(queues.clone()));
        let my_queue = queues.get(&validator_address).unwrap().clone();
        Self {
            validator_address,
            message_queues,
            my_queue,
        }
    }

    pub fn new_network(
        validator_addresses: Vec<ValidatorAddress>,
    ) -> HashMap<ValidatorAddress, Self> {
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
}

#[async_trait]
impl<M> P2PChannel<M> for InMemoryP2PChannels<M>
where
    M: Clone + Send + Sync + 'static,
{
    async fn send_to(&self, recipient: &ValidatorAddress, message: M) -> ChannelResult<()> {
        let queues = self.message_queues.read().await;
        if let Some(queue) = queues.get(recipient) {
            let mut q = queue.lock().await;
            q.push_back(AuthenticatedMessage {
                sender: self.validator_address.clone(),
                message,
            });
        }
        Ok(())
    }

    async fn broadcast(&self, message: M) -> ChannelResult<()> {
        let queues = self.message_queues.read().await;
        for (addr, queue) in queues.iter() {
            if *addr != self.validator_address {
                let mut q = queue.lock().await;
                q.push_back(AuthenticatedMessage {
                    sender: self.validator_address.clone(),
                    message: message.clone(),
                });
            }
        }
        Ok(())
    }

    async fn receive(&mut self) -> ChannelResult<AuthenticatedMessage<M>> {
        loop {
            let mut queue = self.my_queue.lock().await;
            if let Some(authenticated_msg) = queue.pop_front() {
                return Ok(authenticated_msg);
            }
            drop(queue);
            // Sleep briefly to avoid busy-waiting
            tokio::time::sleep(Duration::from_millis(RECEIVE_POLL_INTERVAL_MS)).await;
        }
    }

    async fn try_receive_timeout(
        &mut self,
        duration: Duration,
    ) -> ChannelResult<Option<AuthenticatedMessage<M>>> {
        try_receive_with_timeout(duration, || self.receive()).await
    }

    fn pending_messages(&self) -> Option<usize> {
        get_pending_count(&self.my_queue)
    }
}

/// In-memory ordered broadcast channel for testing
///
/// This implementation simulates consensus-ordered broadcast where all validators
/// see messages in the same order.
#[derive(Clone)]
pub struct InMemoryOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    validator_address: ValidatorAddress,
    shared_queue: MessageQueue<M>,
    read_position: Arc<Mutex<usize>>,
}

impl<M> InMemoryOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    pub fn new_network(
        validator_addresses: Vec<ValidatorAddress>,
    ) -> HashMap<ValidatorAddress, Self> {
        let shared_queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut channels = HashMap::new();
        for addr in validator_addresses {
            channels.insert(
                addr.clone(),
                Self {
                    validator_address: addr.clone(),
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
        // For testing, we simulate ordering by adding to a single shared queue with authenticated sender
        let mut queue = self.shared_queue.lock().await;
        queue.push_back(AuthenticatedMessage {
            sender: self.validator_address.clone(),
            message,
        });
        Ok(())
    }

    async fn receive(&mut self) -> ChannelResult<AuthenticatedMessage<M>> {
        loop {
            let queue = self.shared_queue.lock().await;
            let mut pos = self.read_position.lock().await;
            if *pos < queue.len() {
                let authenticated_msg = queue[*pos].clone();
                *pos += 1;
                return Ok(authenticated_msg);
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
    ) -> ChannelResult<Option<AuthenticatedMessage<M>>> {
        try_receive_with_timeout(duration, || self.receive()).await
    }

    fn pending_messages(&self) -> Option<usize> {
        let queue = self.shared_queue.try_lock().ok()?;
        let pos = self.read_position.try_lock().ok()?;
        Some(queue.len().saturating_sub(*pos))
    }
}

type HookFn<M> = Box<
    dyn Fn(M) -> std::pin::Pin<Box<dyn Future<Output=ChannelResult<()>> + Send>> + Send + Sync,
>;

pub struct MockP2PChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    #[allow(dead_code)]
    validator_address: ValidatorAddress,
    broadcast_hook: Option<HookFn<M>>,
}

impl<M> MockP2PChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    pub fn new(validator_address: ValidatorAddress) -> Self {
        Self {
            validator_address,
            broadcast_hook: None,
        }
    }

    pub fn set_broadcast_hook<F, Fut>(&mut self, hook: F)
    where
        F: Fn(M) -> Fut + Send + Sync + 'static,
        Fut: Future<Output=ChannelResult<()>> + Send + 'static,
    {
        self.broadcast_hook = Some(Box::new(move |msg| Box::pin(hook(msg))));
    }
}

#[async_trait]
impl<M> P2PChannel<M> for MockP2PChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    async fn send_to(&self, _recipient: &ValidatorAddress, _message: M) -> ChannelResult<()> {
        Ok(())
    }

    async fn broadcast(&self, message: M) -> ChannelResult<()> {
        if let Some(ref hook) = self.broadcast_hook {
            hook(message).await
        } else {
            Ok(())
        }
    }

    async fn receive(&mut self) -> ChannelResult<AuthenticatedMessage<M>> {
        // Mock channel doesn't actually receive messages
        std::future::pending().await
    }

    async fn try_receive_timeout(
        &mut self,
        _duration: Duration,
    ) -> ChannelResult<Option<AuthenticatedMessage<M>>> {
        Ok(None)
    }

    fn pending_messages(&self) -> Option<usize> {
        Some(0)
    }
}

pub struct MockOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    publish_hook: Option<HookFn<M>>,
}

impl<M> Default for MockOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<M> MockOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self { publish_hook: None }
    }

    pub fn set_publish_hook<F, Fut>(&mut self, hook: F)
    where
        F: Fn(M) -> Fut + Send + Sync + 'static,
        Fut: Future<Output=ChannelResult<()>> + Send + 'static,
    {
        self.publish_hook = Some(Box::new(move |msg| Box::pin(hook(msg))));
    }
}

#[async_trait]
impl<M> OrderedBroadcastChannel<M> for MockOrderedBroadcastChannel<M>
where
    M: Clone + Send + Sync + 'static,
{
    async fn publish(&self, message: M) -> ChannelResult<()> {
        if let Some(ref hook) = self.publish_hook {
            hook(message).await
        } else {
            Ok(())
        }
    }

    async fn receive(&mut self) -> ChannelResult<AuthenticatedMessage<M>> {
        // Mock channel doesn't actually receive messages
        std::future::pending().await
    }

    async fn try_receive_timeout(
        &mut self,
        _duration: Duration,
    ) -> ChannelResult<Option<AuthenticatedMessage<M>>> {
        Ok(None)
    }

    fn pending_messages(&self) -> Option<usize> {
        Some(0)
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

    fn create_validator_addresses(count: usize) -> Vec<ValidatorAddress> {
        (1..=count)
            .map(|i| ValidatorAddress([i as u8; 32]))
            .collect()
    }

    #[tokio::test]
    async fn test_p2p_send_and_receive() {
        let validators = create_validator_addresses(2);
        let mut channels = InMemoryP2PChannels::new_network(validators.clone());

        let msg = TestMessage {
            id: 1,
            data: "test".to_string(),
        };

        channels
            .get(&validators[0])
            .unwrap()
            .send_to(&validators[1], msg.clone())
            .await
            .unwrap();

        let authenticated = channels
            .get_mut(&validators[1])
            .unwrap()
            .receive()
            .await
            .unwrap();

        // Verify the sender is authenticated correctly
        assert_eq!(authenticated.sender, validators[0]);
        assert_eq!(authenticated.message, msg);
    }

    #[tokio::test]
    async fn test_p2p_broadcast() {
        let validators = create_validator_addresses(3);
        let mut channels = InMemoryP2PChannels::new_network(validators.clone());

        let msg = TestMessage {
            id: 1,
            data: "broadcast".to_string(),
        };

        channels
            .get(&validators[0])
            .unwrap()
            .broadcast(msg.clone())
            .await
            .unwrap();

        // Validators 1 and 2 should receive it (not validator 0)
        for addr in &validators[1..] {
            let authenticated = channels.get_mut(addr).unwrap().receive().await.unwrap();
            // Verify sender is authenticated as validator 0
            assert_eq!(authenticated.sender, validators[0]);
            assert_eq!(authenticated.message, msg);
        }

        // Validator 0 should not have received it
        assert_eq!(
            channels.get(&validators[0]).unwrap().pending_messages(),
            Some(0)
        );
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
        let mut first_senders = vec![];
        for i in 0..NUM_VALIDATORS {
            let authenticated = channels
                .get_mut(&validators[0])
                .unwrap()
                .receive()
                .await
                .unwrap();
            // Verify the sender is authenticated correctly
            assert_eq!(authenticated.sender, validators[i]);
            first_order.push(authenticated.message.id);
            first_senders.push(authenticated.sender.clone());
        }

        // Check all other validators see the same order and same senders
        for validator in &validators[1..] {
            for (i, expected_id) in first_order.iter().enumerate() {
                let authenticated = channels
                    .get_mut(validator)
                    .unwrap()
                    .receive()
                    .await
                    .unwrap();
                assert_eq!(authenticated.sender, first_senders[i]);
                assert_eq!(authenticated.message.id, *expected_id);
            }
        }
    }

    #[tokio::test]
    async fn test_p2p_timeout_no_message() {
        let validators = vec![ValidatorAddress([1; 32])];
        let mut channels = InMemoryP2PChannels::<TestMessage>::new_network(validators.clone());

        let result = channels
            .get_mut(&validators[0])
            .unwrap()
            .try_receive_timeout(Duration::from_millis(100))
            .await
            .unwrap();

        assert!(result.is_none());
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
