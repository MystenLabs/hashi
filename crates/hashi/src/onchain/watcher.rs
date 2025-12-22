use futures::StreamExt;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;
use sui_sdk_types::Address;

use crate::onchain::OnchainState;

pub async fn watcher(mut client: Client, state: OnchainState) {
    let subscription_read_mask = FieldMask::from_paths([
        Checkpoint::path_builder().sequence_number(),
        Checkpoint::path_builder()
            .transactions()
            .events()
            .events()
            .contents()
            .finish(),
        Checkpoint::path_builder().transactions().digest(),
        Checkpoint::path_builder()
            .transactions()
            .effects()
            .status()
            .finish(),
    ]);

    loop {
        let mut subscription = match client
            .subscription_client()
            .subscribe_checkpoints(
                SubscribeCheckpointsRequest::default()
                    .with_read_mask(subscription_read_mask.clone()),
            )
            .await
        {
            Ok(subscription) => subscription,
            Err(e) => {
                tracing::warn!("error trying to subscribe to checkpoints: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        }
        .into_inner();

        while let Some(item) = subscription.next().await {
            let checkpoint = match item {
                Ok(checkpoint) => checkpoint,
                Err(e) => {
                    tracing::warn!("error in checkpoint stream: {e}");
                    break;
                }
            };

            let ckpt = checkpoint.cursor();
            tracing::debug!("recieved checkpoint {ckpt}");
            state.state().update_latest_checkpoint(ckpt);

            for txn in checkpoint.checkpoint().transactions() {
                // Skip txns that were not successful
                if !txn.effects().status().success() {
                    continue;
                }

                for event in txn.events().events() {
                    let Some(type_package_id) = peel_address(event.contents().name()) else {
                        tracing::debug!("parsing address off type failed");
                        continue;
                    };

                    // If this isn't from a package we care about we can skip
                    if !state.state().package_ids.contains(&type_package_id) {
                        continue;
                    }

                    tracing::debug!("found event {}", event.contents().name());
                    //TODO define and do something with the events
                }
            }
        }
    }
}

fn peel_address(ty: &str) -> Option<Address> {
    if let Some((addr, _)) = ty.split_once("::") {
        addr.parse().ok()
    } else {
        None
    }
}
