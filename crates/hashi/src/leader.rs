use crate::Hashi;
use crate::config::ForceRunAsLeader;
use crate::onchain::types::DepositRequest;
pub use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::traits::ToFromBytes;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::MemberSignature;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignDepositConfirmationResponse;
use prost_types::FieldMask;
use std::sync::Arc;
use sui_crypto::SuiSigner;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_sdk_types::Address;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;
use tracing::error;
use tracing::info;
use tracing::trace;
use x509_parser::nom::AsBytes;

const NUM_CONSECUTIVE_LEADER_CHECKPOINTS: u64 = 10;

#[derive(Clone)]
pub struct LeaderService {
    inner: Arc<Hashi>,
}

impl LeaderService {
    pub fn new(hashi: Arc<Hashi>) -> Self {
        Self { inner: hashi }
    }

    // TODO: return a handle so we can gracefully shutdown, etc
    pub async fn start(self) -> () {
        info!("Starting leader service");
        let mut checkpoint_rx = self.inner.onchain_state().subscribe_checkpoint();

        loop {
            trace!("Waiting for next checkpoint...");
            let wait_result = checkpoint_rx.changed().await;
            if let Err(e) = wait_result {
                error!("Error waiting for checkpoint change: {e}");
                break;
            }
            let checkpoint_height = *checkpoint_rx.borrow_and_update();

            if self.is_current_leader(checkpoint_height) {
                trace!("We are the leader node");
            } else {
                trace!("We are not the leader node");
                continue;
            }

            self.process_deposit_requests().await;
        }
    }

    pub fn is_current_leader(&self, checkpoint_height: u64) -> bool {
        match self.inner.config.force_run_as_leader() {
            ForceRunAsLeader::Always => return true,
            ForceRunAsLeader::Never => return false,
            ForceRunAsLeader::Default => (),
        }

        let onchain_state = self.inner.onchain_state();
        let state = onchain_state.state();
        let Some(committee) = state.hashi().committees.current_committee() else {
            // TODO: do we need to do anything when bootstrapping? At genesis there is no committee.
            return false;
        };
        let this_validator_address = self
            .inner
            .config
            .validator_address()
            .expect("No configured validator address");
        let Some(this_validator_idx) = committee
            .index_of(&this_validator_address)
            .map(|i| i as u64)
        else {
            // We are not in the committee yet, so we cannot be the leader
            return false;
        };
        let num_validators = committee.members().len() as u64;

        let current_turn = checkpoint_height / NUM_CONSECUTIVE_LEADER_CHECKPOINTS;
        (current_turn % num_validators) == this_validator_idx
    }

    async fn process_deposit_requests(&self) {
        trace!("Processing deposit requests");
        let mut deposit_requests: Vec<_> = {
            let state = self.inner.onchain_state().state();
            state
                .hashi()
                .deposit_queue
                .requests()
                .values()
                .cloned()
                .collect()
        };
        // Sort deposit_requests by timestamp, from earliest to latest
        deposit_requests.sort_by_key(|r| r.timestamp_ms);

        // TODO: parallelize?
        for deposit_request in deposit_requests {
            self.process_deposit_request(&deposit_request).await;
        }
    }

    async fn process_deposit_request(&self, deposit_request: &DepositRequest) {
        // TODO: parallelize, and after we have a quorum of sigs, stop waiting for sigs from any
        // additional validators
        trace!("Processing deposit request: {:?}", deposit_request);

        // Validate deposit_request before asking for signatures
        let validate_result = self.inner.validate_deposit_request(deposit_request).await;
        if let Err(e) = validate_result {
            error!(
                "Deposit request {:?} failed validation: {e}",
                deposit_request
            );
            return;
        }

        let proto_request = deposit_request.to_proto();
        let members = {
            let state = self.inner.onchain_state().state();
            state
                .hashi()
                .committees
                .current_committee()
                .expect("No current committee")
                .members()
                .to_vec()
        };

        let mut signatures: Vec<MemberSignature> = Vec::new();
        for member in members {
            if let Some(signature) = self
                .request_deposit_confirmation_signature(proto_request.clone(), &member)
                .await
            {
                signatures.push(signature);
            }
        }

        let result = self
            .submit_deposit_confirmation(deposit_request.clone(), signatures)
            .await;
        if let Err(e) = result {
            error!(
                "Failed to submit deposit confirmation for deposit request:{deposit_request:?}: {e}"
            );
        }
    }

    async fn request_deposit_confirmation_signature(
        &self,
        proto_request: SignDepositConfirmationRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting deposit confirmation signature from {}",
            validator_address
        );

        let mut client = {
            let state = self.inner.onchain_state().state();
            state
                .hashi()
                .committees
                .client(&validator_address)
                .or_else(|| {
                    error!(
                        "Cannot find client for validator address: {:?}",
                        validator_address
                    );
                    None
                })?
                .bridge_service_client()
        };

        let response = client
            .sign_deposit_confirmation(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get deposit confirmation signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved deposit confirmation signature from {}",
            validator_address
        );

        into_member_signature(response.into_inner())
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    async fn submit_deposit_confirmation(
        &self,
        deposit_request: DepositRequest,
        signatures: Vec<MemberSignature>,
    ) -> anyhow::Result<()> {
        info!(
            "Aggregating signatures and submitting confirmation to hashi for deposit id {:?}",
            deposit_request.id
        );

        let committee = {
            let state = self.inner.onchain_state().state();
            state
                .hashi()
                .committees
                .current_committee()
                .expect("No current committee")
                .clone()
        };

        // Aggregate signatures
        let mut signature_aggregator =
            BlsSignatureAggregator::new(&committee, deposit_request.clone());
        for signature in signatures {
            signature_aggregator.add_signature(signature)?;
        }

        // Check for quorum
        // TODO: better way to check for quorom than hardcoding
        let weight = signature_aggregator.weight();
        let required_weight = 6667;
        if weight < required_weight {
            anyhow::bail!(
                "Aggregate weight of signatures {weight} is less than required weight {required_weight}"
            );
        }

        // Submit onchain
        let aggregate_signature = signature_aggregator.finish()?;
        self.submit_deposit_confirmation_onchain(&deposit_request, aggregate_signature)
            .await?;
        info!(
            "Successfully submitted deposit confirmation for request: {:?}",
            deposit_request.id
        );
        Ok(())
    }

    async fn submit_deposit_confirmation_onchain(
        &self,
        deposit_request: &DepositRequest,
        signed_message: hashi_types::committee::SignedMessage<DepositRequest>,
    ) -> anyhow::Result<()> {
        use sui_sdk_types::*;

        let sui_rpc_url = self
            .inner
            .config
            .sui_rpc
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No sui_rpc configured"))?;
        let mut client = sui_rpc::Client::new(sui_rpc_url)?;

        let operator_private_key = self.inner.config.operator_private_key()?;
        let sender = operator_private_key.public_key().derive_address();
        let price = client.get_reference_gas_price().await?;
        let gas_objects = client
            .select_coins(&sender, &StructTag::sui().into(), 1_000_000_000, &[])
            .await?;

        let hashi_ids = self.inner.config.hashi_ids();
        let hashi_initial_shared_version = {
            let state = self.inner.onchain_state().state();
            state.hashi().initial_shared_version
        };
        let committee_sig = signed_message.committee_signature();

        // Build a PTB that:
        // 1. Calls committee::new_committee_signature to construct the CommitteeSignature
        // 2. Passes the result to deposit::confirm_deposit
        let mut builder = TransactionBuilder::new();
        builder.set_sender(sender);
        builder.set_gas_price(price);
        builder.set_gas_budget(1_000_000_000);
        builder.add_gas_objects(gas_objects.iter().map(|o| {
            ObjectInput::owned(
                o.object_id().parse().unwrap(),
                o.version(),
                o.digest().parse().unwrap(),
            )
        }));

        let request_id_arg = builder.pure(&deposit_request.id);
        let epoch_arg = builder.pure(&committee_sig.epoch());
        let signature_arg = builder.pure(&committee_sig.signature_bytes());
        let bitmap_arg = builder.pure(&committee_sig.signers_bitmap_bytes());

        // Call new_committee_signature to get the properly serialized CommitteeSignature
        let committee_sig_arg = builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("committee"),
                Identifier::from_static("new_committee_signature"),
            ),
            vec![epoch_arg, signature_arg, bitmap_arg],
        );

        // Call confirm deposit
        let hashi_arg = builder.object(ObjectInput::shared(
            hashi_ids.hashi_object_id,
            hashi_initial_shared_version,
            true,
        ));
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("deposit"),
                Identifier::from_static("confirm_deposit"),
            ),
            vec![hashi_arg, request_id_arg, committee_sig_arg],
        );

        let tx = builder.try_build()?;
        let signature = operator_private_key.sign_transaction(&tx)?;

        let response = client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(tx.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_str("*")),
                std::time::Duration::from_secs(10),
            )
            .await?
            .into_inner();
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "Transaction failed to confirm deposit for request {:?}",
                deposit_request.id
            );
        }
        Ok(())
    }
}

impl DepositRequest {
    fn to_proto(&self) -> SignDepositConfirmationRequest {
        SignDepositConfirmationRequest {
            id: self.id.as_bytes().to_vec().into(),
            txid: self.utxo.id.txid.as_bytes().to_vec().into(),
            vout: self.utxo.id.vout,
            amount: self.utxo.amount,
            derivation_path: self
                .utxo
                .derivation_path
                .map(|p| p.as_bytes().to_vec().into()),
            timestamp_ms: self.timestamp_ms,
        }
    }
}

fn into_member_signature(
    response: SignDepositConfirmationResponse,
) -> anyhow::Result<MemberSignature> {
    let member_signature = response.member_signature.ok_or(anyhow::anyhow!(
        "No member_signature in SignDepositConfirmationResponse"
    ))?;
    let epoch = member_signature
        .epoch
        .ok_or(anyhow::anyhow!("No epoch in MemberSignature"))?;
    let address = Address::from_bytes(
        member_signature
            .address
            .ok_or(anyhow::anyhow!("No address in MemberSignature"))?
            .as_bytes(),
    )?;
    let signature = BLS12381Signature::from_bytes(
        member_signature
            .signature
            .ok_or(anyhow::anyhow!("No signature in MemberSignature"))?
            .as_bytes(),
    )?;
    Ok(MemberSignature::new(epoch, address, signature))
}
