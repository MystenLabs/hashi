// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Module: withdraw
module hashi::withdraw;

use hashi::{
    btc::BTC,
    btc_config,
    committee::CommitteeSignature,
    config::Config,
    hashi::Hashi,
    utxo::UtxoId,
    withdrawal_queue::OutputUtxo
};
use sui::{balance::Balance, clock::Clock, random::Random};

use fun btc_config::bitcoin_withdrawal_minimum as Config.bitcoin_withdrawal_minimum;
use fun btc_config::withdrawal_cancellation_cooldown_ms as
    Config.withdrawal_cancellation_cooldown_ms;

#[error]
const EBelowMinimumWithdrawal: vector<u8> = b"Withdrawal amount is below the minimum";
#[error]
const EInvalidBitcoinAddress: vector<u8> =
    b"Bitcoin address must be 20 bytes (P2WPKH) or 32 bytes (P2TR)";
#[error]
const EUnauthorizedCancellation: vector<u8> = b"Only the original requester can cancel";
#[error]
const ECooldownNotElapsed: vector<u8> = b"Cancellation cooldown has not elapsed";
#[error]
const ECannotCancelProcessingWithdrawal: vector<u8> =
    b"Cannot cancel a withdrawal that is already being processed";
#[error]
const EWithdrawalNotFullySigned: vector<u8> =
    b"Cannot confirm a withdrawal that is not fully signed";

// MESSAGE STEP 1
public struct RequestApprovalMessage has copy, drop, store {
    request_id: address,
}

// MESSAGE STEP 2
public struct WithdrawalCommitmentMessage has copy, drop, store {
    request_ids: vector<address>,
    selected_utxos: vector<UtxoId>,
    outputs: vector<OutputUtxo>,
    txid: address,
}

// MESSAGE STEP 3
//
// The cert binds both signature arrays — otherwise a malicious leader
// could pair valid MPC sigs with garbage guardian sigs and the cert
// would still pass.
public struct WithdrawalSignedMessage has copy, drop, store {
    withdrawal_id: address,
    request_ids: vector<address>,
    signatures: vector<vector<u8>>,
    guardian_signatures: vector<vector<u8>>,
}

// MESSAGE STEP 3 (incremental): one cert per out-of-order chunk of MPC
// signatures, binding exactly the input indices and signature bytes written.
public struct MpcInputSignaturesMessage has copy, drop, store {
    withdrawal_id: address,
    indices: vector<u64>,
    signatures: vector<vector<u8>>,
}

// MESSAGE STEP 4
public struct WithdrawalConfirmationMessage has copy, drop, store {
    withdrawal_id: address,
}

// ======== Message Constructors ========

public(package) fun new_request_approval_message(request_id: address): RequestApprovalMessage {
    RequestApprovalMessage { request_id }
}

public(package) fun new_withdrawal_commitment_message(
    request_ids: vector<address>,
    selected_utxos: vector<UtxoId>,
    outputs: vector<OutputUtxo>,
    txid: address,
): WithdrawalCommitmentMessage {
    WithdrawalCommitmentMessage { request_ids, selected_utxos, outputs, txid }
}

public(package) fun new_withdrawal_signed_message(
    withdrawal_id: address,
    request_ids: vector<address>,
    signatures: vector<vector<u8>>,
    guardian_signatures: vector<vector<u8>>,
): WithdrawalSignedMessage {
    WithdrawalSignedMessage {
        withdrawal_id,
        request_ids,
        signatures,
        guardian_signatures,
    }
}

public(package) fun new_mpc_input_signatures_message(
    withdrawal_id: address,
    indices: vector<u64>,
    signatures: vector<vector<u8>>,
): MpcInputSignaturesMessage {
    MpcInputSignaturesMessage { withdrawal_id, indices, signatures }
}

public(package) fun new_withdrawal_confirmation_message(
    withdrawal_id: address,
): WithdrawalConfirmationMessage {
    WithdrawalConfirmationMessage { withdrawal_id }
}

/// Request a withdrawal of BTC from the bridge.
///
/// The full BTC amount is stored in the withdrawal request. The miner
/// fee is deducted later at commitment time.
///
/// The user must provide at least `bitcoin_withdrawal_minimum()` sats,
/// which guarantees the amount covers worst-case miner fees plus dust.
public fun request_withdrawal(
    hashi: &mut Hashi,
    clock: &Clock,
    btc: Balance<BTC>,
    bitcoin_address: vector<u8>,
    ctx: &mut TxContext,
) {
    hashi.versioning().assert_version_enabled();
    hashi.assert_unpaused();

    assert!(btc.value() >= hashi.config().bitcoin_withdrawal_minimum(), EBelowMinimumWithdrawal);

    // Only P2WPKH (20 bytes) and P2TR (32 bytes) witness programs are supported.
    let addr_len = bitcoin_address.length();
    assert!(addr_len == 20 || addr_len == 32, EInvalidBitcoinAddress);

    // Create the withdrawal request.
    let request = hashi::withdrawal_queue::create_withdrawal(
        btc,
        bitcoin_address,
        clock,
        ctx,
    );
    let request_id = request.request_id().to_address();
    hashi::withdrawal_queue::emit_withdrawal_requested(&request);

    // Insert into the active requests bag.
    hashi.bitcoin_mut().withdrawal_queue_mut().insert_withdrawal(request);

    // Index by sender for client discovery.
    hashi.bitcoin_mut().index_user_request(ctx.sender(), request_id, ctx);
}

entry fun approve_request(
    hashi: &mut Hashi,
    request_id: address,
    cert: CommitteeSignature,
    clock: &Clock,
) {
    hashi.versioning().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.assert_not_reconfiguring();
    hashi.verify(
        hashi::intent::withdrawal_request_approval(),
        RequestApprovalMessage { request_id },
        cert,
    );

    hashi.bitcoin_mut().withdrawal_queue_mut().approve_withdrawal(request_id, cert, clock);
    hashi::withdrawal_queue::emit_withdrawal_approved(request_id);
}

// NOTE: request_ids and outputs must come presorted, so that request_ids[i] matches outputs[i].
// Any change outputs must be the trailing outputs in `outputs`, after the
// per-request outputs.
entry fun commit_withdrawal_tx(
    hashi: &mut Hashi,
    request_ids: vector<address>,
    selected_utxos: vector<UtxoId>,
    outputs: vector<OutputUtxo>,
    txid: address,
    cert: CommitteeSignature,
    clock: &Clock,
    r: &Random,
    ctx: &mut TxContext,
) {
    hashi.versioning().assert_version_enabled();
    hashi.assert_unpaused();
    // Do not allow scheduling of withdrawals during a reconfiguration.
    hashi.assert_not_reconfiguring();

    let epoch = hashi.committee_set().epoch();

    let approval = WithdrawalCommitmentMessage {
        request_ids,
        selected_utxos,
        outputs,
        txid,
    };

    hashi.verify(hashi::intent::withdrawal_commitment(), approval, cert);

    let WithdrawalCommitmentMessage { outputs, txid, .. } = approval;

    // Copy the full UTXO data from the pool before locking — used for fee
    // accounting and event emission inside new_withdrawal_txn.
    let inputs = selected_utxos.map!(|utxo_id| hashi.bitcoin().utxo_pool().get_utxo(utxo_id));

    // Extract request data for fee validation (read-only, before the object exists).
    let request_infos = hashi.bitcoin().withdrawal_queue().extract_request_infos(&request_ids);

    // Allocate presigs from core counter
    let presig_start_index = hashi.allocate_presigs(inputs.length());

    let mut rng = sui::random::new_generator(r, ctx);
    let randomness = rng.generate_bytes(32);

    // Create the WithdrawalTransaction object
    let withdrawal_txn = hashi::withdrawal_queue::new_withdrawal_txn(
        ctx,
        request_ids,
        &request_infos,
        inputs,
        outputs,
        txid,
        presig_start_index,
        epoch,
        hashi.config(),
        clock,
        randomness,
    );

    // Now that the object exists, use its ID for UTXO locks and request commits.
    let withdrawal_txn_id = withdrawal_txn.withdrawal_txn_id();

    // Lock input UTXOs to this withdrawal transaction.
    withdrawal_txn.withdrawal_txn_inputs().do_ref!(|utxo| {
        hashi.bitcoin_mut().utxo_pool_mut().lock(utxo.id(), withdrawal_txn_id);
    });

    // Commit requests: drain BTC, set status + withdrawal_txn_id, move to processed.
    let btc_to_burn = hashi.bitcoin_mut().withdrawal_queue_mut().commit_requests(&withdrawal_txn);

    // Burn BTC balance
    hashi.treasury_mut().burn(btc_to_burn);

    // Insert the pending change UTXOs into the pool immediately so they can be
    // selected by subsequent transactions before this one confirms on Bitcoin.
    let change_utxos = hashi::withdrawal_queue::build_change_utxos(&withdrawal_txn);
    change_utxos.do!(|change_utxo| {
        hashi.bitcoin_mut().utxo_pool_mut().insert_pending(change_utxo, withdrawal_txn_id);
    });

    withdrawal_txn.emit_withdrawal_picked_for_processing();

    hashi.bitcoin_mut().withdrawal_queue_mut().insert_withdrawal_txn(withdrawal_txn);
}

/// Reassign fresh presignatures to the still-unsigned inputs of a withdrawal
/// whose signing batch is from a previous epoch. Only the pending tail is
/// re-presigned; already-collected signatures are final and epoch-independent.
///
/// Gated like commit/finalize (version-enabled, unpaused, not-reconfiguring): an
/// in-progress reconfiguration settles first, then this runs afterward to recover
/// the now-stale batch. Carries no committee cert: it authorizes no signatures,
/// only re-points pending presig indices, bounded to once-per-withdrawal-per-epoch
/// by the `mpc_signing` stale-epoch guard.
entry fun reallocate_presigs(hashi: &mut Hashi, withdrawal_id: address) {
    hashi.versioning().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.assert_not_reconfiguring();
    let current_epoch = hashi.committee_set().epoch();
    let pending = hashi.bitcoin().withdrawal_queue().withdrawal_txn_pending_count(withdrawal_id);
    let new_base = hashi.allocate_presigs(pending);
    hashi
        .bitcoin_mut()
        .withdrawal_queue_mut()
        .reallocate_presigs_for_withdrawal_txn(withdrawal_id, new_base, current_epoch, pending);
}

/// Record a chunk of completed per-input MPC signatures into the withdrawal's
/// signing batch (out-of-order, first-writer-wins). Cert-gated over exactly the
/// `(withdrawal_id, indices, signatures)` written, by the current committee.
/// Repeated across checkpoints/leaders until every input is signed; the leader
/// may bundle a final chunk + `finalize_withdrawal` in one PTB for small txns.
entry fun commit_input_signatures(
    hashi: &mut Hashi,
    withdrawal_id: address,
    indices: vector<u64>,
    signatures: vector<vector<u8>>,
    cert: CommitteeSignature,
) {
    hashi.versioning().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.assert_not_reconfiguring();

    let approval = MpcInputSignaturesMessage { withdrawal_id, indices, signatures };
    hashi.verify(hashi::intent::mpc_input_signatures(), approval, cert);
    let MpcInputSignaturesMessage { indices, signatures, .. } = approval;

    hashi
        .bitcoin_mut()
        .withdrawal_queue_mut()
        .record_input_signatures(withdrawal_id, indices, signatures);
}

/// Finalize a withdrawal once all MPC signatures are in: attach the one-shot
/// guardian signatures and flip the broadcast gate. The cert binds the full MPC
/// signature set (read from the batch) together with the guardian signatures, so
/// a malicious leader cannot pair valid MPC sigs with garbage guardian sigs.
entry fun finalize_withdrawal(
    hashi: &mut Hashi,
    withdrawal_id: address,
    request_ids: vector<address>,
    guardian_signatures: vector<vector<u8>>,
    cert: CommitteeSignature,
    clock: &Clock,
) {
    hashi.versioning().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.assert_not_reconfiguring();

    // Reconstruct the completed MPC set from the batch so the committee signs
    // over the exact bytes the contract will broadcast.
    let signatures = hashi
        .bitcoin()
        .withdrawal_queue()
        .withdrawal_txn_mpc_signatures(withdrawal_id);

    let approval = WithdrawalSignedMessage {
        withdrawal_id,
        request_ids,
        signatures,
        guardian_signatures,
    };
    hashi.verify(hashi::intent::withdrawal_signed(), approval, cert);
    let WithdrawalSignedMessage { request_ids, guardian_signatures, .. } = approval;

    let queue = hashi.bitcoin_mut().withdrawal_queue_mut();
    queue.finalize_withdrawal_txn(withdrawal_id, guardian_signatures, clock);
    queue.update_requests_signed(&request_ids);
}

entry fun confirm_withdrawal(
    hashi: &mut Hashi,
    withdrawal_id: address,
    cert: CommitteeSignature,
    clock: &Clock,
) {
    hashi.versioning().assert_version_enabled();
    hashi.assert_unpaused();
    hashi.verify(
        hashi::intent::withdrawal_confirmation(),
        WithdrawalConfirmationMessage { withdrawal_id },
        cert,
    );

    // Refuse to confirm a withdrawal that is not fully signed (every input has
    // an MPC signature and the guardian signatures are attached). The
    // confirmation cert only binds `withdrawal_id`, so without this gate a
    // committee confirmation could finalize a committed-but-unsigned withdrawal
    // — marking its inputs spent and burning user BTC with no broadcastable
    // Bitcoin transaction. Off-chain signers additionally verify Bitcoin
    // confirmation before contributing to this cert.
    assert!(
        hashi.bitcoin().withdrawal_queue().withdrawal_txn_is_fully_signed(withdrawal_id),
        EWithdrawalNotFullySigned,
    );

    // Remove the in-flight withdrawal txn from the hot bag so we can do
    // all the bookkeeping with a direct handle, then re-insert it into the
    // confirmed bag at the end.
    let mut txn = hashi.bitcoin_mut().withdrawal_queue_mut().remove_withdrawal_txn(withdrawal_id);
    txn.mark_confirmed(clock);
    txn.emit_withdrawal_confirmed();

    // Update request statuses to Confirmed.
    hashi
        .bitcoin_mut()
        .withdrawal_queue_mut()
        .update_requests_confirmed(txn.withdrawal_txn_request_ids());

    let epoch = hashi.committee_set().epoch();

    // Mark each input UTXO as spent and emit spent events. The actual record
    // removal from utxo_records is deferred to `cleanup_spent_utxos` so this
    // transaction stays well under Sui's 1000-object runtime cache limit.
    txn.withdrawal_txn_inputs().do_ref!(|utxo| {
        hashi.bitcoin_mut().utxo_pool_mut().mark_spent(utxo.id(), epoch);
    });

    // Promote the change UTXOs from unconfirmed to confirmed. If a change UTXO
    // was already locked by a subsequent withdrawal, only `produced_by` is
    // cleared.
    let change_ids = txn.change_utxo_ids();
    change_ids.do!(|change_id| {
        hashi.bitcoin_mut().utxo_pool_mut().confirm_pending(change_id);
    });

    // Move the txn to the cold (historical) bag.
    hashi.bitcoin_mut().withdrawal_queue_mut().insert_confirmed_txn(txn);
}

/// Finalize the on-chain bookkeeping for spent UTXOs. Moves each UTXO's
/// record from `utxo_records` to `spent_utxos`, reading the spent epoch
/// from the record's `spent_epoch` field (set by `mark_spent` during
/// `confirm_withdrawal`). Callers pass the individual UTXO IDs to clean up.
entry fun cleanup_spent_utxos(hashi: &mut Hashi, utxo_ids: vector<UtxoId>) {
    hashi.versioning().assert_version_enabled();
    utxo_ids.do!(|utxo_id| {
        hashi.bitcoin_mut().utxo_pool_mut().cleanup_spent(utxo_id);
    });
}

/// Cancel a pending withdrawal request and return the stored BTC to the requester.
///
/// Cancellation is allowed while the request is in the `Requested` or `Approved`
/// state (i.e. still in the active requests bag). Once the committee commits the
/// request to a `WithdrawalTransaction` it moves to `Processing` in the processed
/// bag and its BTC is burned — cancellation is no longer possible.
public fun cancel_withdrawal(
    hashi: &mut Hashi,
    request_id: address,
    clock: &Clock,
    ctx: &mut TxContext,
): Balance<BTC> {
    hashi.versioning().assert_version_enabled();

    assert!(
        !hashi.bitcoin().withdrawal_queue().is_request_processing(request_id),
        ECannotCancelProcessingWithdrawal,
    );

    let request = hashi.bitcoin().withdrawal_queue().borrow_request(request_id);

    // Only the original requester can cancel.
    assert!(request.request_sender() == ctx.sender(), EUnauthorizedCancellation);

    // Enforce cooldown.
    let cooldown = hashi.config().withdrawal_cancellation_cooldown_ms();
    assert!(
        clock.timestamp_ms() >= request.request_created_timestamp_ms() + cooldown,
        ECooldownNotElapsed,
    );

    hashi::withdrawal_queue::emit_withdrawal_cancelled(request);

    // Return BTC to the requester.
    let btc = hashi.bitcoin_mut().withdrawal_queue_mut().cancel_withdrawal(request_id);

    // Clean up the user index.
    hashi.bitcoin_mut().unindex_user_request(ctx.sender(), request_id);

    btc
}
