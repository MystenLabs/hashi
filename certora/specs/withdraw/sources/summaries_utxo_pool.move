module withdraw::summaries_utxo_pool;

use cvlm::asserts::cvlm_assume_msg;
use cvlm::manifest::{ghost, summary};
use hashi::btc::BTC;
use hashi::hashi::Hashi;
use hashi::utxo::{Utxo, UtxoId};
use hashi::utxo_pool::UtxoPool;
use hashi::withdrawal_queue::{
    CommittedRequestInfo,
    OutputUtxo,
    WithdrawalRequestQueue,
    WithdrawalTransaction
};
use sui::balance::Balance;

public fun cvlm_manifest() {
    summary(b"insert_active_summary", @hashi, b"utxo_pool", b"insert_active");
    summary(b"insert_pending_summary", @hashi, b"utxo_pool", b"insert_pending");
    summary(b"lock_summary", @hashi, b"utxo_pool", b"lock");
    summary(b"lock_input_utxos_summary", @hashi, b"withdraw", b"lock_input_utxos");
    summary(b"commit_requests_summary", @hashi, b"withdrawal_queue", b"commit_requests");
    summary(b"insert_change_utxos_summary", @hashi, b"withdraw", b"insert_change_utxos");
    summary(b"sum_input_amounts_summary", @hashi, b"withdrawal_queue", b"sum_input_amounts");
    summary(b"sum_output_amounts_summary", @hashi, b"withdrawal_queue", b"sum_output_amounts");
    summary(
        b"check_withdrawal_outputs_summary",
        @hashi,
        b"withdrawal_queue",
        b"check_withdrawal_outputs",
    );
    summary(b"count_requests_summary", @hashi, b"withdrawal_queue", b"count_requests");
    summary(b"count_outputs_summary", @hashi, b"withdrawal_queue", b"count_outputs");

    ghost(b"total_active_amount");
    ghost(b"sum_of_input_utxos");
    ghost(b"sum_of_withdraw_requests");
    ghost(b"tracked_request");
    ghost(b"sum_of_change_utxos");
    ghost(b"sum_of_output_utxos");
    ghost(b"count_of_requests");
    ghost(b"count_of_outputs");
}

/// Ghost: total amount of pool UTXOs with spent_by == none (pool BTC).
public native fun total_active_amount(): &mut u64;

public fun insert_active_summary(self: &mut UtxoPool, utxo: Utxo) {
    let amount = utxo.amount();
    self.insert_active_reimpl(utxo);

    let total = total_active_amount();
    *total = *total + amount;
}

public fun insert_pending_summary(self: &mut UtxoPool, utxo: Utxo, withdrawal_id: address) {
    let amount = utxo.amount();
    self.insert_pending_reimpl(utxo, withdrawal_id);

    let total = total_active_amount();
    *total = *total + amount;
}

/// Locking a UTXO (spent_by: none -> Some) is where it leaves pool BTC.
public fun lock_summary(self: &mut UtxoPool, utxo_id: UtxoId, withdrawal_id: address) {
    let amount = self.get_utxo(utxo_id).amount();
    self.lock_reimpl(utxo_id, withdrawal_id);

    let total = total_active_amount();
    *total = *total - amount;
}

/// Replaces the loop that locks each input UTXO with one decrease of pool BTC by
/// sum_of_input_utxos.
public fun lock_input_utxos_summary(
    _hashi: &mut Hashi,
    _withdrawal_txn: &WithdrawalTransaction,
    _withdrawal_txn_id: address,
) {
    let total = total_active_amount();
    *total = *total - sum_of_input_utxos();
}

/// Ghost: total amount of a withdrawal's input UTXOs, not tied to the actual inputs.
public native fun sum_of_input_utxos(): u64;

/// Replaces the loop that drains each committed request's escrow with one balance of
/// sum_of_withdraw_requests. The real loop body (commit_request) runs only for
/// tracked_request, and only if it is one of the transaction's requests; every other
/// request is left untouched.
public fun commit_requests_summary(
    self: &mut WithdrawalRequestQueue,
    withdrawal_txn: &WithdrawalTransaction,
): Balance<BTC> {
    let tracked = tracked_request();
    if (withdrawal_txn.withdrawal_txn_request_ids().contains(&tracked)) {
        let drained = self.commit_request(withdrawal_txn.withdrawal_txn_id(), tracked);
        sui::balance::destroy_for_testing(drained);
    };
    sui::balance::create_for_testing<BTC>(sum_of_withdraw_requests())
}

/// Ghost: the one withdrawal request whose commit commit_requests_summary models.
/// Rules about a request pin it with `cvlm_assume(tracked_request() == request_id)`.
public native fun tracked_request(): address;

/// Ghost: total escrowed balance of the committed requests, not tied to the actual
/// requests.
public native fun sum_of_withdraw_requests(): u64;

/// Replaces the loop that inserts each change UTXO with one increase of pool BTC by
/// sum_of_change_utxos.
public fun insert_change_utxos_summary(
    _hashi: &mut Hashi,
    _withdrawal_txn: &WithdrawalTransaction,
    _withdrawal_txn_id: address,
) {
    let total = total_active_amount();
    *total = *total + sum_of_change_utxos();
}

/// Ghost: total amount of a withdrawal's change UTXOs, not tied to the actual outputs.
public native fun sum_of_change_utxos(): u64;

/// Returns sum_of_input_utxos, so fee accounting and locking see the same input total.
public fun sum_input_amounts_summary(_inputs: &vector<Utxo>): u64 {
    sum_of_input_utxos()
}

/// Returns the change total plus the per-request output total.
public fun sum_output_amounts_summary(_outputs: &vector<OutputUtxo>): u64 {
    sum_of_change_utxos() + sum_of_output_utxos()
}

/// Ghost: total amount of a withdrawal's per-request (non-change) outputs.
public native fun sum_of_output_utxos(): u64;

/// Assumes only that per-request outputs plus request count times the per-user fee
/// equal the committed balance; dust and address checks are not modeled.
public fun check_withdrawal_outputs_summary(
    request_count: u64,
    _request_infos: &vector<CommittedRequestInfo>,
    _outputs: &vector<OutputUtxo>,
    per_user_miner_fee: u64,
) {
    cvlm_assume_msg(
        sum_of_output_utxos() + request_count * per_user_miner_fee == sum_of_withdraw_requests(),
        b"sum_of_output_utxos + request_count * per_user_miner_fee == sum_of_withdraw_requests",
    );
}

/// Returns an opaque request count.
public fun count_requests_summary(_request_ids: &vector<address>): u64 {
    count_of_requests()
}

public native fun count_of_requests(): u64;

/// Returns an opaque output count.
public fun count_outputs_summary(_outputs: &vector<OutputUtxo>): u64 {
    count_of_outputs()
}

public native fun count_of_outputs(): u64;
