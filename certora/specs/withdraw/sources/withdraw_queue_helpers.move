module withdraw::withdraw_queue_helpers;

use hashi::withdrawal_queue::WithdrawalRequestQueue;

/// The queue's four ObjectBags are pairwise distinct objects, as in any reachable
/// state: withdrawal_queue::create gives each its own fresh UID. A fully-nondet queue
/// may alias any two, which makes a write to one visible through the other.
public fun queue_bags_distinct(queue: &WithdrawalRequestQueue): bool {
    let requests = object::id(queue.requests_ref());
    let processed = object::id(queue.processed_ref());
    let in_flight = object::id(queue.withdrawal_txns_ref());
    let confirmed = object::id(queue.confirmed_txns_ref());
    requests != processed && requests != in_flight && requests != confirmed &&
        processed != in_flight && processed != confirmed &&
        in_flight != confirmed
}

/// A request is in at most one of the requests and processed bags, as
/// withdraw_request_mutual_exclusion proves for every entry point.
public fun request_in_one_bag(queue: &WithdrawalRequestQueue, id: address): bool {
    !(queue.contains_request(id) && queue.contains_processed(id))
}

/// A transaction is in at most one of the withdrawal_txns and confirmed_txns bags, as
/// withdraw_mutual_exclusion proves for every entry point.
public fun txn_in_one_bag(queue: &WithdrawalRequestQueue, id: address): bool {
    !(queue.contains_withdrawal_txn(id) && queue.contains_confirmed_txn(id))
}
