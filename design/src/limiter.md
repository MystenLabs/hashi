# Rate Limiting

In order to protect against vulnerabilities or other exceptional scenarios,
hashi will implement a Rate Limiter on in and out flows.

Each limit will be a configurable value denominated in `BTC` and capacity will
be replenished continuously over a fixed duration. The Guardian will implement
its own rate limiter and is expected to have its limit be larger than on chain
limit in order to have a slight buffer in case the intervals are not synced
properly.

## Deposits

Hashi requires that users notify hashi of a deposit by sending a transaction to
Sui. All deposit notifications are assigned a unique sequence number and placed
in a queue, this inherently ascribes a total order to the deposits.

When a deposit comes in and it would exceed the rate limit, it will remain in
the queue. Deposits will gradually be processed and released once enough
capacity is replenished.

Deposits will generally be processed in FIFO order, but this isn't a strict
requirement and there are some scenarios where they may be processed out of
order.

Since a deposit requires that a Bitcoin transaction has already been signed and
broadcast, it isn't possible to cancel a deposit.

## Withdrawals

When a user wishes to withdraw their `BTC` back to Bitcoin, they initiate a
withdraw request. All withdraw requests are assigned a unique sequence number
and placed in a queue to wait for hashi to process the withdrawal by building
and signing a Bitcoin transaction.

When a withdraw request comes in and it would exceed the rate limit, hashi will
wait to process it until sufficient capacity is replenished or if the withdraw
request has been in the queue for longer than 48 hours, at which point the
limit will be skipped.

<!-- TODO to figure out how a request skipping the limit impacts the existing -->
<!-- capacity of the limiter -->

Withdrawals will generally be processed in FIFO order, but this isn't a strict
requirement and there are some scenarios where they may be processed out of
order.

Cancellations are not planned to be supported initially. Despite not having
cancellations, a user can expect that their request will take at worst 48 hours
to be processed.
