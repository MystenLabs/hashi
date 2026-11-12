# Rate Limiting Withdrawals

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> Hashi enforces a token-bucket rate limit on withdrawal outflows through the Guardian to protect against vulnerabilities.

To protect against vulnerabilities or other exceptional scenarios, Hashi
implements a rate limiter on outflows through the Guardian.

The limit is implemented as a token-bucket rate limiter with two settings,
set when the Guardian is provisioned: a maximum capacity in satoshis and a
refill rate in satoshis per second. Capacity refills continuously up to the
maximum.

When a user wants to withdraw their `BTC` back to Bitcoin, they initiate a
withdraw request. All withdraw requests are tagged with a timestamp of when
the request was made and placed in a queue to wait for Hashi to process the
withdrawal.

To process withdrawal requests, Hashi selects them from the queue and performs
a number of checks. Before committing a batch, the leader checks it against
its own copy of the Guardian's limiter, which every node seeds from the
Guardian and keeps in step with it. If all checks are satisfied and there is
capacity, Hashi works with the Guardian to sign and broadcast a Bitcoin
transaction to satisfy the requests. The Guardian enforces the limit itself
when it co-signs, and each committee member re-checks its own copy before
certifying the signed transaction.

When a withdraw request would exceed the rate limit, Hashi waits to process
it until sufficient capacity is replenished. A request larger than the
limiter's maximum capacity is skipped until the limit is raised; its owner can
cancel it.

Withdrawals are generally processed in first-in-first-out (FIFO) order, but
this is not a strict requirement, and there are some scenarios where they
might be processed out of order.

The Sui address that initiated a withdrawal request can cancel that request
once the
[`withdrawal_cancellation_cooldown_ms`](config.mdx#withdrawal_cancellation_cooldown_ms)
cooldown has passed, until Hashi commits it to a Bitcoin withdrawal
transaction.
