# Rate Limiting Withdrawals

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> Hashi enforces a token-bucket rate limit on withdrawal outflows through the Guardian to protect against vulnerabilities.

To protect against vulnerabilities or other exceptional scenarios, Hashi
implements a rate limiter on outflows through the Guardian.

## How does Hashi rate limit withdrawals?

A token-bucket rate limiter implements the limit, with two settings that
the operator sets when provisioning the Guardian: a maximum capacity in satoshis (a
Bitcoin denomination) and a refill rate in satoshis per second. Capacity
refills continuously up to the maximum.

| Setting | Unit | Set when |
| --- | --- | --- |
| Maximum capacity | satoshis | Guardian provisioning |
| Refill rate | satoshis per second | Guardian provisioning |

## How are withdrawal requests queued?

When a user wants to withdraw their `BTC` back to Bitcoin, they initiate a
withdraw request. Hashi tags every withdraw request with the timestamp of its
submission and places it in a queue to wait for processing.

## How does Hashi process queued withdrawals?

To process withdrawal requests, Hashi selects them from the queue and performs
a number of checks. If all checks pass and there is capacity, Hashi
works with the Guardian to sign and broadcast a Bitcoin transaction to satisfy
the requests. Hashi checks the limit at 3 points:

1. Before committing a batch, the leader checks it against its own copy of the
   Guardian's limiter, which every node seeds from the Guardian and keeps in
   step with it.
2. The Guardian enforces the limit itself when it co-signs.
3. Each committee member re-checks its own copy before certifying the signed
   transaction.

## What happens when a withdrawal exceeds the rate limit?

When a withdraw request would exceed the rate limit, Hashi waits to process
it until sufficient capacity refills. Hashi skips a request larger than the
limiter's maximum capacity until governance raises the limit; its owner can
cancel it.

## In what order are withdrawals processed?

Withdrawals are generally processed in first-in-first-out (FIFO) order, but
this is not a strict requirement, and there are some scenarios where Hashi
might process them out of order.

## Can users cancel a queued withdrawal?

The Sui address that initiated a withdrawal request can cancel that request
when both of the following hold:

- The
  [`withdrawal_cancellation_cooldown_ms`](config.mdx#withdrawal_cancellation_cooldown_ms)
  cooldown has passed.
- Hashi has not yet committed it to a Bitcoin withdrawal transaction.
