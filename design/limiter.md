# Rate Limiting Withdrawals

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> Hashi enforces a token-bucket rate limit on withdrawal outflows through the Guardian to protect against vulnerabilities.

To protect against vulnerabilities or other exceptional scenarios, Hashi
implements a rate limiter on outflows through the Guardian.

The limit is a configurable value denominated in `BTC` and is implemented as
a token-bucket rate limiter. Capacity is replenished continuously over a
fixed duration.

When a user wants to withdraw their `BTC` back to Bitcoin, they initiate a
withdraw request. All withdraw requests are tagged with a timestamp of when
the request was made and placed in a queue to wait for Hashi to process the
withdrawal.

To process a withdrawal request, Hashi selects a request from the queue and
performs a number of checks. One check communicates with the Guardian to
confirm there is sufficient capacity for the request. If all checks are
satisfied and there is capacity, Hashi works with the Guardian to sign and
broadcast a Bitcoin transaction to satisfy the request.

When a withdraw request would exceed the rate limit, Hashi waits to process
it until sufficient capacity is replenished.

Withdrawals are generally processed in first-in-first-out (FIFO) order, but
this is not a strict requirement, and there are some scenarios where they
might be processed out of order.

The Sui address that initiated a withdrawal request can cancel that request
at any time before Hashi selects it for processing.
