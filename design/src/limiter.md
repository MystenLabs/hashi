# Rate Limiting Withdrawals

In order to protect against vulnerabilities or other exceptional scenarios,
hashi will implement a Rate Limiter on out flows via the Guardian.

The limit will be a configurable value denominated in `BTC` and implemented as
a token bucket rate limiter, that is capacity will be replenished continuously
over a fixed duration.

When a user wishes to withdraw their `BTC` back to Bitcoin, they initiate a
withdraw request. All withdraw requests are tagged with a timestamp of when
the request was made and placed in a queue to wait for hashi to process the
withdrawal.

In order to process a withdrawal request hashi will select a request from the
queue and perform a number of checks, one of which is communicating with the
Guardian to ensure there is sufficient capacity for the request. If all checks
are satisfied and there is capacity, hashi will work with the Guardian to sign
and broadcast a Bitcoin transaction to satisfy the request.

When a withdraw request comes in and it would exceed the rate limit, hashi will
wait to process it until sufficient capacity is replenished.

Withdrawals will generally be processed in FIFO order, but this isn't a strict
requirement and there are some scenarios where they may be processed out of
order.

User withdrawal requests can be canceled, by the Sui address that initiated
them, anytime prior to hashi selecting a request for processing.
