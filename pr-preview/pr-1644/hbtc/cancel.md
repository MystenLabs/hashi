# Cancel a Withdrawal

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> When you can cancel a pending Hashi withdrawal and how to do it with the CLI or the TypeScript SDK to get your hBTC back.

A withdrawal request waits in a queue before Hashi commits it to a Bitcoin
transaction. While it waits, you can cancel it and get your `hBTC` back. This
page explains when a cancellation succeeds and how to submit one with the
Hashi CLI or the TypeScript SDK.

## When you can cancel

The onchain contract enforces 3 conditions. All of them must hold:

- **You made the request:** Only the Sui address that submitted the request
  can cancel it.
- **Hashi has not committed it yet:** The request must still be in the
  Requested or Approved state. After the committee commits the request to a
  Bitcoin transaction, Hashi burns the `hBTC` and the withdrawal completes on
  Bitcoin. You cannot cancel it.
- **The cooldown has passed:** At least
  [`withdrawal_cancellation_cooldown_ms`](../config.mdx#withdrawal_cancellation_cooldown_ms)
  must have elapsed since you submitted the request. The cooldown stops rapid
  submit-and-cancel cycles from interfering with processing.

Common reasons to cancel include a request that is larger than the Guardian
rate limiter's maximum capacity, which Hashi skips until governance raises the limit,
and a destination address you entered incorrectly. See
[Rate Limiting Withdrawals](../limiter.mdx) for how the limiter affects queued
requests.

## Cancel with the CLI

You need the withdrawal request ID that `hashi withdraw request` printed. If
you did not keep it, list your requests:

```bash
hashi withdraw -c hashi-cli.toml list --json
```

Then cancel:

```bash
hashi withdraw -c hashi-cli.toml cancel <request-id>
```

CLI global options such as `-c` belong after the first-level subcommand. See
[Global options](../reference/cli.mdx#global-options).

## Cancel with the TypeScript SDK

Pass the request ID you extracted from the `WithdrawalRequested` event when
you [submitted the withdrawal](withdraw.mdx#withdraw-with-the-typescript-sdk):

```ts
await client.hashi.cancelWithdrawal({ signer, requestId });
```

The SDK does not check the 3 conditions before signing. If any of them fails,
the Sui transaction aborts and your `hBTC` stays locked in the request until
the condition holds or the withdrawal completes.

## After you cancel

Hashi returns the full `hBTC` amount to your Sui address in the same
transaction. The request's status becomes cancelled, and
`client.hashi.view.withdrawalStatus` reports it as `cancelled`. You can
confirm the refund with the balance command or the balance reader described in
[Deposit BTC](deposit.mdx#step-3-check-your-hbtc-balance).
