# Withdraw BTC

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> How to redeem hBTC on Sui for native BTC using the Hashi CLI or the TypeScript SDK, including destination address rules, the miner fee, and how to track the withdrawal.

To move BTC back to Bitcoin, you submit a withdrawal request on Sui that burns
your `hBTC` and names the Bitcoin address that receives the BTC. You can make
the request with the Hashi CLI or with the TypeScript SDK. This page covers the
steps. For what the committee and the Guardian do with your request, see the
[Withdraw](../withdraw.mdx) lifecycle.

<Tabs className="tabsHeadingCentered--small">
<TabItem value="prereq" label="Prerequisites">
- [x] A Sui address holding `hBTC` and funded with SUI for gas, and its private key in one of the [accepted key formats](../validators/keys.mdx#operator-key-day-to-day-signing).
- [x] A Bitcoin address you control on the network that matches your Sui network. See the [Networks](../reference/networks.mdx) table.
- [x] For the CLI: a `hashi` binary built as described in [Software dependencies](../validators/prerequisites.mdx#software-dependencies) and a CLI config file from [CLI config](../validators/configuration.mdx#cli-config).
- [x] For the SDK: a Node.js project with `@mysten/hashi` and `@mysten/sui` installed as described in [TypeScript SDK](../ts-sdk.mdx).
</TabItem>
</Tabs>

## Before you withdraw

Keep the following rules in mind:

- **Minimum amount:** Each request must be at least
  [`bitcoin_withdrawal_minimum`](../config.mdx#bitcoin_withdrawal_minimum).
  The minimum guarantees that the request can pay the worst-case miner fee and
  still leave an output above Bitcoin's dust threshold.
- **Accepted destination addresses:** Hashi pays `P2WPKH` (bech32, `bc1q` on
  Mainnet) and `P2TR` (bech32m, `bc1p` on Mainnet) addresses. It does not
  support `P2WSH` or legacy address types. The address must belong to the
  Bitcoin network that matches your Sui network.
- **You pay the miner fee:** Hashi charges no protocol fee, but it deducts the
  Bitcoin miner fee from your output. The amount of BTC you receive is less
  than the `hBTC` you burn. See [Fees](../fees.mdx) for how Hashi bounds the
  fee.
- **Withdrawals queue:** Your request waits for committee approval, batching
  with other requests, and capacity in the Guardian's rate limiter. See
  [How long does a withdrawal take?](faq.mdx#how-long-does-a-withdrawal-take).

## Withdraw with the CLI

CLI global options such as `-c` belong after the first-level subcommand, so
`-c` goes after `withdraw`. See
[Global options](../reference/cli.mdx#global-options).

##### Step 1: Submit the request

Run the following command with the amount in satoshis and your destination
address:

```bash
hashi withdraw -c hashi-cli.toml request --amount <sats> --btc-address <addr>
```

The command burns the `hBTC` from your address, places the request in the
withdrawal queue, and prints the withdrawal request ID. Keep the ID. You need
it to check status and to cancel.

##### Step 2: Track the request

Check one request, or list all of them:

```bash
hashi withdraw -c hashi-cli.toml status <request-id>
hashi withdraw -c hashi-cli.toml list --json
```

The request moves through the states Requested, Approved, Processing, Signed,
and Confirmed. After Hashi commits the Bitcoin transaction, the status includes
its txid, which you can follow in any Bitcoin explorer.

## Withdraw with the TypeScript SDK

The SDK attaches to a Sui client and exposes every Hashi method under
`client.hashi.*`. Install it and create a client as described in
[TypeScript SDK](../ts-sdk.mdx#setup).

##### Step 1: Check fees and limiter capacity

Before you submit, you can read the worst-case miner fee, the onchain minimum,
and whether the Guardian's rate limiter can sign your amount right now:

```ts
// Withdrawal: worst-case BTC network fee + on-chain minimum. Pass a sender
// to also get a dry-run gas estimate.
const fees = await client.hashi.view.withdrawalFees(signer.toSuiAddress());
// { worstCaseNetworkFeeSats, withdrawalMinimumSats, gasEstimateMist }
```

```ts
// Can the guardian sign a 50,000-sat withdrawal right now?
const check = await client.hashi.guardian.canWithdraw(50_000n);
// { allowed, availableNowSats, estimatedWaitSecs }
```

##### Step 2: Submit the request

The SDK decodes the destination address as bech32 or bech32m and checks that
it matches the client's Bitcoin network before signing:

```ts
const result = await client.hashi.requestWithdrawal({
	signer,
	amountSats: 50_000n,
	bitcoinAddress: 'tb1q…', // P2WPKH on signet/testnet, or `tb1p…` for P2TR
});

if (result.$kind !== 'Transaction') {
	throw new Error(`request failed: ${JSON.stringify(result.FailedTransaction)}`);
}

// Pull the request id out of the WithdrawalRequested — needed if
// you later want to cancel.
const evt = result.Transaction.events?.find((e) =>
	e.eventType.endsWith('::withdrawal_queue::WithdrawalRequested'),
);
const requestId = (evt as { json?: { request_id?: string } } | undefined)?.json?.request_id;
```

Keep `requestId` if you might [cancel the withdrawal](cancel.mdx).

##### Step 3: Track the request

Use the transaction digest to check status once or to wait for a terminal
state:

```ts
const withdrawal = await client.hashi.view.withdrawalStatus(digest);
// withdrawal?.status: "Requested" | "Approved" | "Processing"
//                     | "Signed" | "Confirmed" | "cancelled"
```

```ts
const wInfo = await client.hashi.waitForWithdrawal(digest);
// wInfo.btcTxid is populated once the committee commits the Bitcoin tx.
```

## If the transaction is slow to confirm

Hashi does not replace a slow Bitcoin transaction with a higher-fee version.
If your withdrawal sits in the mempool, you can speed it up yourself by
spending your output with a higher-fee child transaction, which pays for the
parent. See [Stuck transactions](../fees.mdx#stuck-transactions).
