# `loadtest`

Drives a full **deposit → mint → withdraw → settle** loop against a deployed
Hashi bridge. Point it at a cluster, say how many deposits and withdrawals you
want and how big, and it does the rest.

```
cargo run --release -p loadtest -- run \
  --deposits 100 --deposit-amount-btc 0.1 \
  --withdrawals 100 --withdrawal-amount-btc 0.1
```

Useful for load testing, and for verifying a deployment end to end after a
redeploy. It is not part of CI — `e2e-tests` covers that against a localnet.
This one talks to real clusters and real Bitcoin.

The bridge work goes through the same library the `hashi` CLI uses
(`hashi::cli`, `hashi::sui_tx_executor`), so it cannot drift from the CLI. What
this crate owns is everything around it that is easy to get wrong: reading the
deployment's real ids, funding many deposit UTXOs without tripping Bitcoin
Core's coin selection, retrying PTBs, and knowing when a run has finished.

## Setup

You need a synced `bitcoind` with a funded wallet, `sui`, and `kubectl`.

**1. A signing key.** The file may be PKCS#8 PEM/DER, a `suiprivkey1...` line,
or a keystore entry, so this is enough:

```bash
sui keytool export --key-identity "$(sui client active-address)" --json \
  | jq -r .exportedPrivateKey > signer.key
chmod 600 signer.key
```

**2. Funds.**

- SUI gas: roughly `ceil(deposits/333) * 1` + `ceil(withdrawals/250) * 2` SUI.
- BTC: the wallet needs **one UTXO** covering `deposits * deposit_amount` plus
  fees — see [funding](#funding) for why one, rather than merely a large total.

**3. Environment** (or the equivalent flags):

```bash
export HASHI_KEYPAIR=./signer.key
export BTC_RPC_URL=http://127.0.0.1:38332
export BTC_RPC_USER=... BTC_RPC_PASSWORD=...
export BTC_WALLET=mining          # default
```

Then check before spending anything:

```bash
cargo run -p loadtest -- doctor
```

## Usage

```
loadtest doctor                   # verify a run would work; touches nothing
loadtest run [opts]               # the full loop
loadtest deposit [opts]           # fund, register, wait for mint
loadtest withdraw [opts]          # withdraw against hBTC already held
```

| Option | Default | |
|---|---|---|
| `--deposits` | 100 | number of deposit UTXOs |
| `--deposit-amount-btc` | 0.1 | BTC per deposit |
| `--withdrawals` | 100 | number of withdrawal requests |
| `--withdrawal-amount-btc` | 0.1 | BTC per withdrawal |
| `--outputs-per-tx` | 250 | deposit outputs per funding tx |
| `--fee-rate` | 4.0 | funding tx sat/vB |
| `--withdraw-dest` | fresh address | where withdrawals pay out |
| `--report <path>` | | write a JSON run report |
| `--skip-settle` | | submit withdrawals, don't wait for BTC |

**Which deployment.** By default the package id, object id and Sui RPC are read
from `hashi-server-0`'s `config.toml` via `kubectl`. Use `--namespace` for
another environment, or pass `--package-id` / `--hashi-object-id` /
`--sui-rpc-url` to skip `kubectl` entirely.

> Prefer the default. Ids change on **every full redeploy**, and a stale id
> fails silently rather than loudly: the superseded Hashi object still exists
> and still accepts deposits, so the run looks green while testing nothing. Ids
> passed explicitly are cross-checked against the cluster and warned about on
> mismatch.

## What a run does

1. **Preflight** — ids match the cluster; bitcoind is synced, on the right
   network, and shares the bridge's genesis; the bridge isn't paused; amounts
   clear the onchain minimums; wallet and hBTC balances cover the run.
2. **Fund** — pays `--deposits` outputs to the derived deposit address, split
   across `--outputs-per-tx` transactions.
3. **Register** — submits deposit requests in PTBs of 333, straight from the
   mempool. No need to wait for confirmations: the committee enforces
   `bitcoin_confirmation_threshold` itself, so registering early only starts its
   watch sooner.
4. **Wait for mint** — polls hBTC until the deposits land.
5. **Withdraw** — submits requests in PTBs of 250, waiting for hBTC to cover
   each batch, so it also works while deposits are still minting.
6. **Wait for settlement** — until every request *this run submitted* has left
   the queue and its Bitcoin transactions have confirmed.

## Notes

#### Funding

`fundrawtransaction` will happily fund 1 BTC from ~1,400 dust inputs, building a
~95 kvB transaction. Signet's miner caps blocks near 1M weight, so a transaction
that fat gets skipped **indefinitely, at any fee rate** — it never fits the
remaining space. This crate therefore preselects the smallest single UTXO that
covers the run and passes `add_inputs: false`. That is why the wallet needs one
big UTXO, and why `doctor` fails loudly when it hasn't got one.

The same ceiling caps `--outputs-per-tx`: a P2TR output is 43 vB, so 250 outputs
≈ 11 kvB. Raising it means fewer, fatter transactions that are harder to mine.

Funding transactions are deliberately **not** replaceable. Deposits are
registered against the txid seconds after broadcast, so an RBF replacement would
change the txid and strand them; refusing to signal RBF takes `bumpfee` off the
table. A stalled funding tx gets CPFP'd instead — spend its change output with a
high-fee child (`sendrawtransaction <hex> 0` to bypass the fee cap), since
miners sort by ancestor fee rate.

#### Settlement

Withdrawals batch into a Bitcoin transaction at ~70 requests, or flush after a
5-minute window — so a *small* run waits the full window before anything is
built. The guardian also rate-limits withdrawals; past the bucket they trickle
out as it refills rather than failing. Both make settlement slow, not broken.

Broken looks different: `Guardian signature verification failed` in the node
logs. The run counts those while it waits and reports them, because a run that
merely times out otherwise looks the same either way.

#### Retries

Large runs make the peer gRPC layer drop connections. Every PTB is retried 5
times, and each call is exactly one atomic PTB, so a retry never lands a partial
batch.

It can land a whole one twice, in the narrow case where the transaction executed
and only the response was lost. For deposits that is harmless: the duplicate
request never mints, because `deposit()`'s replay check rejects it once the
original's UTXO reaches the pool. For withdrawals it burns hBTC twice, which
surfaces as the run running short of balance near the end.

#### Sui

hBTC lives in Sui's balance accumulator, not `Coin<BTC>` objects — `sui client
objects` shows nothing while the balance is non-zero. That is expected.
