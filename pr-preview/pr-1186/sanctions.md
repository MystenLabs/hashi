# Handling Sanctioned Addresses

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> How Hashi committee members independently apply sanctions checks to deposits and withdrawals with their own TRM Labs accounts.

The decision to facilitate a transaction from or to Bitcoin must take into
account sanctioned addresses.

## Checking if an address is sanctioned

Each member of the committee might have different risk tolerances or policies
for which set of addresses they do not want to serve. To accommodate different
validator preferences, the Hashi node software has a configurable mechanism
for determining whether servicing a particular address should be denied.

## Screening with TRM Labs

Each node operator screens with their own [TRM Labs](https://www.trmlabs.com)
account: create an API key in the TRM platform under **Settings > API Tokens**
and set it as `trm-api-key` in the node config. Without a key, the node does
not screen. TRM only covers mainnet, so the key is ignored on other networks.

| Flow       | What the node screens                            | TRM API                                                  |
| ---------- | ------------------------------------------------ | -------------------------------------------------------- |
| Deposit    | The Bitcoin transaction into the deposit address | Transaction Monitoring (`POST /public/v2/tm/transfers`)  |
| Deposit    | The Sui address credited with `hBTC`             | Wallet Screening (`POST /public/v2/screening/addresses`) |
| Withdrawal | The Bitcoin destination address                  | Wallet Screening                                         |
| Withdrawal | The Sui address that requested the withdrawal    | Wallet Screening                                         |

A node does not vote for a deposit or withdrawal when:

- TRM attributes a screened address itself (risk type `OWNERSHIP`) to a
  category scored High or Severe. Exposure only through counterparties or
  intermediaries does not count.
- The deposit's transfer raises an alert at High or Severe. Alerts come from
  the Transaction Monitoring rules each operator configures in their TRM
  account.
- TRM cannot screen the transfer, or rejects the request.

Transaction Monitoring is asynchronous. A node waits up to 10 seconds for TRM
to finish screening a deposit's transfer; if TRM is still processing it, the
node declines the deposit for now and the leader retries on the next Bitcoin
block. Timeouts, rate limits and TRM server errors are also retried, and the
node does not vote in the meantime. TRM can still alert on a transfer after
the committee approves the deposit; hashi does not revisit an approval.

## When sanctions checks apply

**Deposits**: When a user submits a deposit request, their request sits in a
queue or waiting room until the validators vote on accepting that deposit
and minting an appropriate amount of `hBTC`. Sanctions checking happens at
the time a validator decides whether to vote for accepting a deposit. If a
validator decides that it does not want to service that deposit, it does not
vote for it and ignores that the deposit exists. If a quorum decides to
accept a deposit that a particular validator did not want to accept, per
protocol the validator must recognize (and subsequently make use of) the
deposited BTC.

**Withdrawals**: When a user submits a withdraw request, their request sits
in a queue or waiting room until the validators pick it up for processing.
Before selecting a request for processing, the validators vote on approving
the request. One of the required checks as part of voting for approval is
performing sanctions checking. After a quorum of validators has voted to
approve a request, it can be picked up for processing. If a quorum decides
to approve a request for processing, per protocol all validators must
assist in driving the request to completion.

## Tainted UTXOs

The Hashi protocol implements rigorous sanctions enforcement, but enforcement
is ultimately best-effort. A quorum of validators might accept a deposit that
one validator preferred to not accept, or a previous committee accepted a
deposit that the current committee would have rejected. In either case, after
a UTXO is accepted into Hashi's pool, the protocol treats it as its own, and
it must be available during coin selection to process withdraw requests.
