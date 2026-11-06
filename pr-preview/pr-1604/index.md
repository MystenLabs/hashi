# Introduction

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> Overview of Hashi, the Sui native Bitcoin orchestrator that secures BTC for use on Sui through threshold cryptography and represents it as hBTC.

Hashi is the Sui native Bitcoin orchestrator. It secures native BTC for use
on Sui and represents that BTC onchain as `hBTC`. This documentation is the
canonical description of Hashi's design, how it operates, and how to
use, integrate, and run it.

## What is Hashi?

Hashi is a protocol that lets you move BTC onto Sui and back without handing
your coins to a single custodian. A committee drawn from the Sui validator
set holds the BTC in a shared pool and signs Bitcoin transactions together
using a threshold Multi-Party Computation (MPC) protocol. No single member
holds the signing key, and the key moves to each new committee as the Sui
validator set changes.

A second, independent signer called the Guardian co-signs every withdrawal
from inside a cloud enclave. Every deposit address requires both the committee
and the Guardian to spend it, so a compromised committee cannot move funds on
its own. See [Guardian](guardian.mdx) and
[Bitcoin Address Scheme](address-scheme.mdx) for the details.

## How does Hashi manage Bitcoin on Sui?

Hashi supports 2 flows, deposit and withdraw:

- **Deposit:** Every Sui address has its own unique Bitcoin deposit address.
  You send BTC to yours, then tell Hashi about the transaction on Sui. After
  the committee confirms the deposit on Bitcoin, Hashi mints an equal amount
  of `hBTC` to your Sui address.
- **Withdraw:** You submit `hBTC` and a destination Bitcoin address on Sui.
  Hashi burns the `hBTC`, builds a Bitcoin transaction from its pool, signs it
  with the committee and the Guardian, and broadcasts it.

Deposits are free and withdrawals pay only the Bitcoin miner fee. There is no
protocol fee. See [User Flows](user-flows.mdx) for the end-to-end picture and
[Fees](fees.mdx) for the numbers.

## What is hBTC?

`hBTC` is a fungible `Coin<BTC>` on Sui that Hashi mints on deposit and burns
on withdrawal. Each `hBTC` corresponds to BTC that the committee and Guardian
hold in the Hashi pool. Because `hBTC` is a standard Sui coin, you can use it
in any Sui app, for example as collateral in a lending protocol.

:::info

`hBTC` is the only coin Hashi creates. There is no HASHI governance, utility,
or airdrop token. Committee members govern the protocol by voting onchain with
their validator stake weight. Treat any HASHI token offering, presale, or
airdrop as an imitation.

:::

## Where do I start?

The documentation has 5 sections. Choose the one that matches what you want
to do:

- **hBTC:** Move BTC in and out. Start with [User Flows](user-flows.mdx),
  then follow [Deposit BTC](hbtc/deposit.mdx),
  [Withdraw BTC](hbtc/withdraw.mdx), and
  [Cancel a Withdrawal](hbtc/cancel.mdx), and check the
  [hBTC FAQ](hbtc/faq.mdx).
- **Protocol:** How Hashi works. Start with the architecture pages, then
  read the [Deposit](deposit.mdx) and [Withdraw](withdraw.mdx) lifecycles, [Reconfiguration](reconfiguration.mdx),
  governance, security, and [Fees](fees.mdx).
- **Integration:** Build on Hashi with the [TypeScript SDK](ts-sdk.mdx).
- **Validators:** Join the committee and run a node. Start with the
  [Run a Hashi Node](validators/index.mdx) and keep
  [Hashi Node Backups](node-backup.mdx) nearby.
- **Reference:** Onchain [configuration parameters](config.mdx), plus the
  Move package, the gRPC API, and the Rust API.
