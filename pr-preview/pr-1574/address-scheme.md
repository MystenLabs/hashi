# Bitcoin Address Scheme

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> Hashi derives a unique Bitcoin Taproot deposit address for every Sui address using a 2-of-2 multisig between the MPC committee and the Guardian, plus a delayed MPC-only recovery path.

Every Sui address has its own unique Hashi Bitcoin deposit address. This gives
Hashi a lightweight way to identify which Sui address to credit for a deposit.
All Hashi deposit addresses are `P2TR` (Pay-to-Taproot) with a Taproot tree of
two leaves:

1. A 2-of-2 multisig script between Hashi and the Guardian, used for all
   normal spends.
2. A recovery script that lets the Hashi key alone spend the output after a
   60-day BIP-68 relative timelock enforced by `OP_CHECKSEQUENCEVERIFY`
   (BIP-112). This is an
   escape hatch: if the Guardian key is ever lost, funds become recoverable by
   the MPC committee once the delay elapses. The delay is measured from when
   the UTXO confirms and is baked into the script, so changing it changes
   every deposit address.

## What is the exact descriptor?

The exact [descriptor](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
is:

```
tr({i}, {multi_a(2, {g}, {h}), and_v(v:older({delay}), pk({h}))})
```

where:

- `H` is the base Hashi MPC public key, available onchain.
- `h = derive(H, d)` is the child public key derived from `H` using
  derivation path `d` (the depositor's Sui address).
- `g` is the guardian's fixed public key.
- `delay` is the 60-day relative timelock, encoded as the BIP-68 sequence
  `0x0040278D` (`4_204_429`).
  [How is the 60-day delay encoded?](#how-is-the-60-day-delay-encoded) breaks
  down the encoding step by step.
- `i` is the NUMS (nothing-up-my-sleeve) internal key defined in BIP-341
  (`50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`)
  with no known private key, ensuring all spends occur through the script path.

Read left to right, the descriptor says: the Taproot internal key is `i`, and
the tree has 2 script leaves. `multi_a(2, {g}, {h})` is the 2-of-2 multisig
leaf, which needs signatures from both the guardian key `g` and the child MPC
key `h`. `and_v(v:older({delay}), pk({h}))` is the recovery leaf, which needs
the `delay` to have elapsed and a signature from `h` alone.

## How is the 60-day delay encoded?

Use the BIP-68 sequence value `0x0040278D` (`4_204_429`) for `delay`. To build
the value:

1. Express 60 days in seconds: `60 * 24 * 60 * 60` = `5_184_000`.
2. Convert to 512-second units, rounding up:
   `ceil(5_184_000 / 512)` = `10_125`. This is a count of 512-second units in
   60 days, not a count of blocks.
3. OR in the time-based type bit, `1 << 22` (`4_194_304`):
   `4_194_304 | 10_125` = `4_204_429` = `0x0040278D`.

## How is a deposit address derived from a Sui address?

To derive the deposit address for a Sui address:

1. Take the depositor's Sui address as the derivation path `d`.
2. Derive the child public key `h = derive(H, d)` from the base Hashi MPC
   public key `H`, which is available onchain.
3. Substitute `h`, the guardian's public key `g`, the encoded `delay`, and the
   NUMS internal key `i` into the descriptor above.

The resulting P2TR address is the deposit address for that Sui address. Hashi
credits any deposit to it to that Sui address.

The key derivation is not BIP-32. It is a purpose-built unhardened derivation
over secp256k1, keyed by the Sui address, giving each depositor a unique
Bitcoin address while the master signing key remains shared across the MPC
committee.

## How does withdrawal funding treat older deposit UTXOs?

Normal withdrawal funding remains largest-first. Within the existing
fee-eligible consolidation budget, confirmed UTXOs older than 4,320 blocks are
prioritized before ordinary smallest-first candidates. The 4,320-block
threshold estimates 30 days using Bitcoin's ten-minute block target; actual
MPC-only recovery eligibility remains governed by the time-based CSV script
above.
