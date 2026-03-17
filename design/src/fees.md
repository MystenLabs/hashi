# Fees

Hashi charges two kinds of fees: a flat **deposit fee** paid in `SUI`, and
a **withdrawal fee** paid in `BTC`. Both are governance-configurable. In
addition to the protocol fee, every withdrawal absorbs the Bitcoin
**miner fee** required to get the transaction confirmed on-chain.

## Deposit fee

Deposits pay a flat `SUI` fee at request time (`deposit_fee` config key,
initially `0 SUI`). The fee must match exactly; it is transferred to
the Hashi balance on Sui. Deposits must also meet the dust minimum 
(`546 sats`) to avoid creating unspendable UTXOs on Bitcoin.

## Withdrawal fees

Withdrawal fees have two components that serve different purposes:

1. **Protocol fee** (`withdrawal_fee_btc`, initially `546 sats`) -- a
   flat `BTC` amount deducted upfront when the user submits a withdrawal
   request. This fee is non-refundable and goes to the Hashi treasury.
   It covers protocol operating costs and deters spam. The floor is
   the dust relay minimum (`546 sats`) to prevent misconfiguration.

2. **Miner fee** -- the actual Bitcoin transaction fee required for
   on-chain confirmation. This is not a fixed value; it depends on the
   current network fee rate and the transaction's weight. The user
   pays this fee through a reduction in their withdrawal output
   amount.

### Why the user pays the miner fee

The UTXO pool belongs to the protocol. If the pool absorbed miner fees,
every withdrawal would shrink the pool by more than the withdrawn
amount, effectively socializing costs across all future users. Shifting
the miner fee to the withdrawing user keeps the pool whole: the
invariant `input_total = user_output + change` holds, so the change
output that returns to the pool is undiminished.

### Withdrawal minimum

The protocol enforces a minimum withdrawal amount to guarantee
that every request can produce a valid Bitcoin transaction even under
worst-case fee conditions:

```
withdrawal_minimum = withdrawal_fee_btc
                   + worst_case_network_fee
                   + DUST_RELAY_MIN_VALUE
```

- `withdrawal_fee_btc` is the protocol fee deducted upfront.
- `worst_case_network_fee` is the maximum miner fee the protocol would
  ever charge (see below).
- `DUST_RELAY_MIN_VALUE` (`546 sats`) ensures the user's output remains
  above Bitcoin's dust threshold after all deductions.

This means a user who withdraws exactly the minimum will, in the worst
case, receive a `546 sats` output. In practice, actual miner fees are
usually well below the worst case, so the user receives more.

## Fee rate estimation

Hashi obtains the current fee rate from the connected Bitcoin Core
node via `estimatesmartfee`, targeting confirmation within 3 blocks
(~30 minutes).

The estimated fee rate is then capped at the governance-configured
`max_fee_rate` (initially `25 sat/vB`). This cap serves two purposes:

- It bounds the miner fee the user can be charged, ensuring it stays
  within the worst-case budget the Move contract computed at request
  time.
- It prevents a single fee spike from producing unexpectedly expensive
  withdrawals.

## Worst-case network fee

Every withdrawal is required to cover not just its own on-chain
footprint but also a share of UTXO pool maintenance. At minimum, a
withdrawal must pay for the fixed transaction overhead, its own
recipient output, and a change output back to the pool. On top of
that, the protocol requires each withdrawal to budget for up to
`input_budget` input weights. This headroom allows the coin selector to
consolidate many small UTXOs into fewer large ones during normal
withdrawal traffic -- a form of opportunistic UTXO smashing that keeps
the pool healthy without requiring dedicated consolidation
transactions.

The Move contract and the Rust validator both compute this worst-case
miner fee using conservative transaction size estimates:

```
tx_vbytes    = TX_FIXED_VB + (input_budget * INPUT_VB) + (OUTPUT_BUDGET * OUTPUT_VB)
network_fee  = max_fee_rate * tx_vbytes
```

The constants assume a taproot script-path 2-of-2 spend (the heaviest
input type Hashi uses):

| Constant      | Value       | Rationale                                        |
|---------------|-------------|--------------------------------------------------|
| `TX_FIXED_VB` | `11 vB`     | nVersion (4) + nLockTime (4) + varint counts (3) |
| `INPUT_VB`    | `100 vB`    | 2-of-2 taproot script-path input (398 WU / 4)    |
| `OUTPUT_VB`   | `43 vB`     | P2TR output (172 WU / 4)                          |
| `OUTPUT_BUDGET` | `2`         | One recipient output + one change output          |
| `input_budget`  | `10`        | Per-request worst case, governance-configurable   |
| `max_fee_rate`| `25 sat/vB` | Governance-configurable (initially 25)            |

With defaults: `(11 + 10*100 + 2*43) * 25 = 27,425` sats.

These estimates are intentionally pessimistic. Most transactions use
fewer inputs and pay a lower fee rate, so the actual miner fee is
usually a fraction of the worst case. The difference stays in the
user's output -- users are only charged for the real transaction
weight, not the worst-case budget.

## Transaction validation fee bounds

When validators verify a proposed withdrawal transaction, they check
the fee from two directions:

- **Floor**: the fee must be at least `1 sat/vB` (the minimum relay fee),
  or the Bitcoin network will not propagate the transaction.
- **Ceiling**: the fee must not exceed 3x the validator's own fee
  estimate for the same transaction weight. This prevents a malicious
  leader from overpaying fees to extract value from users.
- **Per-user cap**: the per-user share of the miner fee must not exceed
  the worst-case network fee computed from the on-chain config. This
  ensures the Move contract's upfront minimum calculation was
  sufficient.

## Stuck transactions

Hashi does not attempt to replace stuck transactions with higher-fee
replacements (RBF). Instead, if a transaction is not confirmed within
a reasonable time, fee bumping relies on CPFP (child pays for parent):

- The withdrawal recipient can spend their output with a high-fee
  child transaction.
- Hashi can spend the change UTXO that returned to the pool, which
  also bumps the parent.
