# Fees

Hashi charges two kinds of fees: a flat **deposit fee** paid in `SUI`, and
a **withdrawal fee** paid in `BTC`. Both are governance-configurable. In
addition to the protocol fee, every withdrawal absorbs the Bitcoin
**miner fee** required to get the transaction confirmed on-chain.

## Deposits

Deposits are free. They must meet the configurable
`bitcoin_deposit_minimum` (initially `30,000 sats`).

## Withdrawal fees

The only fee a user pays on withdrawal is the **miner fee** -- the
actual Bitcoin transaction fee required for on-chain confirmation. This
is not a fixed value; it depends on the current network fee rate and
the transaction's weight. The user pays this fee through a reduction in
their withdrawal output amount. There is no protocol fee.

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
bitcoin_withdrawal_minimum = worst_case_network_fee + DUST_RELAY_MIN_VALUE
```

- `worst_case_network_fee` is the maximum miner fee the protocol would
  ever charge (see below).
- `DUST_RELAY_MIN_VALUE` (`546 sats`) ensures the user's output remains
  above Bitcoin's dust threshold after the miner fee deduction.

This means a user who withdraws exactly the minimum will, in the worst
case, receive a `546 sats` output. In practice, actual miner fees are
usually well below the worst case, so the user receives more.

## Fee rate estimation

Hashi obtains the current fee rate from the connected Bitcoin Core
node via `estimatesmartfee` in `ECONOMICAL` mode, targeting
confirmation within `withdrawal_fee_conf_target` blocks (default `3`,
~30 minutes). Low-traffic chains like signet may need a higher target
to route the estimator to its long-horizon bucket.

The estimated fee rate is then capped at a high fee rate threshold
(30 sat/vB by default). This prevents a single fee spike from
producing unexpectedly expensive withdrawals. The per-user miner fee
is additionally bounded by the on-chain `worst_case_network_fee` cap.

## Worst-case network fee

Every withdrawal is required to cover not just its own on-chain
footprint but also a share of UTXO pool maintenance. At minimum, a
withdrawal must pay for the fixed transaction overhead, its own
recipient output, and a change output back to the pool. The
additional headroom allows the coin selector to consolidate many
small UTXOs into fewer large ones during normal withdrawal traffic --
a form of opportunistic UTXO smashing that keeps the pool healthy
without requiring dedicated consolidation transactions.

The worst-case miner fee per withdrawal is derived from the
governance-configured `bitcoin_withdrawal_minimum` parameter:

```
worst_case_network_fee = bitcoin_withdrawal_minimum - DUST_RELAY_MIN_VALUE
```

With defaults: `30,000 - 546 = 29,454` sats.

The actual miner fee is usually well below the worst case. Users are
only charged for the real transaction weight, not the worst-case
budget -- the difference stays in the user's output.

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
