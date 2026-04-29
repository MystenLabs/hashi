# Configuration

Hashi maintains a set of on-chain configuration parameters stored in the
`Config` object. These parameters control protocol behavior for deposits,
withdrawals, fee estimation, and system operations.

All configurable parameters can be updated via the `UpdateConfig` governance
proposal, which requires 2/3 of committee weight (see
[governance actions](./governance-actions.md)). Each key is validated against
its expected type on update.

## Parameters

### `bitcoin_deposit_minimum`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `30000` |
| **Unit** | satoshis |
| **Floor** | `546` (dust relay minimum) |

The minimum deposit amount in satoshis. Deposits below this value are rejected
on-chain. The effective value is always at least `546 sats` to prevent creating
unspendable UTXOs.

### `bitcoin_withdrawal_minimum`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `30000` |
| **Unit** | satoshis |
| **Floor** | `547` (dust relay minimum + 1) |

The minimum total withdrawal amount in satoshis. The `worst_case_network_fee`
is derived as `bitcoin_withdrawal_minimum - 546`, which caps the per-user miner
fee deduction. The floor ensures the worst-case network fee is always at least
`1 sat`.

### `bitcoin_confirmation_threshold`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `6` |
| **Unit** | blocks |

The number of Bitcoin block confirmations required before a deposit is
considered final. Guards against chain reorganizations.

### `paused`

| | |
|---|---|
| **Type** | `bool` |
| **Default** | `false` |

When `true`, the protocol pauses processing of deposits and withdrawals.
Requests already in the queue remain queued and will resume processing when the
system is unpaused. Reconfiguration and governance actions are not affected.

### `withdrawal_cancellation_cooldown_ms`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `3600000` (1 hour) |
| **Unit** | milliseconds |

The minimum time a withdrawal request must remain in the queue before the user
is allowed to cancel it. Prevents users from using rapid submit-cancel cycles
to interfere with processing.

## Read-only / genesis-only parameters

### `bitcoin_chain_id`

| | |
|---|---|
| **Type** | `address` |

The 32-byte Bitcoin chain identifier as defined by
[BIP-122](https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki)
(the genesis block hash). Set at genesis and not updatable via the
`UpdateConfig` proposal.

## Derived values

Several values are computed from the configurable parameters above rather than
stored directly.

### `deposit_minimum`

```
deposit_minimum = bitcoin_deposit_minimum
```

The minimum deposit amount. With defaults: `30,000 sats`.

### `worst_case_network_fee`

```
worst_case_network_fee = bitcoin_withdrawal_minimum - 546
```

The maximum miner fee the contract will accept for a withdrawal transaction,
derived from `bitcoin_withdrawal_minimum` minus the dust threshold. With
defaults: `30,000 - 546 = 29,454 sats`.
