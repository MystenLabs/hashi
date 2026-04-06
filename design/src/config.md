# Configuration

Hashi maintains a set of on-chain configuration parameters stored in the
`Config` object. These parameters control protocol behavior for deposits,
withdrawals, fee estimation, and system operations.

All configurable parameters can be updated via the `UpdateConfig` governance
proposal, which requires 2/3 of committee weight (see
[governance actions](./governance-actions.md)). Each key is validated against
its expected type on update.

## Parameters

### `deposit_fee`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `0` |
| **Unit** | SUI (MIST) |

Flat fee in SUI charged to the user when submitting a deposit request.

### `withdrawal_fee_btc`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `546` |
| **Unit** | satoshis |
| **Floor** | `546` (dust relay minimum) |

Flat protocol fee in BTC deducted from the user's withdrawal amount upfront.
The effective value is always at least `546 sats` regardless of what is
configured, preventing misconfiguration from producing unspendable outputs.

### `bitcoin_min_withdrawal`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `27971` |
| **Unit** | satoshis |
| **Floor** | `1094` (dust relay minimum * 2) |

The minimum net withdrawal amount (after the protocol fee) in satoshis. This
flat value replaces the previous `max_fee_rate` and `input_budget` parameters
and their on-chain vbyte calculation. The `worst_case_network_fee` is derived
as `bitcoin_min_withdrawal - 546`, which caps the per-user miner fee deduction.
The effective value is always at least `1094 sats`, ensuring the worst-case
network fee is at least `546 sats`.

### `bitcoin_confirmation_threshold`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `1` (will be set to `6` before mainnet) |
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
deposit_minimum = 546 sats
```

The minimum deposit amount. Fixed at the dust relay minimum to prevent
creating unspendable UTXOs.

### `worst_case_network_fee`

```
worst_case_network_fee = bitcoin_min_withdrawal - 546
```

The maximum miner fee the contract will accept for a withdrawal transaction,
derived from the flat `bitcoin_min_withdrawal` config. With defaults:
`27,971 - 546 = 27,425 sats`.

### `withdrawal_minimum`

```
withdrawal_minimum = bitcoin_min_withdrawal + withdrawal_fee_btc
```

The minimum withdrawal amount the user must provide, covering the protocol fee
plus the net minimum. With defaults: `27,971 + 546 = 28,517 sats`.
