# Configuration

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> Onchain configuration parameters that control Hashi's deposit, withdrawal, fee, and operational behavior.

Hashi keeps its onchain configuration in two key-value stores on the `Hashi`
object, distinguished by when a change takes effect:

- **Instant config** (`config`): values apply the moment the proposal that
  changes them executes. Deposit and withdrawal minimums, the confirmation
  threshold, the pause flag, and the guardian settings live here.
- **Epoch config** (`epoch_config`): the whole store is copied onto the
  committee formed at each reconfiguration, and nodes read these values from
  their committee's pinned copy. A change lands in the next committee formed
  after the proposal executes and never alters the active committee. The MPC
  parameters live here.

Existing parameters are tuned with `UpdateConfig` (instant) and
`UpdateEpochConfig` (epoch). Both require 2/3 of committee weight, accept only
keys that already exist in their store, and reject a change of value type. New
keys are introduced with `AddConfig`, which names the store and is insert-only
(see [Adding a parameter](#adding-a-parameter-without-a-package-upgrade) and
[Governance Actions](governance-actions.mdx)).

## Parameters

### `bitcoin_deposit_minimum`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `30000` |
| **Unit** | satoshis |
| **Floor** | `546` (dust relay minimum) |

The minimum deposit amount in satoshis. Deposits below this value are rejected
onchain. The effective value is always at least `546 sats` to prevent creating
unspendable UTXOs.

### `bitcoin_deposit_time_delay_ms`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `600000` (10 minutes) |
| **Unit** | milliseconds |

The minimum time that must elapse between a deposit being approved by the
committee (`approve_deposit`) and being confirmed (`confirm_deposit`). Provides
a window in which a fraudulent or erroneous approval can be detected and the
service paused before any `hBTC` is minted. See the
[deposit flow](deposit.mdx#confirm) for how this delay fits into the overall
process.

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
Requests already in the queue remain queued and resume processing when the
system is unpaused. Reconfiguration and governance actions are not affected.

### `withdrawal_cancellation_cooldown_ms`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `3600000` (1 hour) |
| **Unit** | milliseconds |

The minimum time a withdrawal request must remain in the queue before the user
can cancel it. Prevents users from using rapid submit-cancel cycles to
interfere with processing.

### `governance_emergency_pause_threshold_bps`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `500` (5%) |
| **Unit** | basis points of committee voting weight |

The vote threshold for an emergency **pause** proposal. Deliberately low so a
small fraction of the committee can quickly halt deposit and withdrawal
processing when something looks wrong.

### `governance_emergency_unpause_threshold_bps`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `6667` (two thirds) |
| **Unit** | basis points of committee voting weight |

The vote threshold for the **unpause** variant of the same proposal. Resuming
operation requires a supermajority.

## MPC parameters

The MPC parameters live in the epoch config and are tuned with
`UpdateEpochConfig`. The store is pinned onto each committee at
reconfiguration, so a change mid-epoch never affects the active committee; new
values take effect when the next committee forms.

### `mpc_max_faulty_in_basis_points`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `3333` |
| **Valid range** | `1` to `3333` |
| **Unit** | basis points of committee voting weight |

The assumed upper bound on faulty (offline or adversarial) committee weight.
MPC protocol parameters are derived under the assumption that at most this
fraction of weight misbehaves.

### `mpc_weight_reduction_allowed_delta`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `800` |
| **Valid range** | `0` to `10000` |
| **Unit** | basis points |

Committee voting weights are proportionally reduced (compressed) before the
MPC protocol runs, because each unit of weight corresponds to a share and
protocol cost scales with total shares. Reduction necessarily distorts
relative voting power; this parameter bounds the distortion, allowing the
effective fault-tolerance assumption to shift by at most this many basis
points relative to the unreduced committee. `0` disables weight reduction,
so parties keep their full committee weights.

### `mpc_nonce_generation_protocol`

| | |
|---|---|
| **Type** | `u64` |
| **Default** | `0` |
| **Valid values** | `0` (vanilla), `1` (AVID) |

Selects the protocol the committee uses to generate signing nonces
(presignatures): `0` is the original protocol, `1` enables AVID-based nonce
generation.

## Read-only or genesis-only parameters

### `bitcoin_chain_id`

| | |
|---|---|
| **Type** | `address` |

The 32-byte Bitcoin chain identifier as defined by
[BIP-122](https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki)
(the genesis block hash). Set at genesis and not updatable through the
`UpdateConfig` proposal.

### `guardian_btc_public_key`

| | |
|---|---|
| **Type** | `bytes` |

The guardian's x-only BTC public key (32 bytes), pinned at genesis. Every
2-of-2 deposit address is derived against it, so it is write-once and not
updatable through the `UpdateConfig` proposal. The guardian URL
(`guardian_url`) remains governable.

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

The maximum miner fee the contract accepts for a withdrawal transaction,
derived from `bitcoin_withdrawal_minimum` minus the dust threshold. With
defaults: `30,000 - 546 = 29,454 sats`.

## Adding a parameter without a package upgrade

The Move package reads only the keys documented on this page; any other key
is opaque to it and is consumed by the node software. To make a node-side
setting governable, pass an `AddConfig` proposal naming the key, its initial
value (which fixes the key's type for later updates), and the store: the epoch
config when every node must agree on the value for the whole epoch, the
instant config otherwise. A node reads an absent key as its built-in default,
so the key can be added before or after the node release that consumes it.
