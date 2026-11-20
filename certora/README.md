# Certora Formal Verification

Formal verification of the Hashi package (`packages/hashi`) with the Certora Sui Prover. The specs are CVLM (Move). They check the on-chain deposit, withdrawal, solvency, proposal, and reconfiguration logic.

## Folder structure

```
certora/
├── confs/          # Prover configuration. One *_full.conf per spec package,
│                   # plus one conf per property.
├── specs/          # CVLM spec packages: deposit, withdraw, proposal, solvency
├── patches/        # Visibility patches applied to packages/hashi before a run
└── README.md
```

`packages/hashi` stays unchanged in git. `patches/apply_patches.sh` widens a few accessors to `public` so a spec package can read them, and switches `Move.toml` to the legacy dependency style the prover needs. `patches/revert_patches.sh` puts the package back.

## Properties verified

### Solvency

- **Peg** — deposit and withdrawal entry points never shrink the gap between BTC held by the pool and hBTC supply (`solvency.conf`)
- **Frame** — entry points that must not mint, burn, or move the pool leave both sides unchanged (`constant_btc_hbtc.conf`)

### Deposits

- **State machine** — a request is created unapproved, approval sticks, and confirmation implies a prior approval (`deposit_state_machine.conf`)
- **Integrity** — confirmation happens at most once, needs a prior approval, and the pool rejects a duplicate or already-spent UTXO
- **One request per id** — the three deposit queues stay disjoint (`deposit_queue_mutual_exclusion.conf`)
- **Gates** — deposit entry points require the package unpaused, not reconfiguring, and the version enabled (`deposit_gate_checks.conf`)

### Withdrawals

- **Request lifecycle** — approval, commitment, and archival move in one direction (`withdraw_state_machine.conf`)
- **Transaction lifecycle** — a withdrawal transaction is created unsigned, then signed, then confirmed, at most once
- **One id per queue** — withdrawal requests and transactions are not duplicated (`withdraw_queue_mutual_exclusion.conf`)
- **Gates** — the same pause, reconfiguration, and version checks as deposits (`withdraw_gate_checks.conf`)

### Proposals and reconfiguration

- **Proposal integrity** — thresholds, expiry, vote records, and the executed flag match the code (`proposals_integrity.conf`)
- **One proposal per id** (`proposals_mutual_exclusion.conf`)
- **Proposal lifecycle** — create, vote, execute, and delete-expired move a proposal between the active and executed bags (`proposals_state_machine.conf`)
- **Reconfiguration** — start, handoff, end, and abort follow the idle/busy machine, and end is the only step that advances the epoch (`reconfig_state_machine.conf`, `reconfig_integrity.conf`)

Each `*_full.conf` runs every rule of one spec package, including the `target_sanity()` rules. The property confs above are the same rules split by property.

## Prerequisites

```bash
pip install certora-cli
export CERTORAKEY=<your-api-key>
```

The `sui` CLI has to be on `PATH`. The prover compiles the spec package itself.

## Running the prover

From the repository root:

```bash
bash certora/patches/apply_patches.sh
cd certora
certoraSuiProver confs/deposit_full.conf --server production
```

Run one rule by passing its fully qualified name. The flag replaces the conf's rule list:

```bash
certoraSuiProver confs/deposit_full.conf \
  --rule deposit::deposit_unpaused::deposit_is_unpaused \
  --server production
```

The other package runs are `confs/withdraw_full.conf`, `confs/proposal_full.conf`, and `confs/solvency_full.conf`. A property conf, for example `confs/solvency.conf`, runs only that property.

Both `override_base_config` and `spec_package_path` are resolved from the current directory, so the command has to run inside `certora/`.

Restore the package when you are done:

```bash
bash certora/patches/revert_patches.sh
```

## Continuous integration

`.github/workflows/certora.yml` runs the four `*_full.conf` files on pull requests that touch `packages/hashi`, `certora/`, or the workflow itself. Each job submits to the Certora cloud and waits for the result.

The workflow checks `secrets.CERTORAKEY` first. With no key it skips and stays green, so the file can land before the key exists. A violating rule fails the job once the key is set.
