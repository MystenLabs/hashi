# Hashi

Sui-native Bitcoin bridge using threshold cryptography.

[Rustdoc](https://mystenlabs.github.io/hashi/rustdoc/hashi) |
[Design Book](https://mystenlabs.github.io/hashi/design) |
[Frontend](https://devnet.hashi.sui.io)

## Overview

Hashi is a protocol for securing and managing BTC on the Sui blockchain. It enables users to deposit native Bitcoin into a managed pool and receive `hBTC` (a fungible `Coin<BTC>`) on Sui, which can be used in DeFi. When users want their BTC back, the protocol builds, signs, and broadcasts a Bitcoin transaction to return it.

The protocol is operated by a **committee** — a subset of Sui validators who run the Hashi node alongside their validator software. The committee collectively holds a shared Bitcoin key via threshold MPC (BLS12-381 for committee certificates, threshold Schnorr for Bitcoin signatures). A second signer, the **Guardian** (an AWS Nitro Enclave), forms a 2-of-2 Taproot multisig with the committee key, ensuring no single party can unilaterally spend pooled BTC.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Sui Blockchain                              │
│                                                                      │
│  ┌─────────────────────────────┐   ┌───────────────────────────────┐ │
│  │ Hashi Move Package          │   │ Hashi Shared Object (on-chain)│ │
│  │ (packages/hashi/)           │   │  - Committee & Config         │ │
│  │  deposit, withdraw, reconfig│   │  - UTXO Pool                  │ │
│  │  governance proposals       │   │  - Deposit/Withdrawal Queues  │ │
│  └──────────────┬──────────────┘   └──────────┬────────────────────┘ │
│                 │ Sui RPC                      │                     │
└─────────────────┼──────────────────────────────┼─────────────────────┘
                  │                              │
    ┌─────────────┴──────────────────────────────┴─────────────┐
    │                    Hashi Validator Nodes                   │
    │                  (crates/hashi/ binary)                    │
    │                                                           │
    │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │
    │  │ gRPC Server  │  │ MPC Protocol │  │ BTC Monitor      │ │
    │  │ (TLS, mTLS)  │  │ (DKG, Sign)  │  │ (kyoto-cbf)      │ │
    │  └──────┬───────┘  └──────────────┘  └────────┬─────────┘ │
    │         │ gRPC (BridgeService, MpcService)     │           │
    │         │ between validators                   │ JSON-RPC  │
    └─────────┼──────────────────────────────────────┼───────────┘
              │                                      │
              ▼                                      ▼
    ┌──────────────────┐                  ┌─────────────────────┐
    │ Guardian Enclave  │                  │  Bitcoin Network     │
    │ (AWS Nitro)       │                  │  (mainnet/testnet/   │
    │ GuardianService   │◄── gRPC ────────│   regtest)           │
    │ + S3 audit logs   │                  └─────────────────────┘
    └──────────────────┘

    ┌──────────────────┐       ┌──────────────────────┐
    │ Screener Service  │       │ Hashi Monitor         │
    │ (hashi-screener)  │       │ (hashi-monitor)       │
    │ AML/sanctions     │       │ Withdrawal audit      │
    │ via Merkle/TRM    │       │ E1→E2→E3 checks       │
    └──────────────────┘       └──────────────────────┘
```

**Hashi validator nodes** are Rust binaries that watch both Sui and Bitcoin, coordinate with peers via gRPC (TLS with self-signed ed25519 certs), and run the MPC signing protocol. A leader is elected per epoch to drive deposit confirmations, withdrawal batching, and Bitcoin transaction construction.

**The Guardian enclave** runs in AWS Nitro and provides the second Schnorr signature for every Bitcoin spend. It enforces rate limits and writes an immutable audit trail to S3.

**The screener** is an optional gRPC service that checks deposit and withdrawal addresses against AML/sanctions databases (MerkleScience, TRM Labs, or a static list). Each validator configures its own screening endpoint.

**The monitor** audits the withdrawal pipeline by correlating events across three systems: Sui approval (E1), Guardian approval (E2), and Bitcoin confirmation (E3).

## Security model

Hashi's trust model is built on two independent signing layers:

- **Threshold MPC committee**: A subset of Sui validators collectively hold a single Bitcoin private key via threshold Schnorr. All protocol actions (deposit confirmation, withdrawal approval, transaction signing) require a **2/3 stake-weighted quorum** of BLS signatures.
- **Guardian 2-of-2**: Every Bitcoin transaction requires signatures from *both* the MPC committee key and the Guardian key, combined in a Taproot P2TR script path. The Guardian is a hardened AWS Nitro Enclave with rate limiting and immutable S3 logging.
- **AML screening**: Before signing, each validator independently screens addresses via a configurable screener service.
- **Epoch-based key rotation**: When the Sui validator set changes at epoch boundaries, MPC key shares are redistributed from the old committee to the new one. The committee then runs a presigning protocol to pre-generate partial signatures for the epoch.

No single validator, the Guardian alone, or any external party can spend pooled BTC without committee quorum *and* Guardian co-signature.

## Repository layout

| Path | Type | Description |
|------|------|-------------|
| `crates/hashi/` | Binary + Library | Validator node and CLI. Server, MPC, gRPC services, BTC monitor, deposits, withdrawals, leader election, Sui watcher, transaction executor. |
| `crates/hashi-types/` | Library | Shared types, protobuf definitions (`.proto` files), and generated gRPC code for all services. |
| `crates/hashi-guardian-enclave/` | Binary + Library | Guardian enclave service (AWS Nitro). 2-of-2 signing, key setup, rate limiting, S3 audit logs. |
| `crates/hashi-screener/` | Binary + Library | AML/sanctions screening service. Queries MerkleScience; auto-approves non-mainnet requests. |
| `crates/hashi-monitor/` | Binary + Library | Withdrawal audit tool. Correlates E1 (Sui) → E2 (Guardian) → E3 (Bitcoin) events in batch or continuous mode. |
| `crates/e2e-tests/` | Tests + Binary | End-to-end test infrastructure. Also provides the `hashi-localnet` binary for local dev environments. |
| `crates/proto-build/` | Build tool | Compiles `.proto` files from `hashi-types` into generated Rust code. |
| `packages/hashi/` | Sui Move | On-chain smart contract: committee management, UTXO pool, deposits, withdrawals, governance, treasury. |
| `design/` | mdbook | Design documentation: committee, MPC protocol, guardian, fees, address scheme, flows. |
| `docker/` | Containers | Containerfiles for `hashi` and `hashi-screener`. |

## Move package

The on-chain state lives in a single shared `Hashi` object (`packages/hashi/sources/hashi.move`):

```move
public struct Hashi has key {
    id: UID,
    committee_set: CommitteeSet,   // Active + pending committees by epoch
    config: Config,                // Protocol parameters (fees, thresholds, pause)
    treasury: Treasury,            // BTC coin minting and burning
    deposit_queue: DepositRequestQueue,
    withdrawal_queue: WithdrawalRequestQueue,
    utxo_pool: UtxoPool,          // Tracked Bitcoin UTXOs
    proposals: Bag,                // Active governance proposals
    tob: Bag,                      // TOB certificates by (epoch, batch_index)
}
```

The package contains 24 source modules organized as:

| Area | Modules |
|------|---------|
| Core | `hashi`, `btc`, `treasury`, `threshold`, `cert_submission`, `tob` |
| Deposits | `deposit`, `deposit_queue` |
| Withdrawals | `withdraw`, `withdrawal_queue`, `utxo`, `utxo_pool` |
| Committee | `committee/committee`, `committee/committee_set`, `validator`, `reconfig`, `guardian` |
| Configuration | `config/config`, `config/config_value` |
| Governance | `proposal/proposal`, `proposal/events`, `proposal/types/upgrade`, `proposal/types/update_config`, `proposal/types/enable_version`, `proposal/types/disable_version` |

Tests live in `packages/hashi/tests/` (8 test modules).

## Protocol flows

### Deposit (BTC → hBTC)

1. User sends BTC to a Taproot deposit address derived from their Sui address and the committee+guardian keys
2. User calls `deposit()` on Sui with the UTXO details and a deposit fee in SUI
3. Validators watch Bitcoin for confirmations, screen the address, and collect BLS signatures
4. Once quorum is reached, a validator calls `confirm_deposit()` — the UTXO is added to the pool and `hBTC` is minted to the user

### Withdrawal (hBTC → BTC)

1. User calls `request_withdrawal()` with their `hBTC` balance and a destination Bitcoin address
2. Committee screens the destination, votes, and submits an approval certificate (`approve_request()`)
3. The leader batches approved requests, selects UTXOs, and proposes a Bitcoin transaction on-chain (`commit_withdrawal_tx()`)
4. The Guardian provides one Schnorr signature; the committee runs threshold signing for the second (`sign_withdrawal()`)
5. The transaction is broadcast to Bitcoin; once confirmed, the committee submits `confirm_withdrawal()` on Sui

### Reconfiguration

At each Sui epoch boundary, the committee membership may change. Hashi runs:
1. **Key rotation** — MPC key shares are redistributed from the old committee to the new one
2. **Presigning** — the new committee pre-generates partial Schnorr signatures to speed up signing during the epoch

## Getting started

### Prerequisites

- **Rust 1.91+** (pinned in `rust-toolchain.toml`)
- **cargo-nextest** — `cargo install cargo-nextest`
- **buf** — `brew install bufbuild/buf/buf` (protobuf linting/formatting)
- **Sui CLI** — `cargo install --locked --git https://github.com/MystenLabs/sui.git sui`
- **prettier-move** — `npm install -g @mysten/prettier-plugin-move` (Move formatter)
- **bitcoind** (optional) — required for e2e tests and localnet
- **mdbook + mdbook-mermaid** (optional) — required to build the design book

See the [Design Book](https://mystenlabs.github.io/hashi/design) for detailed protocol documentation.

### Building

```bash
cargo build                    # builds crates/hashi (the default member)
cargo build --workspace        # builds all crates
make proto                     # regenerate Rust code from .proto files
```

### Running locally

```bash
# Start the validator server
cargo run -- server --config path/to/config.toml

# Start a full local environment (Bitcoin regtest + Sui localnet + N validators)
cargo run -p e2e-tests --bin hashi-localnet -- start --num-validators 4
```

## Development

### Testing

```bash
make test              # all Rust tests (nextest + doc tests)
make test-move         # all Move tests
cargo nextest run -p e2e-tests  # e2e tests (requires bitcoind + sui on PATH)
```

E2E tests spin up Bitcoin regtest, Sui localnet, and multiple Hashi validator nodes. They require 4 threads per test (configured in `.config/nextest.toml`).

### Code quality

```bash
make fmt               # format Rust + protobuf + Move
make clippy            # lint
make ci                # full CI pipeline: check-fmt → buf-lint → clippy → test
```

### Protobuf workflow

Proto definitions live in `crates/hashi-types/proto/sui/hashi/v1alpha/`. After editing `.proto` files:

```bash
make proto             # compiles protos → generated Rust in hashi-types/src/proto/generated/
```

The generated code and FDS binaries must be committed.

### Localnet commands

The `hashi-localnet` binary provides additional dev utilities:

```bash
cargo run -p e2e-tests --bin hashi-localnet -- status     # show running status
cargo run -p e2e-tests --bin hashi-localnet -- info       # print connection details
cargo run -p e2e-tests --bin hashi-localnet -- mine       # mine Bitcoin blocks
cargo run -p e2e-tests --bin hashi-localnet -- faucet-sui # send SUI to an address
cargo run -p e2e-tests --bin hashi-localnet -- faucet-btc # mine BTC to an address
cargo run -p e2e-tests --bin hashi-localnet -- deposit    # execute full deposit flow
```

## gRPC services

Validators communicate over gRPC with TLS. Proto definitions are in `crates/hashi-types/proto/sui/hashi/v1alpha/`.

| Service | Description |
|---------|-------------|
| `BridgeService` | Validator-to-validator: service info, deposit confirmation, withdrawal approval, TX construction, signing, and confirmation. |
| `GuardianService` | Validator-to-Guardian: key setup, operator/provisioner init, withdrawal signing. |
| `MpcService` | MPC protocol messages: DKG, key rotation, presigning, and signing rounds. |
| `ScreenerService` | AML screening: takes an address and transaction type, returns approve/deny. |

## Configuration

The validator reads a TOML config file (`--config`). Protocol parameters live on-chain in the `Config` object and are modified through `UpdateConfig` governance proposals requiring 2/3 stake-weighted quorum.

For the full configuration reference, see `crates/hashi/src/config.rs` and the on-chain parameter definitions in `packages/hashi/sources/config/config.move`.

## Further reading

| Resource | Description |
|----------|-------------|
| [Design Book](https://mystenlabs.github.io/hashi/design) | Protocol design: committee, MPC, guardian, address scheme, fees, deposit/withdrawal/reconfiguration flows. Build locally with `make book`. |
| [Rustdoc](https://mystenlabs.github.io/hashi/rustdoc/hashi) | API documentation for all crates. Build locally with `make doc-open`. |
| [Monitor README](crates/hashi-monitor/README.md) | Withdrawal audit tool usage and E1→E2→E3 event correlation. |
| [Guardian Enclave README](crates/hashi-guardian-enclave/README.md) | Guardian service architecture and S3 logging format. |

## License

[Apache 2.0](LICENSE)
