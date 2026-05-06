# Move Model Lifecycle

This document illustrates the lifecycle of key Move models in the deposit and withdrawal flows, showing how data structures transform between on-chain (Sui) and off-chain (Bitcoin) states.

## Deposit Flow

```mermaid
---
title: Deposit Flow - Move Model Lifecycle
---
flowchart TD
    subgraph Bitcoin["Bitcoin Network"]
        BTC_UTXO["Bitcoin UTXO<br/>(txid:vout, amount)"]
    end

    subgraph Committee["Hashi Protocol Committee"]
        MEMBERS["Committee Members<br/>(Sui Validators)"]
        SIGN["Aggregate BLS Signatures"]
        CERT["CommitteeSignature<br/>{ epoch, signature, signers_bitmap }"]
        VERIFY["verify_certificate()<br/>threshold check"]
    end

    subgraph Sui["Sui Chain"]
        subgraph DepositPhase["1. Request Phase"]
            DR["DepositRequest<br/>{ id, utxo, timestamp_ms,<br/>approval_cert, approval_timestamp_ms }"]
            DRQ["DepositRequestQueue<br/>.requests"]
        end

        subgraph ApprovePhase["2. Approval Phase"]
            APPROVED["DepositRequest (approved)<br/>approval_cert: Some(cert)<br/>approval_timestamp_ms: Some(t)"]
        end

        subgraph ConfirmPhase["3. Confirmation Phase"]
            DELAY["Time-delay window<br/>(bitcoin_deposit_time_delay_ms)"]
            CERTIFIED["CertifiedMessage&lt;DepositRequest&gt;<br/>{ message, signature, stake_support }"]
            UTXO["Utxo<br/>{ id, amount, derivation_path }"]
            POOL["UtxoPool<br/>.utxos"]
            MINT["Treasury.mint()"]
            BAL["Balance&lt;BTC&gt;<br/>(Coin sent to user)"]
        end
    end

    BTC_UTXO -->|"User creates request<br/>with UTXO info"| DR
    DR -->|"deposit()"| DRQ
    DRQ -.->|"Observe request"| MEMBERS
    MEMBERS -->|"Sign deposit request"| SIGN
    SIGN -->|"Quorum reached"| CERT
    CERT -->|"approve_deposit()"| VERIFY
    VERIFY -->|"Valid certificate"| APPROVED
    APPROVED --> DELAY
    DELAY -->|"confirm_deposit()<br/>(re-verifies cert)"| CERTIFIED
    CERTIFIED --> UTXO
    UTXO -->|"Insert"| POOL
    UTXO -->|"Extract amount"| MINT
    MINT -->|"Mint tokens"| BAL

    style Bitcoin fill:#f7931a,color:#fff
    style Committee fill:#E91E8A,color:#fff
    style Sui fill:#4da2ff,color:#fff
    style BAL fill:#00d4aa,color:#000
    style BTC_UTXO fill:#f7931a,color:#fff
    style CERT fill:#E91E8A,color:#fff
    style CERTIFIED fill:#00d4aa,color:#000
```

### Deposit Flow Summary

| Step | Action                                     | Model Transformation                                                                  |
| ---- | ------------------------------------------ | ------------------------------------------------------------------------------------- |
| 1    | User sends BTC to bridge address           | Bitcoin UTXO created                                                                  |
| 2    | User calls `deposit()`                     | `DepositRequest` → `DepositRequestQueue`                                              |
| 3    | Committee members observe and sign request | BLS signatures aggregated → `CommitteeSignature`                                      |
| 4    | Leader calls `approve_deposit()` with cert | `verify_certificate()` → request stores `approval_cert` and `approval_timestamp_ms`   |
| 5    | Time-delay window elapses                  | `bitcoin_deposit_time_delay_ms` (allows committee rotation if approval is fraudulent) |
| 6    | Anyone calls `confirm_deposit()`           | Re-`verify_certificate()` → `CertifiedMessage<DepositRequest>`                        |
| 7    | Certified request processed                | `DepositRequest` → `Utxo` in `UtxoPool`                                               |
| 8    | Treasury mints tokens                      | `Utxo.amount` → `Balance<BTC>` to user                                                |

---

## Withdrawal Flow

```mermaid
---
title: Withdrawal Flow - Move Model Lifecycle
---
flowchart TD
    subgraph Sui["Sui Chain"]
        subgraph RequestPhase["1. Request Phase"]
            BAL["Balance&lt;BTC&gt;<br/>(User's tokens)"]
            WR["WithdrawRequest<br/>{ id, amount, destination }"]
            WRQ["WithdrawalQueue<br/>.requests"]
        end

        subgraph ProcessPhase["2. Processing Phase"]
            UTXO_POOL["UtxoPool<br/>"]
            BURN["Treasury.burn()"]
            PW["WithdrawalTransaction<br/>{ id, txid, inputs, outputs,<br/>signatures }"]
            PWQ["WithdrawalRequestQueue<br/>.withdrawal_txns"]
        end

        subgraph SignPhase["3. Signature Storage Phase"]
            SUBMIT_SIGS["sign_withdrawal()<br/>Store witness sigs on-chain"]
            PW_SIGNED["WithdrawalTransaction<br/>(with signatures)"]
        end

        subgraph ConfirmPhase["4. Confirmation Phase"]
            CERTIFIED2["CertifiedMessage&lt;Confirmation&gt;"]
            MOVE_CONFIRMED["Move to .confirmed_txns"]
            RECORD["Record withdrawn UTXOs<br/>(replay prevention)"]
        end
    end

    subgraph Committee["Hashi Protocol Committee"]
        MEMBERS2["Committee Members<br/>(Sui Validators)"]
        VOTE["Vote to process withdrawal<br/>& select UTXOs"]
        VAL["validate_consume()<br/>per-node read-only<br/>seq + capacity check"]
        MPC["MPC Signing Protocol"]
        BLS_GW["Aggregate BLS cert over<br/>StandardWithdrawalRequest<br/>(wid, seq, ts, utxos)"]
        LL["LocalLimiter<br/>(per-node cache:<br/>next_seq, tokens)"]
        SIGN2["Aggregate BLS Signatures"]
        CERT2["CommitteeSignature"]
    end

    subgraph Guardian["Hashi Guardian (off-chain rate limiter)"]
        GRL["RateLimiter<br/>{ next_seq,<br/>num_tokens, last_updated }"]
        STD_RPC["StandardWithdrawal RPC<br/>verifies committee cert,<br/>consumes from limiter,<br/>returns enclave signature"]
    end

    subgraph Bitcoin["Bitcoin Network"]
        BTC_TX["Bitcoin Transaction<br/>(signed via MPC)"]
        BTC_UTXO["Bitcoin UTXO<br/>(at destination)"]
    end

    BAL -->|"User deposits<br/>Balance&lt;BTC&gt;"| WR
    WR -->|"request_withdrawal()"| WRQ
    WRQ -.->|"Observe & approve<br/>request"| MEMBERS2
    MEMBERS2 --> VOTE
    VOTE -.->|"Select UTXOs<br/>(off-chain)"| UTXO_POOL
    VOTE --> BURN
    BURN -->|"Balance&lt;BTC&gt; burned"| PW
    PW --> PWQ
    PWQ -.->|"Observe withdrawal<br/>transactions"| VAL
    LL -.->|"current next_seq,<br/>capacity"| VAL
    VAL -->|"validation passes"| MPC
    MPC -->|"Schnorr witness signatures<br/>per input"| BLS_GW
    BLS_GW -->|"finalize_withdrawal_<br/>through_guardian"| STD_RPC
    STD_RPC -->|"consume(wid, seq, ts, amt)"| GRL
    GRL -.->|"GetGuardianInfo<br/>(bootstrap only)"| LL
    BLS_GW -->|"witness signatures + cert"| SUBMIT_SIGS
    SUBMIT_SIGS -->|"signatures<br/>stored on-chain"| PW_SIGNED
    PW_SIGNED -.->|"WithdrawalSignedEvent<br/>each node's observer:<br/>apply_consume(next_seq, ts, amt)"| LL
    PW_SIGNED -->|"Reconstruct & broadcast<br/>signed BTC tx"| BTC_TX
    BTC_TX --> BTC_UTXO
    BTC_UTXO -.->|"Observe confirmation<br/>(N confirmations)"| SIGN2
    SIGN2 --> CERT2
    CERT2 -->|"confirm_withdrawal()"| CERTIFIED2
    CERTIFIED2 --> MOVE_CONFIRMED
    MOVE_CONFIRMED --> RECORD

    style Bitcoin fill:#f7931a,color:#fff
    style Committee fill:#E91E8A,color:#fff
    style Sui fill:#4da2ff,color:#fff
    style Guardian fill:#7B1FA2,color:#fff
    style BAL fill:#00d4aa,color:#000
    style BTC_UTXO fill:#f7931a,color:#fff
    style CERT2 fill:#E91E8A,color:#fff
    style CERTIFIED2 fill:#00d4aa,color:#000
    style PW_SIGNED fill:#00d4aa,color:#000
    style MOVE_CONFIRMED fill:#00d4aa,color:#000
    style GRL fill:#7B1FA2,color:#fff
    style LL fill:#E91E8A,color:#fff
```

> **Note:** The Bitcoin confirmation threshold is stored on-chain in config key `bitcoin_confirmation_threshold` (default `6`). Witness signatures are stored on-chain so that any leader can reconstruct and re-broadcast the signed Bitcoin transaction without MPC re-signing (e.g., after leader rotation or mempool eviction).
>
> **Limiter coordination.** The `LocalLimiter` on each committee node is a deterministic projection of the on-chain stream — its `next_seq` advances **only** when the node's watcher observes `WithdrawalSignedEvent` for a withdrawal. The MPC signing path uses `validate_consume` (read-only) to gate participation, never to mutate state. Because the leader's flow only reaches `sign_withdrawal()` after `finalize_withdrawal_through_guardian` returns Ok, observing the on-chain signed event is a sufficient proxy for "guardian acked" — so the local cache and the guardian stay in lockstep across leader rotation, MPC retries, and guardian-RPC failures. On startup each node bootstraps its `LocalLimiter` once via `GetGuardianInfo`.

### Withdrawal Flow Summary

| Step | Action                                       | Model Transformation                                                        |
| ---- | -------------------------------------------- | --------------------------------------------------------------------------- |
| 1    | User requests withdrawal                     | `Balance<BTC>` → `WithdrawalRequest` → `WithdrawalRequestQueue.requests`    |
| 2    | Committee approves request                   | `WithdrawalRequest` status → `Approved`                                     |
| 3    | Leader commits withdrawal tx                 | `Balance<BTC>` burned, `WithdrawalTransaction` created in `.withdrawal_txns`|
| 4    | Per-node limiter validation gates MPC        | Each node's `LocalLimiter::validate_consume(seq, ts, amt)` (read-only)      |
| 5    | MPC protocol signs Bitcoin transaction       | Committee collectively signs via MPC using selected UTXOs                   |
| 6    | Leader BLS-certs `StandardWithdrawalRequest` | Aggregated cert over `(wid, seq, ts, utxos)` — input to the guardian RPC    |
| 7    | Guardian rate-limit check + enclave sig      | `StandardWithdrawal` RPC: verify cert → `consume(wid, seq)` → `EnclaveSig`  |
| 8    | Leader stores witness signatures on-chain    | `sign_withdrawal()` → `WithdrawalTransaction` updated with signatures       |
| 9    | Each node advances its `LocalLimiter`        | Watcher observes `WithdrawalSignedEvent` → `apply_consume(seq, ts, amt)`    |
| 10   | BTC transaction broadcast (and re-broadcast) | Signed tx reconstructed from on-chain data, broadcast to Bitcoin            |
| 11   | Committee signs confirmation certificate     | `CommitteeSignature` created after BTC tx confirmed                         |
| 12   | Leader confirms withdrawal                   | `WithdrawalTransaction` moved to `.confirmed_txns`, UTXOs marked spent      |

---

## Key Models Reference

| Model                    | Location                                 | Description                                                            |
| ------------------------ | ---------------------------------------- | ---------------------------------------------------------------------- |
| `Balance<BTC>`           | User wallet                              | Wrapped BTC token on Sui                                               |
| `DepositRequest`         | `DepositRequestQueue`                    | Pending deposit awaiting committee confirmation                        |
| `Utxo`                   | `UtxoPool`                               | On-chain representation of a Bitcoin UTXO                              |
| `WithdrawalRequest`      | `WithdrawalRequestQueue.requests`        | User's withdrawal request with destination and lifecycle status        |
| `WithdrawalTransaction`  | `WithdrawalRequestQueue.withdrawal_txns` | In-flight withdrawal tx, stores inputs, outputs, and witness signatures|
| `WithdrawalTransaction`  | `WithdrawalRequestQueue.confirmed_txns`  | Confirmed withdrawal tx (historical record)                            |
| `Bitcoin UTXO`           | Bitcoin Network                          | Actual unspent transaction output on Bitcoin                           |
| `Committee`              | `CommitteeSet`                           | BLS signing committee of Sui validators for an epoch                   |
| `CommitteeMember`        | `Committee.members`                      | Validator with public_key and voting weight                            |
| `CommitteeSignature`     | Transaction input                        | Aggregated BLS signature with signers bitmap                           |
| `CertifiedMessage<T>`    | Verified on-chain                        | Message proven to have committee quorum support                        |
