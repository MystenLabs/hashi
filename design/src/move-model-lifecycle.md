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
            DR["DepositRequest<br/>{ id, utxo, timestamp_ms }"]
            DRQ["DepositRequestQueue<br/>.requests"]
        end

        subgraph ConfirmPhase["2. Confirmation Phase"]
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
    CERT -->|"confirm_deposit()"| VERIFY
    VERIFY -->|"Valid certificate"| CERTIFIED
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

| Step | Action                                     | Model Transformation                                        |
| ---- | ------------------------------------------ | ----------------------------------------------------------- |
| 1    | User sends BTC to bridge address           | Bitcoin UTXO created                                        |
| 2    | User calls `deposit()`                     | `DepositRequest` → `DepositRequestQueue`                    |
| 3    | Committee members observe and sign request | BLS signatures aggregated → `CommitteeSignature`            |
| 4    | Leader calls `confirm_deposit()` with cert | `verify_certificate()` → `CertifiedMessage<DepositRequest>` |
| 5    | Certified request processed                | `DepositRequest` → `Utxo` in `UtxoPool`                     |
| 6    | Treasury mints tokens                      | `Utxo.amount` → `Balance<BTC>` to user                      |

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
            PW["PendingWithdrawal<br/>{ request, picked_utxos,<br/>witness_signatures }"]
            PWQ["WithdrawalQueue<br/>.pending_withdrawals"]
        end

        subgraph SignPhase["3. Signature Storage Phase"]
            SUBMIT_SIGS["submit_withdrawal_signatures()<br/>Store witness sigs on-chain"]
            PW_SIGNED["PendingWithdrawal<br/>(with witness_signatures)"]
        end

        subgraph ConfirmPhase["4. Confirmation Phase"]
            CERTIFIED2["CertifiedMessage&lt;Confirmation&gt;"]
            DEL["Delete PendingWithdrawal"]
            RECORD["Record withdrawn UTXOs<br/>(replay prevention)"]
        end
    end

    subgraph Committee["Hashi Protocol Committee"]
        MEMBERS2["Committee Members<br/>(Sui Validators)"]
        VOTE["Vote to process withdrawal<br/>& select UTXOs"]
        MPC["MPC Signing Protocol"]
        SIGN2["Aggregate BLS Signatures"]
        CERT2["CommitteeSignature"]
    end

    subgraph Bitcoin["Bitcoin Network"]
        BTC_TX["Bitcoin Transaction<br/>(signed via MPC)"]
        BTC_UTXO["Bitcoin UTXO<br/>(at destination)"]
    end

    BAL -->|"User deposits<br/>Balance&lt;BTC&gt;"| WR
    WR -->|"request_withdraw()"| WRQ
    WRQ -.->|"Observe request"| MEMBERS2
    MEMBERS2 --> VOTE
    VOTE -.->|"Select UTXOs<br/>(off-chain)"| UTXO_POOL
    VOTE --> BURN
    BURN -->|"Balance&lt;BTC&gt; burned"| PW
    PW --> PWQ
    PWQ -.->|"Observe pending<br/>withdrawals queue"| MPC
    MPC -->|"Schnorr signatures<br/>per input"| SUBMIT_SIGS
    SUBMIT_SIGS -->|"witness_signatures<br/>stored on-chain"| PW_SIGNED
    PW_SIGNED -->|"Reconstruct & broadcast<br/>signed BTC tx"| BTC_TX
    BTC_TX --> BTC_UTXO
    BTC_UTXO -.->|"Observe confirmation<br/>(N confirmations)"| SIGN2
    SIGN2 --> CERT2
    CERT2 -->|"confirm_withdraw()"| CERTIFIED2
    CERTIFIED2 --> DEL
    DEL --> RECORD

    style Bitcoin fill:#f7931a,color:#fff
    style Committee fill:#E91E8A,color:#fff
    style Sui fill:#4da2ff,color:#fff
    style BAL fill:#00d4aa,color:#000
    style BTC_UTXO fill:#f7931a,color:#fff
    style CERT2 fill:#E91E8A,color:#fff
    style CERTIFIED2 fill:#00d4aa,color:#000
    style PW_SIGNED fill:#00d4aa,color:#000
```

> **Note:** The Bitcoin confirmation threshold is stored on-chain in config key `bitcoin_confirmation_threshold` (default `1`, will be set to `6` before mainnet). Witness signatures are stored on-chain so that any leader can reconstruct and re-broadcast the signed Bitcoin transaction without MPC re-signing (e.g., after leader rotation or mempool eviction).

### Withdrawal Flow Summary

| Step | Action                                       | Model Transformation                                             |
| ---- | -------------------------------------------- | ---------------------------------------------------------------- |
| 1    | User requests withdrawal                     | `Balance<BTC>` → `WithdrawRequest` → `WithdrawalQueue.requests`  |
| 2    | Committee votes & selects UTXOs              | Quorum votes, reads `UtxoPool` (off-chain) to select UTXOs       |
| 3    | Leader processes request                     | `Balance<BTC>` burned, `PendingWithdrawal` created               |
| 4    | MPC protocol signs Bitcoin transaction       | Committee collectively signs via MPC using selected UTXOs        |
| 5    | Leader stores witness signatures on-chain    | `submit_withdrawal_signatures()` → `PendingWithdrawal` updated   |
| 6    | BTC transaction broadcast (and re-broadcast) | Signed tx reconstructed from on-chain data, broadcast to Bitcoin |
| 7    | Committee signs confirmation certificate     | `CommitteeSignature` created after BTC tx confirmed              |
| 8    | Leader confirms withdrawal                   | `CertifiedMessage` verified, `PendingWithdrawal` deleted         |
| 9    | Record withdrawn UTXOs                       | Spent UTXOs recorded for replay prevention                       |

---

## Key Models Reference

| Model                 | Location                              | Description                                                            |
| --------------------- | ------------------------------------- | ---------------------------------------------------------------------- |
| `Balance<BTC>`        | User wallet                           | Wrapped BTC token on Sui                                               |
| `DepositRequest`      | `DepositRequestQueue`                 | Pending deposit awaiting committee confirmation                        |
| `Utxo`                | `UtxoPool`                            | On-chain representation of a Bitcoin UTXO                              |
| `WithdrawRequest`     | `WithdrawalQueue.requests`            | User's withdrawal request with destination                             |
| `PendingWithdrawal`   | `WithdrawalQueue.pending_withdrawals` | Withdrawal being processed, stores picked UTXOs and witness signatures |
| `Bitcoin UTXO`        | Bitcoin Network                       | Actual unspent transaction output on Bitcoin                           |
| `Committee`           | `CommitteeSet`                        | BLS signing committee of Sui validators for an epoch                   |
| `CommitteeMember`     | `Committee.members`                   | Validator with public_key and voting weight                            |
| `CommitteeSignature`  | Transaction input                     | Aggregated BLS signature with signers bitmap                           |
| `CertifiedMessage<T>` | Verified on-chain                     | Message proven to have committee quorum support                        |
