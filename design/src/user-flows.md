# User Flows

There are two main user flows for interacting with `hashi`, deposits and
withdrawals.


## Deposit Flow

In order for a user to leverage their `BTC` on Sui (e.g. as collateral for a
loan), they'll need to deposit the `BTC` they want to leverage to a hashi mpc
controlled bitcoin address.

<div style="zoom: 1.5;">

```mermaid
---
title: Deposit Flow
config:
  sequence:
    diagramMarginX: 0
---
sequenceDiagram
    autonumber

    participant User
    participant Hashi as Sui / Hashi
    participant Bitcoin

    User    ->>     Bitcoin:    Deposit native BTC
    User    ->>     Hashi:      Notify hashi of deposit
    Hashi   ->>     Bitcoin:    Query for deposit
    Hashi   ->>     Hashi:      Quorum agreement on deposit
    Hashi   ->>     User:       hBTC sent to User
```

</div>

### BTC Deposit Address

Every Sui Address has its own unique Hashi Bitcoin deposit address.

This unique deposit address is `P2TR` and can be derived by the following:

```
tr({i}, multi_a(2, {g}, {h}))

where:
- H is base Hashi MPC Public Key
- h = derive(H, d) -- the child public key derived from public key H using
  derivation path d (the User's Sui Address)
- g is the guardian's fixed public key
- i is the NUMS internal key
  0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 defined in
  BIP-341.
```

Once confirmed, the quantity of `BTC` sent to this address will be minted directly into the user's Sui address.

> **NOTE**
>
> For devnet the deposit address omits the guardian key and can be determined by:
>
> ```
> tr({i}, pk({h}))
> ```

### Deposit

Once a user's deposit address has been determined, they can initiate a deposit to
hashi.

1. Broadcast a Bitcoin transaction depositing `BTC` into the user's unique
   deposit address.
1. Notify hashi of the deposit by submitting a transaction to Sui including the
   deposit transaction id.
1. Hashi nodes will query Bitcoin and watch for confirmation of the deposit
   transaction.
1. Hashi nodes communicate, waiting till a quorum has confirmed the deposit
   (after X block confirmations).
1. Hashi confirms the deposit on chain, minting the equivalent amount of `hBTC`
   and transferring it to the user's Sui address. The user can then immediately
   use the `hBTC` to interact with a defi protocol to, for example, leverage the
   `hBTC` as collateral for a loan in `USDC`.

## Withdraw Flow

Once a user has decided they want their `BTC` back on Bitcoin (e.g. they've paid
off their loan) they can initiate a withdrawal.

<div style="zoom: 1.5;">

```mermaid
---
title: Withdraw Flow
config:
  sequence:
    diagramMarginX: 0
---
sequenceDiagram
    autonumber

    participant User
    participant Hashi as Sui / Hashi
    participant Bitcoin

    User    ->>     Hashi:   Request withdrawal
    Hashi   ->>     Hashi:   Craft and sign Bitcoin transaction using MPC
    Hashi   ->>     Bitcoin: Broadcast transaction
```

</div>

### Withdraw

1. User sends a transaction to Sui with the amount of `hBTC` they would like to
   withdraw and the Bitcoin address they want to withdraw to.
1. Hashi will pick up the withdrawal request and will craft a bitcoin
   transaction that sends the requested `BTC` (minus fees) to the provided
   Bitcoin address and uses MPC to sign the transaction.
1. The transaction is broadcast to the Bitcoin network.
