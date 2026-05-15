# Reconfiguration

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> How the Hashi committee transfers MPC key shares between epochs through DKG or key rotation as Sui validators change.

Reconfiguration is one of the most important parts of the Hashi protocol,
because it is the step where the old committee shares key shares of the MPC
key with the new committee.

The Hashi service monitors the Sui epoch change and immediately starts Hashi
reconfiguration after Sui's epoch change completes. During reconfiguration,
in-progress operations (for example, processing of withdrawals) are paused.
The new committee resumes and processes them after reconfiguration completes.

```mermaid
graph LR
    A[Start Reconfig] --> B[DKG or Key Rotation] --> C[End Reconfig]
```

### Start Reconfig

```mermaid
graph LR
    A[Start Reconfig]:::active --> B[DKG or Key Rotation] --> C[End Reconfig]
    classDef active fill:#298DFF,stroke:#1759C4,color:#FFFFFF
```

Each Hashi node monitors Sui for epoch changes. When a new Sui epoch is
detected and the Hashi epoch has not yet advanced to match, the node knows
that a reconfiguration is needed. A committee member submits an onchain
transaction by calling `hashi::reconfig::start_reconfig` to signal that
reconfiguration should begin for the target epoch:

```move
entry fun start_reconfig(
    self: &mut Hashi,
    sui_system: &SuiSystemState,
    ctx: &TxContext,
)
```

This sets a pending epoch change flag in the onchain state, which pauses
normal operations (deposits, withdrawals) until reconfiguration completes.
The new committee membership is determined by the set of validators that
registered with Hashi for the new epoch. Stake weights come from the Sui
validator set.

### DKG or Key Rotation

```mermaid
graph LR
    A[Start Reconfig] --> B[DKG or Key Rotation]:::active --> C[End Reconfig]
    classDef active fill:#298DFF,stroke:#1759C4,color:#FFFFFF
```

The MPC key protocol runs among the new committee members. Which protocol
runs depends on whether this is the first Hashi epoch or a subsequent one:

- **Initial DKG**: if there is no existing MPC public key (the genesis epoch),
  the committee runs the distributed key generation protocol to produce a
  fresh master key.
- **Key rotation**: if an MPC public key already exists, the old committee's
  key shares are redistributed to the new committee. The old committee
  members act as dealers and the new committee members act as receivers.

In both cases, the output is a `DkgOutput` containing the new committee's
key shares and the MPC public key. See [MPC Protocol](/mpc-protocol)
for details.

Each committee member then signs a `ReconfigCompletionMessage` containing
the target epoch and the MPC public key using their BLS12-381 key. Nodes
collect signatures from each other through RPC until a quorum (2/3 of
committee weight) is reached, producing a BLS aggregate signature certificate.
This ensures that a supermajority of the new committee agrees on the key
protocol output before the epoch transition is finalized onchain.

### End Reconfig

```mermaid
graph LR
    A[Start Reconfig] --> B[DKG or Key Rotation] --> C[End Reconfig]:::active
    classDef active fill:#298DFF,stroke:#1759C4,color:#FFFFFF
```

A committee member submits the aggregate signature certificate onchain by
calling `hashi::reconfig::end_reconfig`:

```move
entry fun end_reconfig(
    self: &mut Hashi,
    mpc_public_key: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    ctx: &TxContext,
)
```

The onchain contract verifies the certificate, commits the generated MPC
public key if DKG ran (or verifies that the key remains unchanged from the
previous epoch), advances the Hashi epoch, and clears the pending epoch
change flag.

After the new epoch begins, the new committee initializes the signing state
for the epoch by running the presigning protocol to generate a batch of
presignatures needed for the threshold Schnorr signing protocol (see
[MPC Protocol](/mpc-protocol)). After presignatures are ready, normal
operations resume for processing deposits and withdrawals.

### Abort Reconfig

```mermaid
graph LR
    A[Start Reconfig] --> B[DKG or Key Rotation] --> C[Abort Reconfig]:::active
    C --> A
    classDef active fill:#298DFF,stroke:#1759C4,color:#FFFFFF
```

Reconfiguration can fail after `start_reconfig` has committed the pending
committee but before `end_reconfig` can safely advance the Hashi epoch.
Examples include:

- The pending committee cannot complete initial DKG because too much
  registered stake is offline or misconfigured.
- Key rotation cannot complete because the old committee cannot supply enough
  valid resharing material to the new committee.
- The new committee completes the MPC protocol but cannot gather a threshold
  BLS certificate over a single `ReconfigCompletionMessage`.
- The MPC output is inconsistent with the onchain invariant that the threshold
  public key remains unchanged across key-rotation epochs.
- A bad pending committee was formed from stale or incorrect validator
  metadata, such as invalid endpoint, TLS, BLS, or encryption key updates.

In these cases, governance can create and execute an
`abort_reconfig::AbortReconfig` proposal for the specific pending epoch being
aborted. The proposal is voted on by the current committed committee. When
quorum is reached, execution re-checks that the same epoch is still pending,
clears the pending epoch change, removes the pending committee, and emits the
standard `ProposalExecutedEvent<AbortReconfig>` with the aborted epoch in the
proposal data. The current Hashi epoch and MPC public key remain unchanged.
Normal operations can then resume under the last committed committee, and a
later Sui epoch notification can trigger a fresh `start_reconfig`.
