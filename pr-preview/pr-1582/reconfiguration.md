# Reconfiguration

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> How the Hashi committee transfers MPC key shares between epochs through DKG or key rotation as Sui validators change.

Reconfiguration is one of the most important parts of the Hashi protocol,
because it is the step where the old committee shares key shares of the MPC
key with the new committee (see [MPC Protocol](mpc-protocol.mdx)).

The Hashi service monitors the Sui epoch change and immediately starts Hashi
reconfiguration after Sui's epoch change completes. During reconfiguration,
Hashi pauses in-progress operations (for example, processing of withdrawals).
The new committee resumes and processes them after reconfiguration completes.

```mermaid
graph LR
    A[Start Reconfig] --> B[DKG or Key Rotation] --> C[End Reconfig]
```

## How does a reconfiguration proceed?

On the happy path, a reconfiguration runs these steps in order:

1. A Hashi node detects a new Sui epoch while the Hashi epoch has not yet
   advanced to match.
2. Running nodes submit `hashi::reconfig::start_reconfig`; the first
   transaction to land forms the pending committee and sets the pending epoch
   change flag, which pauses deposit approval and confirmation, and withdrawal
   approval, commitment, and signing.
3. The new committee runs initial DKG (at genesis) or key rotation (in every
   later epoch), and each member ends with its `MpcOutput`.
4. Each member signs a `ReconfigCompletionMessage` with its BLS12-381 key, and
   nodes collect signatures until a quorum (2/3 of committee weight) produces
   an aggregate signature certificate.
5. On a key rotation only, nodes also collect the outgoing committee's
   signatures over a `CommitteeTransitionRequest`.
6. Within the same Sui epoch, a committee member submits `end_reconfig` (on a
   key rotation, together with `submit_committee_handoff` in the same
   transaction).
7. The chain verifies the certificate, advances the Hashi epoch, and clears
   the pending epoch change flag; deposits, and withdrawal approval and
   commitment, resume.
8. The new committee runs the presigning protocol; signing withdrawal inputs
   resumes once its presignatures are ready.

If Sui's epoch moves on before step 6 lands, [abort reconfig](#abort-reconfig)
resolves the pending reconfiguration instead.

## Start reconfig

Each Hashi node monitors Sui for epoch changes. When a new Sui epoch is
detected and the Hashi epoch has not yet advanced to match, the node knows
that it needs a reconfiguration. Every running node then submits
`hashi::reconfig::start_reconfig`, which is permissionless; the first
transaction to land forms the committee for Sui's current epoch:

```move
entry fun start_reconfig(
    self: &mut Hashi,
    sui_system: &SuiSystemState,
    ctx: &TxContext,
)
```

This sets a pending epoch change flag in the onchain state. Until
reconfiguration completes, the chain refuses deposit approval and
confirmation, and withdrawal approval, commitment, and signing
(`EReconfiguring`); users can still submit deposit and withdrawal requests,
which Hashi processes afterwards.
The active Sui validators that registered with Hashi and set their next-epoch
keys make up the new committee, leaving out any that
resigned or that governance ignored through an `IgnoreMember` proposal. Each
member's weight is its Sui voting power, and every threshold is a share of the
formed committee's total weight.

At genesis (the first Hashi epoch, when no MPC public key exists yet and the
committee must run initial DKG), the **launch switch**
additionally gates `start_reconfig`: it aborts until the publisher
has sent `hashi::finish_publish` (the `hashi launch` CLI command), which
finalizes the deploy configuration and hands the package `UpgradeCap` into
onchain custody. This gives the publisher explicit control over when (and
with which registered validators) the initial committee forms. After genesis
Hashi never consults the gate and applies no registration floor, because a
floor on a normal reconfig would let validators brick reconfiguration by
withholding registration.

## DKG or key rotation

The MPC key protocol runs among the new committee members. Which protocol
runs depends on whether this is the first Hashi epoch or a subsequent one:

- **Initial DKG**: if there is no existing MPC public key (the genesis epoch),
  the committee runs the distributed key generation protocol to produce a
  fresh master key.
- **Key rotation**: if an MPC public key already exists, the old committee
  redistributes its key shares to the new committee. The old committee
  members act as dealers and the new committee members act as receivers.

In both cases, each new member ends with an `MpcOutput`: its own key shares
and the MPC public key. See [MPC Protocol](mpc-protocol.mdx) for details.

Each committee member then signs a `ReconfigCompletionMessage` containing
the target epoch and the MPC public key using their BLS12-381 key. Nodes
collect signatures from each other through RPC until they reach a quorum (2/3 of
committee weight), producing a BLS aggregate signature certificate.
This ensures that a supermajority of the new committee agrees on the key
protocol output before the epoch transition finalizes onchain.

On a key rotation the outgoing committee must also approve the new one. Nodes
collect its signatures over a `CommitteeTransitionRequest` with the
`SignCommitteeTransition` RPC and submit that certificate through
`submit_committee_handoff`, in the same transaction as `end_reconfig`, which
does not activate a rotation without it. Initial DKG has no outgoing committee
and skips this step.

## End reconfig

A committee member submits the aggregate signature certificate onchain by
calling `hashi::reconfig::end_reconfig`:

```move
entry fun end_reconfig(
    self: &mut Hashi,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
)
```

The onchain contract verifies the certificate, commits the generated MPC
public key if DKG ran (or verifies that the key remains unchanged from the
previous epoch), advances the Hashi epoch, and clears the pending epoch
change flag.

Completion must land inside the Sui epoch in which the reconfiguration formed.
`start_reconfig` pins the pending committee to Sui's epoch, and both
`submit_committee_handoff` and `end_reconfig` abort with
`EReconfigWindowClosed` once Sui's epoch has moved past it; from then on only
[abort reconfig](#abort-reconfig) can resolve the pending state. Each
submission is bound to its target. `end_reconfig` reads it from the
completion certificate's signing epoch; `submit_committee_handoff` takes it
as an explicit `epoch` argument, because the outgoing committee signs the
handoff certificate and its signing epoch is the source epoch. The signed
handoff message already binds the target, so the argument adds no security;
it lets the chain name the failure. Both entries abort with
`EWrongReconfigEpoch` when a different epoch is pending (the target was
aborted and a replacement has formed), before it checks any signature. It reports a
submission whose own target already activated as
`EReconfigAlreadyCompleted` (another node's `end_reconfig` won the race, which
the node treats as success), whether or not the next reconfiguration is
already pending; nothing pending otherwise is `ENotReconfiguring` (the target
was aborted). The contract stores handoffs by source epoch, and a replacement can form
from the same source epoch after an abort. So for a handoff, the submission
counts as its own target only if the handoff stored under the certificate's
signing epoch (the source epoch) names the submitted `epoch`. Nodes
key their retry-or-give-up decision on which of these fires.

| Error | Raised by | Condition | What it means for the node |
| --- | --- | --- | --- |
| `EReconfigWindowClosed` | `submit_committee_handoff`, `end_reconfig` | Sui's epoch has moved past the pending committee's epoch | Only [abort reconfig](#abort-reconfig) can resolve the pending state |
| `EWrongReconfigEpoch` | `submit_committee_handoff`, `end_reconfig` | A different epoch is pending (checked before any signature) | The target was aborted and a replacement has formed |
| `EReconfigAlreadyCompleted` | `submit_committee_handoff`, `end_reconfig` | The submission's own target already activated, whether or not the next reconfiguration is pending | Another node's `end_reconfig` won the race; the node treats this as success |
| `ENotReconfiguring` | `submit_committee_handoff`, `end_reconfig` | Nothing is pending and the target did not activate | The target was aborted |

After the new epoch begins, the new committee initializes the signing state
for the epoch by running the presigning protocol to generate a batch of
presignatures needed for the threshold Schnorr signing protocol (see
[MPC Protocol](mpc-protocol.mdx)). Deposits, and withdrawal approval and
commitment, resume as soon as `end_reconfig` lands; signing withdrawal inputs
waits until the new committee's presignatures are ready.

## Abort reconfig

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
- Stale or incorrect validator metadata, such as invalid endpoint, TLS, BLS,
  or encryption key updates, formed a bad pending committee.

In these cases, anyone can call the `reconfig::abort_reconfig` entry function
directly, naming the pending epoch to abort. It is deliberately not a
governance proposal and takes no vote: the committees that could vote on one
are exactly the parties a stalled reconfiguration puts in doubt. The pending
committee might never finish DKG or key rotation, and the same offline stake
that stalled the reconfiguration can strand a proposal gated on the outgoing
committee's quorum. Instead the abort is bound to objective onchain
conditions, all checked in the same transaction:

1. A reconfiguration is in progress, that is, a pending epoch change exists, and
   the named epoch is the pending one (a stale transaction cannot tear down a
   different reconfiguration).
2. The pending epoch is not Sui's current epoch. `start_reconfig` pins the
   pending committee's epoch to Sui's epoch at formation time, so while the
   two still match the reconfiguration is inside its window and might
   legitimately complete. Only once Sui's epoch has moved past the target is
   the reconfiguration stuck by definition: [end reconfig](#end-reconfig)
   refuses to land after the window, so completion and abort are mutually
   exclusive by Sui epoch and can never race each other.

The launch switch is not re-checked: a pending genesis committee can only
exist because `start_reconfig` passed it, and the package `UpgradeCap` it
looks for never leaves onchain custody.

When these hold, the call clears the pending epoch change, removes the pending
committee (discarding any committee handoff certificate it had collected), and
emits `ReconfigAborted` with the aborted epoch. The current Hashi epoch,
committee, and MPC public key remain unchanged. After genesis, normal
operations resume under the last committed committee; at genesis there is no
committee yet, so Hashi returns to its pre-genesis state. Either way the Hashi
epoch now lags Sui's, and a fresh `start_reconfig` forms a replacement
committee from the then-current validator set.

Nodes drive this themselves. When a node sees a checkpoint from a later Sui
epoch while a reconfiguration is still pending, it stops working on that
reconfiguration, submits the abort (the chain settles the race between nodes),
and submits the replacement `start_reconfig` as soon as the abort is
reflected. A node that observes an abort it did not submit, including one an
operator sent by hand with `hashi committee abort-reconfig`, starts the
replacement in the same way, as does a node that comes up to find Hashi's
epoch behind Sui's with nothing pending, whether or not it can rebuild its
own signing state for the lagging epoch. The CLI commands are therefore
fallbacks for when no node is doing this: `abort-reconfig` refuses up front
when nothing is pending or the pending epoch is still Sui's current epoch,
and `hashi committee start-reconfig` submits the replacement, refusing when
a reconfiguration is pending or Hashi is already on Sui's current epoch.

Governance can hold the replacement off. While the
[`reconfig_hold`](config.mdx#reconfig_hold) config flag is set through an
`UpdateConfig` proposal, `start_reconfig` aborts on chain, so no committee
can form and the last committed committee keeps serving deposits and
withdrawals; nodes see the flag and do not submit. A reconfiguration already
pending continues, and so does `abort_reconfig`, so the sequence for staying
on the last committed committee is to set the flag and then let the nodes abort the overrun
reconfiguration. Clearing the flag does not itself start a
replacement: nodes submit `start_reconfig` on a Sui epoch change, on an abort,
and at startup, and none of those is a config change, so the replacement waits
for the next Sui epoch change unless an operator runs
`hashi committee start-reconfig`.

Every abort observed on chain, whoever submitted it, increments the node
metric `hashi_reconfig_aborted_total`. An abort means a reconfiguration
stalled for an entire Sui epoch with deposits and withdrawals halted, so it is
worth alerting on and investigating even though the system recovers on its
own.

## Which CLI commands can operators run?

Nodes normally submit these transactions themselves; `abort-reconfig` and
`start-reconfig` are fallbacks for when no node is doing so.

| Command | What it does | Refuses when |
| --- | --- | --- |
| `hashi launch` | Sends `hashi::finish_publish` at genesis, finalizing the deploy configuration and handing the package `UpgradeCap` into onchain custody, which opens the launch switch | None |
| `hashi committee abort-reconfig` | Submits the abort for the pending reconfiguration | Nothing is pending, or the pending epoch is still Sui's current epoch |
| `hashi committee start-reconfig` | Submits the replacement `start_reconfig` | Governance holds reconfiguration (`reconfig_hold` is set), a reconfiguration is already pending, a committee already exists for Sui's current epoch, Hashi is already on Sui's current epoch, or the fullnode's Sui epoch is behind Hashi's |
