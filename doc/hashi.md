# Overview

This is a high level overview and design doc for `hashi` the Sui <-> Bitcoin
bridge product. This is intended to be a living document that should be updated
as new decisions and features are made with the goal of this being a canonical
description for how hashi is designed and operates.

At a high level `hashi` is a protocol for a decentralized committee to manage a
bridge for moving BTC between bitcoin and sui.

# Design

Overall hashi consists of 3 main parts: assets custodied on bitcoin, contracts
and protocol state on sui and the stand-alone binary that all members of the
committee run.

## Committee

Hashi is intended to be a "native" bridge, meaning the expectation is that the
members of the bridge committee are a subset of the Sui validators. Being a
member of the hashi committee is restricted to members of Sui's validator set
but is essentially optional as it requires a separate on-chain registration and
running extra services.

Each committee member will register an additional network address (do we need
an additional network key for TLS or do we reuse the same one used by sui-node?)
and an additional bls12381 public key. An aggregated bls signature from the
committee will be used to approve various actions necessary for normal
operations. 

```
struct PublicKey {
    scheme: u8,
    public_key: Vec<u8>,
}

struct CommitteeMember {
    protocol_key: PublicKey, // bls12381
    network_key: PublicKey,  // ed25519
    network_address: String, // or URL
    sui_validator_staking_pool_id: ID, // Unique id of this validator in the validator set
    stake: u64,
}

struct Committee {
    members: Vec<CommitteeMember>,
    updates: Vec<CommitteeMember>, // updates that a member wants to make
    total_stake: u64,
}
```

The exact details of committee reconfiguration are still TBD, but one possible
design would be:
- immediately post sui epoch change we inspect the new sui committee and
  determine the new committee for the bridge. This will require effort from the
  move team to add the ability to inspect the system state using a non-mutable
  reference.

- existing committee begins the process of handing off to the new committee

Reconfiguration will likely always happen while the committee has other/on
going operations in flight. We'll need to figure out if we should complete
pending operations or if reconfiguration should preempt those operations which
can resume once a new committee has been installed.

### Why is the committee not exactly the set of Sui Validators?

Above its mentioned that the bridge committee is a subset of the Sui Validators
instead of being strictly the same set. There are a few challenges with forcing
these sets to be identical:
- Being a member of the committee is strictly optional since hashi's system
  state is separate from sui's system state. When someone registers to become a
  Sui Validator the set of metadata (public keys, network addresses, etc) they
  are required to submit only includes information necessary for running the
  `sui-node` validator service. Without changes, there is no way of preventing
  a new validator from becoming a validator without also registering to join
  the bridge committee.
- If we enforce tight coupling we'd likely need to change sui's epoch
  change/reconfiguration process in a few ways:
  - Given the mpc hand-off protocol takes non-trivial amount of time to
    execute, the new set of validators would need to be locked-in some time
    period before the closing of the epoch to give the mpc committee time to
    reconfigure and
  - We'd need to block Sui's epoch change and reconfiguration on successful
    reconfiguration of the mpc committee.

Addressing any of the above would require deep changes to sui's reconfiguration
process some of which would be directly opposed by the core team and regardless
would take a significant amount of time itself to implement correctly.

The one downside of not having tight coupling is needing to handle the hand off
from an old committee to a newer committee as it would require that 2f+1
stake-weighted members of the old committee are alive and willing to
participate in the hand-off protocol. I think this is a reasonable trade off
given the challenges we'd need to overcome to enforce tight coupling and we can
likely find some other economic mechanism for motivating older committee
members in participating in the hand-off process.

## Sui Contracts

- The hashi move package(s) will be published as normal packages. In other
  words, the hashi packages will *not* be system packages and will *not* be a
  part of sui's framework.

## Stateless

A main goal of this design is the make the hashi service as stateless as
possible. Outside of any cryptographic material required for participating in
the protocol, any state critical for the functioning of the service must be
stored on Sui as a part of the live object set and knowledge of any historical
transactions or events previously emitted must not be needed for correct
operations of the service.

## Workflows

For example, when processing a BTC withdrawal we could have the state of that
withdrawal on chain as it moves through various stages:

- Request withdrawal -> transaction formation -> MPC committee sig generation
  -> waiting for confirmations -> Finalized

In the system state on sui (or maybe another shared object?) we can have a
buffer of these sort of heterogeneous ongoing or pending actions. This way a
node can trivially list out or fetch these actions from Sui on startup or after
a crash.

TODO add workflows

```
struct Workflow {
    id: UID,
    name: String, // type of workflow
    // Dynamic fields with workflow specific information
}
```

## How do we handle sanctioned BTC addresses?

The decision to facilitate a transaction from/to bitcoin must take into account
sanctioned addresses. Each member of the committee may have different risk
tolerances or policies for which set of addresses they don't want to serve,
therefore the decision must be made individually by each committee member vs
having an on-chain set of addresses to not serve. Each action taken, either
minting sBTC on sui or settlement back onto bitcoin, requires ~2/3 of the
committee to form a certificate to execute. This allows each member to
explicitly opt-out of signing a proposal to service an address that it deems as
"sanctioned".

This sanctioned list can be provided via configuration as a file listing the
banned addresses. One such list can be found
[here](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses/blob/lists/sanctioned_addresses_XBT.txt).

## Tracking Bitcoin

Unlike Sui, Bitcoin can undergo chain reorganizations when forks arise and
eventually the network chooses the fork with the larger height as the winner.
Due to this many who interact in the bitcoin ecosystem wait for a number of
block confirmations before recognizing that the transactions in a block are
considered final. The industry standard seems to sit around waiting for 6
confirmations before treating a block as final. As such we'll also use a
minimum of 6-10 confirmations before our system recognizes a block as final.

We'll have a shared object used to track the latest bitcoin blocks. As new
bitcoin blocks are mined, the committee will form a cert to confirm a block or
set of blocks. Once a block has enough confirmations it'll graduate to become
the new finalized chain head for the purposes of determining if a transaction
has settled and is finalized on btc.

Each time a new block is finalized, the quorum will process the block and
either mint sBTC for each new UTXO or close out any previously pending
withdrawals on the sui side.

We'll need a shared object to maintain the set of UTXOs and/or public keys
(addresses) that the committee is managing. This will act as both an accounting
mechanism as well as a nonce/replay protection mechanism. As UTXOs are
deposited, entries will be added, and as UTXOs are withdrawn (spent), entries
will be removed, all after the requisite number of confirmations.

### Alternative
Alternatively we could implement btc block verification inside of move and have
them all verified inside of move (block headers). To do this we'd need to
expose a sha256 hash function to be used in move.

We could also just have the committee act as an oracle and instead have users
need to drive the formation of a cert to have btc collateral minted on the sui
side.

## Proof of possession

Depending on how we expect users to deposit to the bridge committee owned BTC
addresses, we may want to build out some way for a user to get a proof of
possession of the address they'll be sending to.

## Bridge Node API

Every committee member will be responsible for running a hashi node service.
Each hashi node will expose an http service, secured by TLS leveraging a
self-signed cert (ed25519 public key can be found in the Hashi System State
object) which will serve a gRPC `HashiService`. If we want to gate some API
surface to only be callable by other committee members then we can trivially
leverage mTLS and a middleware auth layer that enforces that callers'
self-signed cert must be from a member of the committee.

## MPC protocol

TBD

## BTC account rotation

TBD

## Collateral object or just sBTC

TBD

## Fees and Incentives

TBD


# Open Questions

- How do we pay for gas (on sui and bitcoin)
- How do we handle congestion on bitcoin?
- How often should we do reconfiguration given we wont operate in lock-step
  with sui's reconfiguration?
- how do we handle the catastrophic scenario where validators loose their key
  shares
- How do we have a validator auth themselves to the bridge system contracts for
  the purpose of registration or updating their info
