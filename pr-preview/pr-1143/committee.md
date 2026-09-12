# Committee

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> The Hashi committee is a subset of the Sui validator set that operates the protocol's MPC signing service.

Hashi is a native protocol, meaning the members of the Hashi committee are a
subset of the Sui validators. Membership in the Hashi committee is restricted
to members of the Sui validator set but is otherwise optional, because it
requires a separate onchain registration and running extra services. In
practice, more than 90% of Sui validators are expected to be members of the
Hashi committee.

## Registration information

Each Sui validator must register before joining the Hashi committee. Each
committee member provides the following additional information:

```rust
struct HashiNodeInfo {
    /// Sui Validator Address of this node
    validator_address: address,

    /// Sui Address of an operations account 
    operator_address: address,

    /// bls12381 public key to be used in the next epoch.
    ///
    /// This public key can be rotated but will only take effect at the
    /// beginning of the next epoch.
    next_epoch_public_key: Element<UncompressedG1>,

    /// The publicly reachable URL where the `hashi` service for this validator
    /// can be reached.
    ///
    /// This URL can be rotated and any such updates will take effect
    /// immediately.
    endpoint_url: String,

    /// ed25519 public key used to verify TLS self-signed x509 certs
    ///
    /// This public key can be rotated and any such updates will take effect
    /// immediately.
    tls_public_key: vector<u8>,
}
```

The voting weight each validator possesses is mirrored from the
`SuiSystemState`.

## Why the committee is not exactly the set of Sui validators

The Hashi committee is a subset of the Sui validators rather than strictly the
same set. There are a few challenges with forcing these sets to be identical:

- Membership in the committee is strictly optional, because Hashi's system
  state is separate from Sui's system state. When someone registers as a Sui
  validator, the required metadata (public keys, network addresses, and so on)
  only includes information necessary for running the `sui-node` validator
  service. Without changes, there is no way to require a new Sui validator to
  also register for the Hashi committee.
- Enforcing tight coupling would require changes to Sui's epoch change and
  reconfiguration process in a few ways:
  - The MPC hand-off protocol takes a non-trivial amount of time to execute,
    so the new set of validators would need to be locked in some time period
    before the close of the epoch, giving the MPC committee time to
    reconfigure.
  - Sui's epoch change and reconfiguration would need to block on successful
    reconfiguration of the MPC committee.

Addressing any of the above would require deep changes to Sui's
reconfiguration process. Some of those changes are directly opposed by the
core team, and any of them would take significant time to implement correctly.

The one downside of not having tight coupling is the need to handle the
hand-off from an old committee to a new committee. The hand-off requires that
`2f+1` stake-weighted members of the old committee are alive and willing to
participate in the hand-off protocol. This design makes that assumption,
because of the challenges of enforcing tight coupling, and an economic
mechanism can be added later to motivate older committee members to
participate in the hand-off process.
