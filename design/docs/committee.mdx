# Committee

Hashi is intended to be "native", meaning the expectation is that the members
of the hashi committee are a subset of the Sui validators. Being a member of
the hashi committee is restricted to members of Sui's validator set but is
essentially optional as it requires a separate on-chain registration and
running extra services. In practice we expect the % of Sui validators who are
members of the hashi committee to be >90%.

## Registration Info

Each Sui validator will need to register themselves before they'll be able to
join the hashi committee. Each committee member will need to provide the
following additional information:

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

The voting weight each validator possesses will be mirrored from the
`SuiSystemState`.

## Why is the committee not exactly the set of Sui Validators?

Above it's mentioned that the hashi committee is a subset of the Sui Validators
instead of being strictly the same set. There are a few challenges with forcing
these sets to be identical:

- Being a member of the committee is strictly optional since hashi's system
  state is separate from sui's system state. When someone registers to become a
  Sui Validator the set of metadata (public keys, network addresses, etc) they
  are required to submit only includes information necessary for running the
  `sui-node` validator service. Without changes, there is no way of preventing
  a new validator from becoming a validator without also registering to join
  the hashi committee.
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

The one downside of not having tight coupling is needing to handle the hand-off
from an old committee to a newer committee as it would require that 2f+1
stake-weighted members of the old committee are alive and willing to
participate in the hand-off protocol. This design makes this assumption given
the challenges we'd need to overcome to enforce tight coupling and we can
likely find some other economic mechanism for motivating older committee
members in participating in the hand-off process.
