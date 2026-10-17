# Service

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> The Hashi node service that committee members run, the gRPC interface it exposes, and the on-Sui state it relies on.

Every committee member is responsible for running a Hashi node service. Each
Hashi node exposes an HTTP service, secured by Transport Layer Security (TLS)
using a self-signed cert (each member registers its ed25519 public key in the
`CommitteeSet` on the `Hashi` object), and serves the gRPC `BridgeService` and
`MpcService`. Peers connect with their own registered TLS key, and the node
refuses any caller whose key belongs to no registered validator, except on
`/health` and `/ready`.

## How should liveness probes check the node?

The node runs two HTTP listeners: the TLS-secured service described above, and
a separate plain-HTTP metrics listener. The `/health` on the TLS service always
answers; liveness probes should use the `/health` on the plain-HTTP metrics
listener instead, which fails once the node's main runtime stops running tasks
for 2 minutes.

| Option | Default | Description |
| --- | --- | --- |
| `metrics-http-address` | `127.0.0.1:9180` | Address of the plain-HTTP metrics listener, whose `/health` liveness probes should use. |

## How is the Hashi Move package published?

- The Hashi Move package is published as a normal package. It is not a system
  package and is not part of the Sui framework.

## Is the Hashi service stateless?

A main goal of this design is to make the Hashi service as stateless as
possible. Outside of any cryptographic material required for participating in
the protocol, any state critical for the functioning of the service must be
stored on Sui as part of the live object set. Knowledge of any historical
transactions or events previously emitted must not be needed for correct
operation of the service.

The set of data structures and state kept onchain is as follows:

```mermaid
block-beta
  columns 1

  block
    committee
    config
  end

  pool["UTXO pool"]

  block
    gov["Governance Requests"]
    deposits["Deposit Request Queue"]
    withdrawals["Withdrawal Request Queue"]
  end

  broadcast["Ordered broadcast channel"]
```
