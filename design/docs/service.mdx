# Service

Every committee member will be responsible for running a hashi node service.
Each hashi node will expose an http service, secured by TLS leveraging a
self-signed cert (ed25519 public key can be found in the Hashi System State
object) which will serve a gRPC `HashiService`.

## Sui Contracts

- The hashi move package(s) will be published as normal packages. In other
  words, the hashi packages will *not* be system packages and will *not* be a
  part of sui's framework.

## Stateless

A main goal of this design is to make the hashi service as stateless as
possible. Outside of any cryptographic material required for participating in
the protocol, any state critical for the functioning of the service must be
stored on Sui as a part of the live object set and knowledge of any historical
transactions or events previously emitted must not be needed for correct
operations of the service.

The set of data structures and state that are kept on chain are as follows:

```mermaid
---
config:
  theme: base
  themeVariables:
    primaryColor: '#298DFF'
    primaryTextColor: '#FFFFFF'
    primaryBorderColor: '#1759C4'
    secondaryColor: '#6C7584'
    secondaryTextColor: '#FFFFFF'
    secondaryBorderColor: '#4B515B'
    tertiaryColor: '#FFFFFF'
    tertiaryTextColor: '#000000'
    tertiaryBorderColor: '#6C7584'
    lineColor: '#298DFF'
    background: '#FFFFFF'
    mainBkg: '#FFFFFF'
    secondBkg: '#6C7584'
    fontSize: '14px'
    fontFamily: 'Inter, sans-serif'
---
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
