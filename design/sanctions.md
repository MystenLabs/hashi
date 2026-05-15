# Handling Sanctioned Addresses

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> How Hashi committee members independently apply sanctions checks to deposits and withdrawals using a configurable screening endpoint.

The decision to facilitate a transaction from or to Bitcoin must take into
account sanctioned addresses.

## Checking if an address is sanctioned

Each member of the committee might have different risk tolerances or policies
for which set of addresses they do not want to serve. To accommodate different
validator preferences, the Hashi node software has a configurable mechanism
for determining whether servicing a particular address should be denied.

To enable custom policies, the Hashi node software supports configuration of
a transaction screening endpoint defined by the gRPC service in
[`screener_service.proto`](https://github.com/MystenLabs/hashi/blob/main/crates/hashi-types/proto/sui/hashi/v1alpha/screener_service.proto).

One benefit of this interface is that the service can be arbitrarily basic.
For example, it can check a predefined sanctions list like the
[OFAC sanctioned digital currency addresses list](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses/blob/lists/sanctioned_addresses_XBT.txt),
or it can make calls to third-party risk services like TRM Labs or
Chainalysis.

## When sanctions checks apply

**Deposits**: When a user submits a deposit request, their request sits in a
queue or waiting room until the validators vote on accepting that deposit
and minting an appropriate amount of `hBTC`. Sanctions checking happens at
the time a validator decides whether to vote for accepting a deposit. If a
validator decides that it does not want to service that deposit, it does not
vote for it and ignores that the deposit exists. If a quorum decides to
accept a deposit that a particular validator did not want to accept, per
protocol the validator must recognize (and subsequently make use of) the
deposited BTC.

**Withdrawals**: When a user submits a withdraw request, their request sits
in a queue or waiting room until the validators pick it up for processing.
Before selecting a request for processing, the validators vote on approving
the request. One of the required checks as part of voting for approval is
performing sanctions checking. After a quorum of validators has voted to
approve a request, it can be picked up for processing. If a quorum decides
to approve a request for processing, per protocol all validators must
assist in driving the request to completion.

## Tainted UTXOs

The Hashi protocol implements rigorous sanctions enforcement, but enforcement
is ultimately best-effort. A quorum of validators might accept a deposit that
one validator preferred to not accept, or a previous committee accepted a
deposit that the current committee would have rejected. In either case, after
a UTXO is accepted into Hashi's pool, the protocol treats it as its own, and
it must be available during coin selection to process withdraw requests.
