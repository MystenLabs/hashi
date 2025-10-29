# Handling Sanctioned Addresses

The decision to facilitate a transaction from/to bitcoin must take into account
sanctioned addresses.

## Checking if an Address is Sanctioned

Each member of the committee may have different risk tolerances or policies for
which set of addresses they don't want to serve. In order to accommodate
different validator preferences the hashi node software will have a
configurable mechanism for it determining if servicing a particular address
should be denied.

One simple way of enabling custom policies is to have the hashi node software
make an HTTP request to a configured sanctions checking endpoint which will
return if an address is allowed to be serviced or not.

<!-- TODO provide details of the actual interface -->
```
Request:  GET /<Bitcoin Address>
Response: 200 "allow" | "deny"
```

One benefit of this interface is the ability for the service to be arbitrarily
simple, by checking a predefined sanctions list like this one
[here](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses/blob/lists/sanctioned_addresses_XBT.txt),
or allow for making calls to third-party risk services like TRM labs or
chainalysis.

We will provide a reference implementation of the sanctions checking service
that will be provided without warranty that validators can use as a base for
implementing their own polices.

## When are sanctions checks applied

**Deposits**: When a user submits a Deposit request, their request sits
in a queue or waiting room till the validators vote on accepting that deposit
and minting an appropriate amount of `#BTC`. Sanctions checking will happen at
the time a validator is deciding to vote for accepting a deposit. If a
validator decides that it doesn't want to service that deposit, it will not
vote for it and will simply ignore that the deposit exists. If a quorum decides
to accept a deposit that a particular validator did not want to accept, per
protocol it will need to recognize (and subsequently make use of in the future)
the deposited BTC.

**Withdrawals**: When a user submits a Withdraw request, their request sits in
a queue or waiting room till the validators pick it up for processing.
Sanctions checking will happen at the time the committee is deciding to select
a request for processing. If a validator decides that it doesn't want to service
that withdrawal, it will not vote to pick it up for processing and will ignore
that it is even in the queue. If a quorum decides to pick up a request for
processing that a particular validator did not want to service, per protocol it
will need to assist in driving the request to completion.

## Tainted UTXOs

While we intend to have a rigorous implementation of sanctions enforcement, it
is ultimately best-effort. A quorum of validators may accept a deposit that one
validator may have preferred to not accept, or a previous committee accepted a
deposit that the current committee may have rejected. In either case, once a
UTXO has been accepted into hashi's pool, the protocol treats it as its own and
it must be able to be used during coin selection to process withdraw requests.
