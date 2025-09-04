# Handling Sanctioned Addresses

The decision to facilitate a transaction from/to bitcoin must take into account
sanctioned addresses.

## Individual Validator Choice

Each member of the committee may have different risk tolerances or policies for
which set of addresses they don't want to serve. In order to enable individual
validators the ability to not participate in facilitating a transaction with an
address that violates their risk tolerances, the hashi service will have
support for operators to provide lists of addresses that shouldn't be served.
This list will be able to be dynamically updated on-the-fly. When a node is
configured to not serve a particulate address, the hashi service will refuse to
sign on and process transactions (in either direction) that involve said
address.

One such list can be found
[here](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses/blob/lists/sanctioned_addresses_XBT.txt).

## Quorum Voting

In addition to this individual choice, the protocol itself will have a
mechanism for the committee to vote for addresses which should not be served,
storing them on-chain. If enough validators (1/3) vote to not serve a
particular address then the remaining validators will respect that per
protocol.
