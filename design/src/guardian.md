# Guardian

In order to protect against vulnerabilities as well as against malicious past
committees, hashi will make use of a withdrawal guardian, which is a second
signatory on the managed Bitcoin deposits. All deposits will only be spendable
with a 2-of-2 multisig with the guardian as one party and the hashi MPC
committee as the other.

TODO fill in rest of details.

Flow:
- User calls burn, request enters queue
- Enqueue reported to guardian, recorded with timestamp
- When ready (based on limit or 2-day timelock) Hashi nodes create unsigned BTC tx
- Unsigned BTC tx + metadata sent to Guardian for signature
- Hashi nodes use MPC to add their signature
- On-Sui proposal-vote primitive used to post signed BTC tx back to chain; tx also submitted to BTC network

