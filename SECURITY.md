# Security Policy

We appreciate your help keeping Hashi secure. This policy covers the Hashi Move package (`packages/hashi`), the Hashi node and guardian software, and the hBTC deposit and withdrawal flows.

## Reporting a vulnerability

Report through the Sui bug bounty on HackenProof: https://hackenproof.com/programs/sui-protocol (Hashi is in scope), or email **security@mystenlabs.com** for anything outside that scope. **Do not report security issues through GitHub issues, pull requests or Discord.**

Include the affected component (Move module, node, guardian or monitor), a transaction, test or log that reproduces the issue, and the impact you believe it has. Do not test against mainnet funds you do not own.

## What to expect

| Step | Commitment |
|---|---|
| Acknowledgement | within 4 business hours |
| Initial severity assessment | within 72 hours |
| Fix or mitigation | Critical and High started immediately; an emergency pause needs only 5% of committee stake |
| Public disclosure of a material incident | within 72 hours of confirmation; if disclosing then would put users at further risk (for example, a fix is not yet live), as soon as that risk has passed |
| Postmortem | within 14 days |

## How changes are governed

Hashi is not governed by an admin key or a team multisig. Package upgrades and configuration changes are proposals that the Hashi committee, formed from active Sui validators, must approve with at least two thirds of stake. Proposals and votes are public on chain before a change can execute. This validator approval is Hashi's control on upgrades and admin actions, in place of an admin timelock. Pausing needs 5% of stake; unpausing needs two thirds.

## Audits

Certora performed a security review and formal verification of the Hashi Move package. The final reports, with the audited commit, will be published here (expected November 2026).
