# MPC Protocol

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> The Multi-Party Computation protocols that Hashi uses for distributed key generation, key rotation, and threshold Schnorr signing.

Sui validators use several Multi-Party Computation (MPC) protocols to
implement a threshold Schnorr signer: Distributed Key Generation (DKG) for
generating a key, key rotation for redistributing the key on committee
changes, and a distributed signing protocol for signing transactions. These
protocols are parametrized by two values, `f` and `t`, such that Hashi
operates as long as fewer than `f` of the staking power is unresponsive
(liveness), and is secure as long as fewer than `t` of the staking power
is colluding. In the first version of Hashi, `t` is expected to be in the
range of 33% to 50%, and `f` in the range of 20% to 33%. These values
might increase in future versions of Hashi. The protocols are based on
prior published work, modified and improved by the Mysten Labs cryptography
team.

In addition to the MPC signer, Hashi uses a second signer implemented with a
cloud enclave that enforces policies independently of the MPC protocols,
reducing the risk of collusion or supply-chain attacks.
