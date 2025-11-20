# MPC Protocol

Sui validators use several MPC protocols for realizing a threshold schnorr
signer: Distributed Key Generation for generating a key, Key Rotation for
redistributing the key on committee changes, and a distributed signing protocol
for signing transactions. Those protocols are parametrized by two parameters,
`f` and `t`, such that hashi can operate as long as `<f` of the staking power
is not responsive ("liveness"), and is secure as long as `<t` of the staking
power is colluding. In the first version of hashi we expect `t` to be in the
range of 33%-50% and `f` in the range of 20%-33%. Those values may increase in
future versions of hashi. The protocols are based on prior published work,
modified and improved by our crypto team.

In addition to the MPC signer, hashi will also use a second signer implemented
with a cloud enclave that enforces policies independently of the MPC protocols,
reducing the risk of collusion or supply chain attacks.
