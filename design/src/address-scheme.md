# Bitcoin address scheme

Every Sui address has its own unique Hashi Bitcoin deposit address, this allows
hashi a lightweight way to know which address on sui to credit for a deposit.
All Hashi deposit addresses are `P2TR` (Pay-to-Taproot) where the 2-of-2 multisig
script between Hashi and the Guardian is encoded as the sole leaf in the
Taproot tree.

The exact [descriptor](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
is:

```
tr({i}, multi_a(2, {g}, {h}))
```

where:

- `H` is the base Hashi MPC public key and can be found on-chain.
- `h = derive(H, d)` -- the child public key derived from `H` using
  derivation path `d` (the depositor's Sui address)
- `g` is the guardian's fixed public key
- `i` is the NUMS (nothing-up-my-sleeve) internal key defined in BIP-341
  (`50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`)
  with no known private key, ensuring all spends occur via the script path

The key derivation is not BIP-32. It is a purpose-built unhardened derivation
over secp256k1, keyed by the Sui address, giving each depositor a unique
Bitcoin address while the master signing key remains shared across the MPC
committee.

> **Note:** for `devnet` the deposit address omits the guardian key and uses a
> single-key script path:
>
> ```
> tr({i}, pk({h}))
> ```
