# Bitcoin address scheme

All Hashi addresses are 2-of-2 Taproot addresses between Hashi and the Guardian, where the 2-of-2 script is encoded as the sole leaf in the Taproot tree.

The exact [descriptor](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md) is `tr({i},multi_a(2,{h},{g}))` where 

- `h` is hashi's public key, derived from a fixed master key and a variable derivation path (e.g., the sui address of the depositor)
- `g` is the guardian's fixed public key
- `i` is a fixed nothing-up-my-sleeve internal key with no known private key, ensuring all spends occur via the script path
