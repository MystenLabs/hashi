# Networks

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> Hashi Testnet and Mainnet parameters: Sui and Bitcoin chain IDs, package and object IDs, endpoints, ports, and release tags.

Hashi is network-specific: the Sui chain, the Bitcoin chain, and their endpoints all differ per deployment. Testnet pairs Sui Testnet with Bitcoin Signet, and Mainnet pairs Sui Mainnet with Bitcoin Mainnet. The tabbed examples in the Validators pages already carry the values from the matching column.

Hashi enforces the pairing rather than just documenting it: Bitcoin Mainnet goes with Sui Mainnet and nothing else. `hashi launch` refuses to build the launch transaction when its `--bitcoin-chain-id` does not match the chain the fullnode reports under that rule, and a node refuses to start (as does `hashi register`) when the validator config's `bitcoin-chain-id` is Mainnet on any other Sui network or is not Mainnet on Sui Mainnet.

| Parameter | Testnet | Mainnet |
|-----------|---------|---------|
| Sui network | Testnet | Mainnet |
| `sui-chain-id` | `69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD` | `4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S` |
| Sui fullnode (`sui-rpc`) | Public (`https://fullnode.testnet.sui.io:443`) or self-hosted | Self-hosted; see [Sui RPC](../validators/prerequisites.mdx#sui-rpc) |
| Bitcoin network | Signet | Mainnet |
| `bitcoin-chain-id` (genesis block hash) | `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6` | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` |
| `[bitcoin].network` | `signet` | `mainnet` |
| Bitcoin RPC port (default) | 38332 | 8332 |
| Bitcoin P2P port (default) | 38333 | 8333 |
| `package-id` | `0x5e0b99c31f691742acea5de4ca1bf53c398d5639fed6503a51ffe8035dc68485` | `0xd30fb3f8914efdbeb7b8e85fae1d65dc584b44a1281f66737b92bb9f03a59d06` |
| `hashi-object-id` | `0x342e908043db6090558ed7766df95bfc3609881b2eac7edb5343dd5bb3ddd1bb` | `0x8d110642d9b5133bd661cda4873edf135ab6b91ff6918601015880874b950e5d` |
| `[metrics-push].push-url` | `https://metrics-proxy.testnet.sui.io:8443/publish/metrics` | `https://metrics-proxy.mainnet.sui.io:8443/publish/metrics` |
| Release tags | `testnet-X.Y` | `mainnet-X.Y` |

> You reach a self-hosted Sui fullnode at its RPC port (default `9000`) on any network. Hashi's built-in default for `bitcoin-rpc` is `http://localhost:8332` (the Mainnet port), so on Signet you must set the port explicitly, and on Mainnet you set the host when the Bitcoin node runs elsewhere.
