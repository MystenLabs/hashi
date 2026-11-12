# Run a Hashi Node

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> How Sui validators join the Hashi committee and run a Hashi node, with the onboarding steps, common questions, and links to each operator guide.

---

These pages are for Sui validators joining the Hashi committee. They cover prerequisites, configuration, genesis, ongoing operations, and governance.

Hashi is a Sui-native **asset orchestration protocol** that secures and manages native BTC for use on Sui through threshold cryptography. [Committee](../committee.mdx) members run the `hashi` service alongside their Sui validator to participate in MPC threshold Schnorr signing for Bitcoin custody. The committee collectively manages a Bitcoin master key, and no single validator ever holds the full key. The work your node performs is the [deposit](../deposit.mdx) and [withdrawal](../withdraw.mdx) flows, plus [reconfiguration](../reconfiguration.mdx) at every epoch boundary.

The pages cover both Hashi deployments, Testnet and Mainnet. The [Networks](../reference/networks.mdx) table gives each network's status and parameters. Network-specific examples come in **Mainnet** and **Testnet** tabs: pick your network in any one of them and the rest of the section follows. Everywhere else, use the column for your **target network**.

## Joining the committee

Onboarding takes 6 steps. The pages in this section cover the detail, the defaults, and the failure modes:

1. **Provision the two external dependencies:** a Bitcoin archival node (`txindex`, `blockfilterindex`, `peerblockfilters`) and a Sui fullnode serving the gRPC v2 API. On Mainnet, run the Sui fullnode yourself; running the Bitcoin node yourself is strongly encouraged. For a Mainnet Bitcoin node, provision 2TB of SSD storage. See [External service dependencies](prerequisites.mdx#external-service-dependencies), [Sui RPC](prerequisites.mdx#sui-rpc), and [Bitcoin node](prerequisites.mdx#bitcoin-node).
2. **Generate keys:** a dedicated TLS key, a fresh operator key funded with at least 2 SUI, and an OpenPGP backup key. See [TLS key (dedicated)](keys.mdx#tls-key-dedicated), [Operator key (day-to-day signing)](keys.mdx#operator-key-day-to-day-signing), and [Backup key (OpenPGP)](keys.mdx#backup-key-openpgp).
3. **Write the validator config:** use your target network's column in [Networks](../reference/networks.mdx). See [Validator config](configuration.mdx#validator-config).
4. **Register your validator:** run `hashi register --serialize-unsigned-transaction` and sign the result offline with your Sui validator account key. See [Registration must be signed by the account key](keys.mdx#registration-must-be-signed-by-the-account-key) and [Step 2: register your validator](genesis.mdx#step-2-register-your-validator).
5. **Start the node:** run `hashi server` and keep it online, including across epoch boundaries. See [Step 3: start the server](genesis.mdx#step-3-start-the-server) and [Epoch Changes](epoch-changes.mdx).
6. **Monitor the node:** watch the key metrics and push them to the Mysten collection endpoint. See [Monitoring and Alerts](monitoring.mdx).

These details trip up most operators:

- Your Sui validator account key must sign the initial registration. The operator key cannot. See [Registration must be signed by the account key](keys.mdx#registration-must-be-signed-by-the-account-key).
- Hashi defaults `bitcoin-rpc` to port `8332`, the Mainnet port. On Testnet (Bitcoin Signet) you must set `38332` explicitly. See [Bitcoin node](prerequisites.mdx#bitcoin-node).
- A self-hosted Sui fullnode needs `rpc.enable-indexing: true` in its own config, which is off by default. See [Sui RPC](prerequisites.mdx#sui-rpc).
- Fund the operator address with at least 2 SUI. With exactly 1 SUI, the node's gas bootstrap fails with `InsufficientCoinBalance` and retries every 10 minutes until you add SUI. See [Operator key (day-to-day signing)](keys.mdx#operator-key-day-to-day-signing).

## Common questions

These answers summarize details from the pages in this section.

### Does the Hashi node connect to your Sui validator?

The node's Sui connection is to a Sui fullnode ([Sui RPC](prerequisites.mdx#sui-rpc)), not to your validator, and the Hashi node should run on a separate host from your Sui validator ([Resources](prerequisites.mdx#resources)). The link to your validator is onchain: `validator-address` in the validator config is your Sui validator address, and your validator account key signs the initial registration ([Registration must be signed by the account key](keys.mdx#registration-must-be-signed-by-the-account-key)).

### Which validators can run a Hashi node?

Only active Sui validators. Onchain registration asserts that the sender is in the Sui active validator set, so the registration must come from your Sui validator account key ([Registration must be signed by the account key](keys.mdx#registration-must-be-signed-by-the-account-key), [Registration and offline signing](troubleshooting.mdx#registration-and-offline-signing)). [Committee](../committee.mdx#why-the-committee-is-not-exactly-the-set-of-sui-validators) explains why the committee is not exactly the set of Sui validators.

### Do you need to generate a backup key?

Yes. The backup key is required: `backup-pgp-cert` and `backup-dir` are both required in the validator config. Generate an OpenPGP key on a YubiKey or locally with `sq` or `gpg`, and give the node only the public certificate. See [Backup key (OpenPGP)](keys.mdx#backup-key-openpgp) and [Hashi Node Backups](../node-backup.mdx).

### How much storage does the Bitcoin node need on Mainnet?

Provision 2TB of SSD storage for a self-hosted archival Mainnet Bitcoin node with `txindex` and `blockfilterindex`; see the Mainnet tab of [Bitcoin node](prerequisites.mdx#bitcoin-node). This is separate from the Hashi process itself, which needs 10GB of persistent storage ([Resources](prerequisites.mdx#resources)).

### What does a Mainnet node depend on?

A Mainnet node depends on:

- A self-hosted Sui fullnode serving the gRPC v2 API with `rpc.enable-indexing: true`
- An archival Bitcoin Core v29 or newer node reachable over both JSON-RPC and P2P (self-hosting is strongly encouraged)
- A dedicated TLS key
- An operator key funded with at least 2 SUI
- An OpenPGP backup key

See [External service dependencies](prerequisites.mdx#external-service-dependencies), [Sui RPC](prerequisites.mdx#sui-rpc), [Bitcoin node](prerequisites.mdx#bitcoin-node), and [Keys and Security](keys.mdx).

## Pages in this section
