# Hashi Frontend — Local Testing Guide

How to run the frontend against a local devnet and test deposit/withdrawal flows end-to-end.

## Prerequisites

- **Rust toolchain** (`cargo`)
- **Node.js** (v20+) and **pnpm**
- **`bitcoind`** in your PATH (Bitcoin Core)
- **`sui`** in your PATH (Sui CLI) — override with `SUI_BINARY` env var if needed

## 1. Start the localnet

The localnet spins up a Sui network (with faucet), a Bitcoin regtest node, publishes the Hashi Move package, and runs 4 validator nodes that complete DKG automatically.

```bash
# Terminal 1 — keep this running the whole time
cargo run -p e2e-tests -- start
```

Wait until you see output indicating the localnet is ready (validators have completed DKG). This process blocks — leave it running.

You can check status anytime from another terminal:

```bash
cargo run -p e2e-tests -- info    # Print connection details (RPC URLs, package IDs)
cargo run -p e2e-tests -- status   # Check if the process is alive
```

## 2. Start the frontend

```bash
# Terminal 2
cd frontend
pnpm install
pnpm --filter @hashi/app dev:localnet
```

This runs `sync-localnet.sh` (reads `state.json` and generates `.env.localnet` with the correct RPC URLs and package IDs), then starts Vite on `http://localhost:5173`.

> **Note:** If you restart the localnet, you must also restart Vite (`Ctrl+C` then `pnpm --filter @hashi/app dev:localnet` again) so it picks up the new config.

## 3. Connect a wallet

Open `http://localhost:5173` in your browser. Click **Connect Wallet** and select **Unsafe Burner Wallet** (a dev-only in-memory wallet provided by dAppKit).

> The burner wallet generates a new keypair each time the page refreshes. Avoid `Cmd+R` if you want to keep the same address during a test session. annoying....

Copy your wallet address from the header (click the address → Copy Address).

## 4. Fund your wallet with SUI

The burner wallet starts with no SUI for gas. Fund it:

```bash
# Terminal 3
cargo run -p e2e-tests -- faucet-sui <YOUR_SUI_ADDRESS>
```

This sends 1 SUI (1,000,000,000 MIST) to the address. Run it multiple times if needed.

## 5. Test the deposit flow (BTC → suiBTC)

### Option A: Full automated deposit (CLI)

```bash
cargo run -p e2e-tests -- deposit --amount 100000000 --recipient <YOUR_SUI_ADDRESS>
```

This does everything: generates a deposit address, sends BTC from the regtest wallet, mines blocks to confirm, and submits the deposit request on Sui. The validators will process it and mint suiBTC to your address.

Check your balance:

```bash
cargo run -p hashi -- balance <YOUR_SUI_ADDRESS>
```

### Option B: Step-by-step via the frontend

1. On the homepage, select the **Receive suiBTC** tab
2. Enter a BTC amount (e.g. `1`) and click **Review Transfer**
3. On the deposit page, a deposit address is generated — copy it
4. Send BTC to the deposit address from the regtest wallet:

```bash
# Send BTC to the deposit address
curl -s -u test:test \
  --data-binary '{"jsonrpc":"1.0","id":"send","method":"sendtoaddress","params":["<DEPOSIT_ADDRESS>", 1.0]}' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:<BTC_RPC_PORT>/wallet/test

# Mine blocks to confirm (need 10 for the validators to process)
cargo run -p e2e-tests -- mine --blocks 10
```

> Find the BTC RPC port with `cargo run -p e2e-tests -- info` or check `.env.localnet`.

5. Paste the Bitcoin TXID into the frontend. The vout should auto-detect via the Vite proxy
6. Click **Submit Deposit Request** — this signs a Sui transaction
7. The status page polls for validator confirmations. Mine a few more blocks if needed:

```bash
cargo run -p e2e-tests -- mine --blocks 6
```

8. Once validators process the deposit, you'll see "Deposit Completed" and your suiBTC balance updates

## 6. Test the withdrawal flow (suiBTC → BTC)

You need suiBTC in your wallet first (complete a deposit above).

### Generate a BTC address to receive funds

```bash
cargo run -p e2e-tests -- keygen btc
```

This prints a regtest BTC address (e.g. `bcrt1q...`) and saves the private key. Copy the address.

### Submit a withdrawal

1. On the homepage, select the **Withdraw suiBTC** tab
2. Your suiBTC balance should appear with a Max button
3. Enter an amount and click **Review Transfer**
4. Paste the BTC address from above into the **Bitcoin Destination Address** field
5. Click **Confirm & Send** — this burns suiBTC and submits a withdrawal request on Sui
6. The status page tracks the withdrawal through: requested → approved → processing → signed → confirmed

The validators will construct, sign, and broadcast the Bitcoin transaction automatically. You may need to mine blocks for the BTC transaction to confirm:

```bash
cargo run -p e2e-tests -- mine --blocks 6
```

### Verify BTC was received

```bash
# Scan the UTXO set for your address
curl -s -u test:test \
  --data-binary '{"jsonrpc":"1.0","id":"scan","method":"scantxoutset","params":["start",[{"desc":"addr(<YOUR_BTC_ADDRESS>)","range":1000}]]}' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:<BTC_RPC_PORT>/
```

## 7. Useful CLI commands

| Command | Description |
|---|---|
| `cargo run -p e2e-tests -- info` | Print RPC URLs, package ID, object ID |
| `cargo run -p e2e-tests -- mine [--blocks N]` | Mine N bitcoin blocks (default 1) |
| `cargo run -p e2e-tests -- faucet-sui <ADDR> [--amount MIST]` | Send SUI to an address (default 1 SUI) |
| `cargo run -p e2e-tests -- faucet-btc <ADDR> [--blocks N]` | Mine N blocks to a BTC address (~50 BTC each) |
| `cargo run -p e2e-tests -- deposit --amount <SATS> [--recipient <SUI_ADDR>]` | Full automated deposit flow |
| `cargo run -p e2e-tests -- keygen btc` | Generate a regtest BTC keypair |
| `cargo run -p e2e-tests -- keygen sui` | Generate a Sui Ed25519 keypair |
| `cargo run -p hashi -- balance <SUI_ADDR>` | Check suiBTC balance |
| `cargo run -p hashi -- deposit list` | List deposit requests |
| `cargo run -p hashi -- withdraw list` | List withdrawal requests |

## 8. Troubleshooting

**"No suiBTC coins found in wallet"**
Your wallet doesn't have any suiBTC. Complete a deposit first, or use the automated CLI deposit.

**Deposit stuck on "Pending"**
The validators may need more Bitcoin confirmations. Mine more blocks: `cargo run -p e2e-tests -- mine --blocks 10`

**Vout auto-lookup not working**
Check the browser console for errors. The Vite dev proxy at `/btc-rpc` forwards requests to bitcoind to avoid CORS. Make sure Vite was restarted after the localnet.

**Balance shows on homepage but withdrawal fails**
The suiBTC may be stored as an address-level balance (a Sui feature). The withdrawal hook uses `coinWithBalance` to handle this automatically — make sure you have the latest code.

**Localnet restarted but frontend shows stale data**
Restart Vite (`Ctrl+C` then `pnpm --filter @hashi/app dev:localnet`). The sync script regenerates `.env.localnet` with the new package IDs and RPC ports.

**Withdrawal stuck on "BTC sent to Bitcoin wallet"**
Mine blocks so the validators can confirm the BTC transaction: `cargo run -p e2e-tests -- mine --blocks 6`
