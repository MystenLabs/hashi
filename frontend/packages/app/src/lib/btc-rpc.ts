import { CONFIG } from '@/lib/constants';

/**
 * Look up a Bitcoin transaction and find the output index (vout)
 * that pays to the given deposit address.
 *
 * Uses Bitcoin Core JSON-RPC when VITE_BTC_RPC_URL is configured (localnet/regtest).
 * Returns { vout, amount } on success, or null if not found.
 */
export async function lookupVout(
	txid: string,
	depositAddress: string,
): Promise<{ vout: number; amountSats: bigint } | null> {
	if (!CONFIG.BTC_RPC_URL) return null;

	// In dev, requests go through Vite's proxy at /btc-rpc to avoid CORS.
	// The proxy forwards to the actual BTC_RPC_URL configured in .env.
	const url = import.meta.env.DEV ? '/btc-rpc' : CONFIG.BTC_RPC_URL;

	const auth = CONFIG.BTC_RPC_USER
		? 'Basic ' + btoa(`${CONFIG.BTC_RPC_USER}:${CONFIG.BTC_RPC_PASSWORD}`)
		: undefined;

	const res = await fetch(url, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			...(auth ? { Authorization: auth } : {}),
		},
		body: JSON.stringify({
			jsonrpc: '1.0',
			id: 'lookup-vout',
			method: 'getrawtransaction',
			params: [txid, true], // verbose = true → returns decoded tx
		}),
	});

	const data = await res.json();
	if (data.error) throw new Error(data.error.message);

	const tx = data.result;
	for (const output of tx.vout) {
		if (output.scriptPubKey?.address === depositAddress) {
			const amountSats = BigInt(Math.round(output.value * 1e8));
			return { vout: output.n, amountSats };
		}
	}

	return null;
}
