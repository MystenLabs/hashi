import { useQuery } from '@tanstack/react-query';
import { useSuiClient, useCurrentAccount } from '@mysten/dapp-kit';
import { Transaction, coinWithBalance } from '@mysten/sui/transactions';
import { requestWithdrawal } from '@hashi/contracts/src/hashi/withdraw';
import { CONFIG } from '@/lib/constants';

// Bitcoin transaction weight constants (from Move contract)
const TX_FIXED_VB = 11n;
const INPUT_VB = 100n;
const OUTPUT_VB = 43n;
const NUM_OUTPUTS = 2n;
const DUST_RELAY_MIN_VALUE = 546n;

interface WithdrawalFees {
	/** Protocol withdrawal fee in satoshis */
	withdrawalFeeSats: bigint;
	/** Protocol withdrawal fee formatted */
	withdrawalFeeLabel: string;
	/** Worst-case BTC network fee in satoshis */
	worstCaseNetworkFeeSats: bigint;
	/** BTC network fee formatted as range */
	btcNetworkFeeLabel: string;
	/** Minimum withdrawal amount in satoshis */
	withdrawalMinimumSats: bigint;
	/** Minimum withdrawal amount in BTC */
	withdrawalMinimumBtc: string;
	/** Estimated gas cost in MIST */
	gasEstimateMist: bigint;
	/** Estimated gas cost formatted as SUI string */
	gasEstimateSui: string;
}

function formatMistToSui(mist: bigint): string {
	const sui = Number(mist) / 1e9;
	if (sui === 0) return '0 SUI';
	if (sui < 0.001) return '<0.001 SUI';
	return `${sui.toFixed(4).replace(/0+$/, '').replace(/\.$/, '')} SUI`;
}

function formatSats(sats: bigint): string {
	return sats.toLocaleString() + ' sats';
}

function formatSatsCompact(sats: bigint): string {
	const n = Number(sats);
	if (n >= 1000) return Math.round(n / 1000) + 'k';
	return n.toString();
}

function getConfigValue(contents: Array<Record<string, unknown>>, key: string): bigint {
	for (const entry of contents) {
		const entryFields = entry.fields as Record<string, unknown> | undefined;
		if (entryFields?.key === key) {
			const valueObj = entryFields.value as Record<string, unknown>;
			if (valueObj?.variant === 'U64') {
				const valFields = valueObj.fields as Record<string, string>;
				return BigInt(valFields.pos0 ?? '0');
			}
			break;
		}
	}
	return 0n;
}

export function useWithdrawalFees() {
	const client = useSuiClient();
	const account = useCurrentAccount();
	const sender = account?.address;

	return useQuery<WithdrawalFees | null>({
		queryKey: ['withdrawal-fees', sender],
		queryFn: async () => {
			if (!CONFIG.HASHI_OBJECT_ID || !CONFIG.HASHI_PACKAGE_ID) return null;

			const hashiObject = await client.getObject({
				id: CONFIG.HASHI_OBJECT_ID,
				options: { showContent: true },
			});

			const content = hashiObject.data?.content;
			if (!content || content.dataType !== 'moveObject') return null;

			const fields = content.fields as Record<string, unknown>;
			const configField = fields.config as Record<string, unknown> | undefined;
			const configFields = configField?.fields as Record<string, unknown> | undefined;
			const configMap = configFields?.config as Record<string, unknown> | undefined;
			const configMapFields = configMap?.fields as Record<string, unknown> | undefined;
			const contents = configMapFields?.contents as Array<Record<string, unknown>> | undefined;

			if (!contents) return null;

			// Read config values
			let withdrawalFeeSats = getConfigValue(contents, 'withdrawal_fee_btc');
			if (withdrawalFeeSats < DUST_RELAY_MIN_VALUE) withdrawalFeeSats = DUST_RELAY_MIN_VALUE;

			const maxFeeRate = getConfigValue(contents, 'max_fee_rate') || 25n;
			const maxInputs = getConfigValue(contents, 'max_inputs') || 10n;

			// Calculate network fee bounds
			// Best case: 1 sat/vB, 1 input
			const minTxVbytes = TX_FIXED_VB + 1n * INPUT_VB + NUM_OUTPUTS * OUTPUT_VB;
			const bestCaseNetworkFeeSats = minTxVbytes; // 1 sat/vB * vbytes
			// Worst case: max_fee_rate, max_inputs
			const maxTxVbytes = TX_FIXED_VB + maxInputs * INPUT_VB + NUM_OUTPUTS * OUTPUT_VB;
			const worstCaseNetworkFeeSats = maxFeeRate * maxTxVbytes;

			// Minimum withdrawal = protocol fee + worst-case network fee + dust
			const withdrawalMinimumSats = withdrawalFeeSats + worstCaseNetworkFeeSats + DUST_RELAY_MIN_VALUE;
			const withdrawalMinimumBtc = (Number(withdrawalMinimumSats) / 1e8).toString();

			// Estimate gas
			let gasEstimateMist = 0n;
			if (sender) {
				try {
					const pkg = CONFIG.HASHI_PACKAGE_ID;
					const tx = new Transaction();
					const btcCoinType = `${pkg}::btc::BTC`;

					const btcCoin = tx.add(coinWithBalance({ type: btcCoinType, balance: 100000n }));
					const dummyAddress = Array(20).fill(0);
					tx.add(requestWithdrawal({ package: pkg, arguments: { hashi: CONFIG.HASHI_OBJECT_ID, btc: btcCoin, bitcoinAddress: dummyAddress } }));

					const result = await client.devInspectTransactionBlock({
						transactionBlock: tx,
						sender,
					});

					if (result.effects?.gasUsed) {
						const gas = result.effects.gasUsed;
						const total = BigInt(gas.computationCost) + BigInt(gas.storageCost) - BigInt(gas.storageRebate);
						gasEstimateMist = total > 0n ? (total * 120n) / 100n : 0n;
					}
				} catch {
					// devInspect may fail — gas estimate is best-effort
				}
			}

			return {
				withdrawalFeeSats,
				withdrawalFeeLabel: formatSats(withdrawalFeeSats),
				worstCaseNetworkFeeSats,
				btcNetworkFeeLabel: `${formatSatsCompact(bestCaseNetworkFeeSats)}–${formatSatsCompact(worstCaseNetworkFeeSats)} sats`,
				withdrawalMinimumSats,
				withdrawalMinimumBtc,
				gasEstimateMist,
				gasEstimateSui: gasEstimateMist > 0n ? `~${formatMistToSui(gasEstimateMist)}` : '~0.003 SUI',
			};
		},
		enabled: !!CONFIG.HASHI_OBJECT_ID,
		staleTime: 60_000,
	});
}
