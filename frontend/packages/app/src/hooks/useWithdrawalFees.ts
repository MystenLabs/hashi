import { useQuery } from '@tanstack/react-query';
import { useSuiClient, useCurrentAccount } from '@mysten/dapp-kit';
import { Transaction, coinWithBalance } from '@mysten/sui/transactions';
import { requestWithdrawal } from '@hashi/contracts/src/hashi/withdraw';
import { CONFIG } from '@/lib/constants';

interface WithdrawalFees {
	/** Protocol withdrawal fee in satoshis */
	withdrawalFeeSats: bigint;
	/** Protocol withdrawal fee formatted */
	withdrawalFeeLabel: string;
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

export function useWithdrawalFees() {
	const client = useSuiClient();
	const account = useCurrentAccount();
	const sender = account?.address;

	return useQuery<WithdrawalFees | null>({
		queryKey: ['withdrawal-fees', sender],
		queryFn: async () => {
			if (!CONFIG.HASHI_OBJECT_ID || !CONFIG.HASHI_PACKAGE_ID) return null;

			// 1. Fetch withdrawal_fee_btc from the Hashi config
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

			let withdrawalFeeSats = 0n;
			if (contents) {
				for (const entry of contents) {
					const entryFields = entry.fields as Record<string, unknown> | undefined;
					if (entryFields?.key === 'withdrawal_fee_btc') {
						const valueObj = entryFields.value as Record<string, unknown>;
						if (valueObj?.variant === 'U64') {
							const valFields = valueObj.fields as Record<string, string>;
							withdrawalFeeSats = BigInt(valFields.pos0 ?? '0');
						}
						break;
					}
				}
			}

			// 2. Estimate gas via devInspectTransactionBlock with a mock withdrawal tx
			let gasEstimateMist = 0n;
			if (sender) {
				try {
					const pkg = CONFIG.HASHI_PACKAGE_ID;
					const tx = new Transaction();
					const btcCoinType = `${pkg}::btc::BTC`;

					const btcCoin = tx.add(coinWithBalance({ type: btcCoinType, balance: 100000n }));
					// Dummy 20-byte P2WPKH address
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
				withdrawalFeeLabel: `${withdrawalFeeSats.toString()} sats`,
				gasEstimateMist,
				gasEstimateSui: gasEstimateMist > 0n ? formatMistToSui(gasEstimateMist) : '~0.003 SUI',
			};
		},
		enabled: !!CONFIG.HASHI_OBJECT_ID,
		staleTime: 60_000,
	});
}
