import { useQuery } from '@tanstack/react-query';
import { useSuiClient, useCurrentAccount } from '@mysten/dapp-kit';
import { Transaction } from '@mysten/sui/transactions';
import { utxoId as createUtxoId, utxo as createUtxo } from '@hashi/contracts/src/hashi/utxo';
import { depositRequest as createDepositRequest } from '@hashi/contracts/src/hashi/deposit_queue';
import { deposit } from '@hashi/contracts/src/hashi/deposit';
import { CONFIG } from '@/lib/constants';

interface DepositFees {
	/** Protocol deposit fee in MIST */
	depositFeeMist: bigint;
	/** Protocol deposit fee formatted as sats string */
	depositFeeSats: string;
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

export function useDepositFees() {
	const client = useSuiClient();
	const account = useCurrentAccount();
	const sender = account?.address;

	return useQuery<DepositFees | null>({
		queryKey: ['deposit-fees', sender],
		queryFn: async () => {
			if (!sender || !CONFIG.HASHI_OBJECT_ID || !CONFIG.HASHI_PACKAGE_ID) return null;

			// 1. Fetch deposit_fee from the Hashi config
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

			let depositFeeMist = 0n;
			if (contents) {
				for (const entry of contents) {
					const entryFields = entry.fields as Record<string, unknown> | undefined;
					if (entryFields?.key === 'deposit_fee') {
						const valueObj = entryFields.value as Record<string, unknown>;
						// On-chain shape: { variant: "U64", fields: { pos0: "0" } }
						if (valueObj?.variant === 'U64') {
							const valFields = valueObj.fields as Record<string, string>;
							depositFeeMist = BigInt(valFields.pos0 ?? '0');
						}
						break;
					}
				}
			}

			// 2. Estimate gas via devInspectTransactionBlock with a mock deposit tx
			let gasEstimateMist = 0n;
			try {
				const pkg = CONFIG.HASHI_PACKAGE_ID;
				const tx = new Transaction();

				// Use a dummy txid/vout — devInspect won't actually execute
				const dummyTxid = '0x' + '00'.repeat(32);
				const [utxoIdResult] = tx.add(createUtxoId({ package: pkg, arguments: { txid: dummyTxid, vout: 0 } }));
				const [utxoResult] = tx.add(createUtxo({ package: pkg, arguments: { utxoId: utxoIdResult, amount: 100000n, derivationPath: sender } }));
				const [requestResult] = tx.add(createDepositRequest({ package: pkg, arguments: { utxo: utxoResult } }));
				const [feeCoin] = tx.splitCoins(tx.gas, [depositFeeMist]);
				tx.add(deposit({ package: pkg, arguments: { hashi: CONFIG.HASHI_OBJECT_ID, request: requestResult, fee: feeCoin } }));

				const result = await client.devInspectTransactionBlock({
					transactionBlock: tx,
					sender,
				});

				if (result.effects?.gasUsed) {
					const gas = result.effects.gasUsed;
					const total =
						BigInt(gas.computationCost) +
						BigInt(gas.storageCost) -
						BigInt(gas.storageRebate);
					// Add 20% buffer for safety margin
					gasEstimateMist = total > 0n ? (total * 120n) / 100n : 0n;
				}
			} catch {
				// devInspect may fail (e.g. duplicate utxo, missing state) — that's ok,
				// gas estimate is best-effort
			}

			return {
				depositFeeMist,
				depositFeeSats: depositFeeMist > 0n ? `${depositFeeMist.toString()} sats` : '— sats',
				gasEstimateMist,
				gasEstimateSui: gasEstimateMist > 0n ? `~${formatMistToSui(gasEstimateMist)}` : '~0.003 SUI',
			};
		},
		enabled: !!sender && !!CONFIG.HASHI_OBJECT_ID,
		staleTime: 60_000,
	});
}
