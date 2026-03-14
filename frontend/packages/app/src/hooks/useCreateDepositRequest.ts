import { useQueryClient } from '@tanstack/react-query';
import { useCurrentAccount, useSignAndExecuteTransaction } from '@mysten/dapp-kit';
import { Transaction } from '@mysten/sui/transactions';
import { utxoId as createUtxoId, utxo as createUtxo } from '@hashi/contracts/src/hashi/utxo';
import { depositRequest as createDepositRequest } from '@hashi/contracts/src/hashi/deposit_queue';
import { deposit } from '@hashi/contracts/src/hashi/deposit';
import { CONFIG } from '@/lib/constants';
import { QueryKeys } from '@/lib/queryKeys';

interface CreateDepositParams {
	txid: string;
	vout: number;
	amountSats: bigint;
	recipient: string;
	depositFeeMist?: bigint;
}

export function useCreateDepositRequest() {
	const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();
	const account = useCurrentAccount();
	const queryClient = useQueryClient();

	return {
		mutateAsync: async ({ txid, vout, amountSats, recipient, depositFeeMist = 0n }: CreateDepositParams) => {
			if (!account) throw new Error('Wallet not connected');

			// Bitcoin txids are displayed in reversed byte order.
			// The Move contract expects internal byte order (reversed from display).
			// This matches the Rust CLI: Txid::parse(hex).to_byte_array()
			const txidBytes = txid.replace(/^0x/, '').match(/.{2}/g);
			if (!txidBytes || txidBytes.length !== 32) throw new Error('Invalid txid: must be 64 hex characters');
			const reversedTxid = '0x' + txidBytes.reverse().join('');

			const tx = new Transaction();
			const pkg = CONFIG.HASHI_PACKAGE_ID;

			// 1. Create UtxoId from txid + vout
			const [utxoIdResult] = tx.add(
				createUtxoId({
					package: pkg,
					arguments: { txid: reversedTxid, vout },
				}),
			);

			// 2. Create Utxo from UtxoId + amount + derivation_path (recipient)
			const [utxoResult] = tx.add(
				createUtxo({
					package: pkg,
					arguments: {
						utxoId: utxoIdResult,
						amount: amountSats,
						derivationPath: recipient,
					},
				}),
			);

			// 3. Create DepositRequest from Utxo + Clock
			const [requestResult] = tx.add(
				createDepositRequest({
					package: pkg,
					arguments: { utxo: utxoResult },
				}),
			);

			// 4. Split SUI for the protocol deposit fee
			const [feeCoin] = tx.splitCoins(tx.gas, [depositFeeMist]);

			// 5. Call deposit(hashi, request, fee)
			tx.add(
				deposit({
					package: pkg,
					arguments: {
						hashi: CONFIG.HASHI_OBJECT_ID,
						request: requestResult,
						fee: feeCoin,
					},
				}),
			);

			const result = await signAndExecute({ transaction: tx });

			queryClient.invalidateQueries({ queryKey: [QueryKeys.DepositStatus] });
			queryClient.invalidateQueries({ queryKey: [QueryKeys.History] });

			return result;
		},
	};
}
