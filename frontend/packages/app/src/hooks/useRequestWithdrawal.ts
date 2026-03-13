import { useQueryClient } from '@tanstack/react-query';
import { useCurrentAccount, useSignAndExecuteTransaction } from '@mysten/dapp-kit';
import { Transaction, coinWithBalance } from '@mysten/sui/transactions';
import { requestWithdrawal } from '@hashi/contracts/src/hashi/withdraw';
import { CONFIG } from '@/lib/constants';
import { QueryKeys } from '@/lib/queryKeys';

interface RequestWithdrawalParams {
	amountSats: bigint;
	bitcoinAddress: number[];
}

export function useRequestWithdrawal() {
	const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();
	const account = useCurrentAccount();
	const queryClient = useQueryClient();

	return {
		mutateAsync: async ({ amountSats, bitcoinAddress }: RequestWithdrawalParams) => {
			if (!account) throw new Error('Wallet not connected');

			const tx = new Transaction();
			const pkg = CONFIG.HASHI_PACKAGE_ID;
			const btcCoinType = `${pkg}::btc::BTC`;

			// Use coinWithBalance intent — handles both address balances and coin objects
			const btcCoin = tx.add(coinWithBalance({ type: btcCoinType, balance: amountSats }));

			// Split zero SUI for fee (withdrawal fee — may need real amount from config)
			const [feeCoin] = tx.splitCoins(tx.gas, [0]);

			tx.add(
				requestWithdrawal({
					package: pkg,
					arguments: {
						hashi: CONFIG.HASHI_OBJECT_ID,
						btc: btcCoin,
						bitcoinAddress,
						fee: feeCoin,
					},
				}),
			);

			const result = await signAndExecute({ transaction: tx });

			queryClient.invalidateQueries({ queryKey: [QueryKeys.WithdrawalStatus] });
			queryClient.invalidateQueries({ queryKey: [QueryKeys.Balance] });
			queryClient.invalidateQueries({ queryKey: [QueryKeys.History] });

			return result;
		},
	};
}
