import { useQuery } from '@tanstack/react-query';
import { useCurrentAccount } from '@mysten/dapp-kit';
import { QueryKeys } from '@/lib/queryKeys';
import { getTransactions, type StoredTransaction } from '@/lib/transactionHistory';

export function useTransactionHistory() {
	const account = useCurrentAccount();
	const address = account?.address;

	return useQuery({
		queryKey: [QueryKeys.History, address],
		queryFn: (): StoredTransaction[] => {
			if (!address) return [];
			return getTransactions(address);
		},
		enabled: !!address,
	});
}
