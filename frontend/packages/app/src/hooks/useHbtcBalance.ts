import { useQuery } from '@tanstack/react-query';
import { useCurrentAccount, useSuiClient } from '@mysten/dapp-kit';
import { QueryKeys } from '@/lib/queryKeys';
import { CONFIG } from '@/lib/constants';

export function useHbtcBalance() {
	const client = useSuiClient();
	const account = useCurrentAccount();

	return useQuery({
		queryKey: [QueryKeys.Balance, account?.address],
		queryFn: async () => {
			if (!account) return null;

			const balance = await client.getBalance({
				owner: account.address,
				coinType: `${CONFIG.HASHI_PACKAGE_ID}::btc::BTC`,
			});

			return {
				totalBalance: BigInt(balance.totalBalance),
				coinObjectCount: balance.coinObjectCount,
			};
		},
		enabled: !!account,
		refetchInterval: 30_000,
	});
}
