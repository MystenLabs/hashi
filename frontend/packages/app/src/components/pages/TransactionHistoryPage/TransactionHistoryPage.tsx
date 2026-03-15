import { useNavigate } from 'react-router-dom';
import { useCurrentAccount } from '@mysten/dapp-kit';
import { PageLayout } from '@/components/atoms/PageLayout';
import { PageTitle } from '@/components/atoms/PageTitle';
import { TransactionHistory, type Transaction } from '@/components/organisms/TransactionHistory';
import { useTransactionHistory } from '@/hooks/useTransactionHistory';

export function TransactionHistoryPage() {
	const navigate = useNavigate();
	const account = useCurrentAccount();
	const { data: storedTransactions = [] } = useTransactionHistory();

	const transactions: Transaction[] = storedTransactions.map((tx) => ({
		...tx,
		status: 'pending' as const,
	}));

	return (
		<PageLayout>
			<PageTitle>Transaction History</PageTitle>

			<div className="mx-auto w-full max-w-230">
				<TransactionHistory
					isConnected={!!account}
					transactions={transactions}
					onMakeTransfer={() => navigate('/')}
					onRowClick={(id, direction) => {
						const path = direction === 'btc-to-sui' ? `/deposit/${id}` : `/withdraw/${id}`;
						navigate(path);
					}}
				/>
			</div>
		</PageLayout>
	);
}
