import { PageLayout } from '@/components/atoms/PageLayout';
import { PageTitle } from '@/components/atoms/PageTitle';
import { TransactionHistory } from '@/components/organisms/TransactionHistory';

export function TransactionHistoryPage() {
	return (
		<PageLayout>
			<PageTitle>Transaction History</PageTitle>

			<div className="w-full max-w-230">
				<TransactionHistory isConnected transactions={[]} />
			</div>
		</PageLayout>
	);
}
