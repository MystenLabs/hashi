import { cva } from 'class-variance-authority';
import { Button } from '@/components/atoms/Button';
import { Icon } from '@/components/atoms/Icon';
import { PageContent } from '@/components/atoms/PageContent';

type TransactionStatus = 'pending' | 'confirming' | 'complete' | 'failed';
type TransactionDirection = 'btc-to-sui' | 'sui-to-btc';

export interface Transaction {
	id: string;
	direction: TransactionDirection;
	amount: string;
	currency: 'BTC' | 'suiBTC';
	status: TransactionStatus;
	date: string;
}

interface TransactionHistoryProps {
	transactions?: Transaction[];
	isConnected?: boolean;
	onMakeTransfer?: () => void;
	onConnectWallet?: () => void;
	onRowClick?: (id: string) => void;
	className?: string;
}

const EmptyIcon = () => (
	<div className="flex h-20 w-20 items-center justify-center rounded-xs bg-white/12">
		<svg
			viewBox="0 0 32 32"
			fill="none"
			stroke="currentcolor"
			strokeWidth="2"
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-8 w-8 opacity-60"
		>
			<path d="M14 22L10 26L6 22" />
			<path d="M10 6V26" />
			<path d="M18 10L22 6L26 10" />
			<path d="M22 26V6" />
		</svg>
	</div>
);

const badgeVariants = cva('inline-flex text-sm px-2 -my-0.5 py-0.5 capitalize', {
	variants: {
		variant: {
			pending: 'bg-[#A15A00]/32 text-[#FFB252]',
			confirming: 'bg-[#9D9D00]/32 text-[#FFFF7A]',
			complete: 'bg-[#005C31]/32 text-[#94FFCD]',
			failed: 'bg-[#A50000]/32 text-[#FFB8B8]',
		},
	},
	defaultVariants: {
		variant: 'pending',
	},
});

function StatusBadge({ status }: { status: TransactionStatus }) {
	return <span className={badgeVariants({ variant: status })}>{status}</span>;
}

function DirectionLabel({ direction }: { direction: TransactionDirection }) {
	const isBtcToSui = direction === 'btc-to-sui';
	return (
		<div className="flex items-center gap-1.5">
			<span className="font-bold">{isBtcToSui ? 'BTC' : 'suiBTC'}</span>
			<Icon
				name="ArrowRight"
				className={'h-4 w-4' + (isBtcToSui ? ' text-valid' : ' text-orange')}
			/>
			<span className="opacity-60">{isBtcToSui ? 'suiBTC' : 'BTC'}</span>
		</div>
	);
}

function TableHeader() {
	const cols = ['Direction', 'Amount', 'Status', 'Date & Time'];
	return (
		<thead>
			<tr>
				{cols.map((col) => (
					<th key={col} className="p-3 text-left font-normal opacity-60 first:pl-0 last:pr-0">
						{col}
					</th>
				))}
			</tr>
		</thead>
	);
}

function TableRow({ transaction, onClick }: { transaction: Transaction; onClick?: () => void }) {
	return (
		<tr onClick={onClick} className="cursor-pointer">
			<td className="border-t border-white/12 p-3 pl-0">
				<DirectionLabel direction={transaction.direction} />
			</td>
			<td className="border-t border-white/12 p-3">
				<div className="flex items-center gap-1.5 leading-none">
					<Icon name={transaction.currency} />
					<span>
						{transaction.amount}
						<span className="ml-1 text-xs leading-none text-white/60">
							{transaction.currency}
						</span>
					</span>
				</div>
			</td>
			<td className="border-t border-white/12 p-3">
				<StatusBadge status={transaction.status} />
			</td>
			<td className="border-t border-white/12 p-3">{transaction.date}</td>
			<td className="w-1 border-t border-white/12 p-3 pr-0">
				<Icon name="CaretDown" className="-rotate-90" />
			</td>
		</tr>
	);
}

function EmptyState({ onMakeTransfer }: { onMakeTransfer?: () => void }) {
	return (
		<div className="flex flex-col items-center justify-center gap-6 py-16">
			<EmptyIcon />
			<h3 className="font-book text-lg leading-none">No Transactions</h3>
			<p className="max-w-90 text-center text-sm text-current/60">
				Once you connect your SUI wallet and start making transactions, they'll appear here. Your
				full activity history will be organized in one place for easy tracking.
			</p>
			<Button variant="secondary" onClick={onMakeTransfer}>
				Make a Transfer
			</Button>
		</div>
	);
}

function NotConnectedState({ onConnectWallet }: { onConnectWallet?: () => void }) {
	return (
		<div className="flex flex-col items-center justify-center gap-6 py-16">
			<EmptyIcon />
			<h3 className="font-book text-lg leading-none">Wallet not Connected</h3>
			<p className="max-w-90 text-center text-sm text-current/60">
				Once you connect your SUI wallet and start making transactions, they'll appear here. Your
				full activity history will be organized in one place for easy tracking.
			</p>
			<Button variant="secondary" leadingIcon={<Icon name="SUI" />} onClick={onConnectWallet}>
				Connect Wallet
			</Button>
		</div>
	);
}

export function TransactionHistory({
	transactions = [],
	isConnected = true,
	onMakeTransfer,
	onConnectWallet,
	onRowClick,
	className,
}: TransactionHistoryProps) {
	const hasTransactions = transactions.length > 0;

	return (
		<div className={className}>
			{isConnected && hasTransactions && (
				<h2 className="font-book mb-5 text-xl leading-none">
					{transactions.length} Transactions
				</h2>
			)}

			<PageContent className="max-w-none">
				{!isConnected ? (
					<NotConnectedState onConnectWallet={onConnectWallet} />
				) : !hasTransactions ? (
					<EmptyState onMakeTransfer={onMakeTransfer} />
				) : (
					<table className="mx-3 border-collapse leading-none">
						<TableHeader />
						<tbody>
							{transactions.map((tx) => (
								<TableRow
									key={tx.id}
									transaction={tx}
									onClick={() => onRowClick?.(tx.id)}
								/>
							))}
						</tbody>
					</table>
				)}
			</PageContent>
		</div>
	);
}
