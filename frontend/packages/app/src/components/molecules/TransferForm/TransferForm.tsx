import { useState, useRef, useLayoutEffect } from 'react';
import { useCurrentAccount, ConnectModal } from '@mysten/dapp-kit';
import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';
import { Tabs } from '@/components/atoms/Tabs';
import { InputValue } from '@/components/atoms/InputValue';
import { InputWallet } from '@/components/atoms/InputWallet';
import { Button } from '@/components/atoms/Button';
import { useHbtcBalance } from '@/hooks/useHbtcBalance';

interface TransferFormProps {
	className?: string;
	onSubmit?: (data: { tab: string; amount: string; wallet: string }) => void;
}

export function TransferForm({ className, onSubmit }: TransferFormProps) {
	const account = useCurrentAccount();
	const { data: hbtcBalance } = useHbtcBalance();
	const [tab, setTab] = useState('receive');
	const [amount, setAmount] = useState('');
	const [wallet, setWallet] = useState('');
	const [connectModalOpen, setConnectModalOpen] = useState(false);

	const isWithdraw = tab === 'withdraw';
	const balanceBtc = isWithdraw && hbtcBalance
		? (Number(hbtcBalance.totalBalance) / 1e8).toString()
		: undefined;

	const handleSubmit = () => {
		onSubmit?.({
			tab,
			amount,
			wallet: account?.address ?? wallet,
		});
	};

	const contentRef = useRef<HTMLDivElement>(null);
	const [contentHeight, setContentHeight] = useState<number | undefined>();

	useLayoutEffect(() => {
		if (contentRef.current) {
			setContentHeight(contentRef.current.scrollHeight);
		}
	}, [tab]);

	const hasWallet = !!account || !!wallet;
	const parsedAmount = parseFloat(amount) || 0;
	const insufficientBalance = isWithdraw && balanceBtc !== undefined && parsedAmount > parseFloat(balanceBtc);
	const canSubmit = isWithdraw
		? !!amount && parsedAmount > 0 && hasWallet && !insufficientBalance
		: hasWallet;

	return (
		<div className={cn('flex flex-col gap-4', className)}>
			<Tabs value={tab} onChange={setTab} />
			<div
				className="transition-[height] duration-300 ease-out"
				style={contentHeight ? { height: contentHeight, overflow: 'hidden' } : undefined}
			>
				<div
					ref={contentRef}
					key={tab}
					className="flex animate-fade-in flex-col gap-4"
				>
					{isWithdraw && (
						<InputValue
							value={amount}
							onChange={setAmount}
							icon={<Icon name="suiBTC" />}
							currency="suiBTC"
							maxValue={balanceBtc}
						/>
					)}
					<InputWallet
						connectedAddress={account?.address}
						onConnectWallet={() => setConnectModalOpen(true)}
						onChange={setWallet}
						label={isWithdraw ? 'To Bitcoin Wallet' : 'To SUI Wallet'}
						placeholder={isWithdraw ? 'Enter Bitcoin wallet address' : 'Enter SUI wallet address'}
					/>
					<Button disabled={!canSubmit} onClick={handleSubmit}>
						{insufficientBalance ? 'Insufficient Balance' : isWithdraw ? 'Review Transfer' : 'Generate Deposit Address'}
					</Button>
				</div>
			</div>

			<ConnectModal
				trigger={<></>}
				open={connectModalOpen}
				onOpenChange={setConnectModalOpen}
			/>
		</div>
	);
}
