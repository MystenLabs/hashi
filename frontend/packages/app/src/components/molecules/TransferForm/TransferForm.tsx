import { useState } from 'react';
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

	const hasWallet = !!account || !!wallet;

	return (
		<div className={cn('flex flex-col gap-4', className)}>
			<Tabs value={tab} onChange={setTab} />
			<InputValue
				value={amount}
				onChange={setAmount}
				icon={isWithdraw ? <Icon name="suiBTC" /> : <Icon name="BTC" />}
				currency={isWithdraw ? 'suiBTC' : 'BTC'}
				maxValue={balanceBtc}
			/>
			<InputWallet
				connectedAddress={account?.address}
				onConnectWallet={() => setConnectModalOpen(true)}
				onChange={setWallet}
			/>
			<Button disabled={!amount || !hasWallet} onClick={handleSubmit}>
				Review Transfer
			</Button>

			<ConnectModal
				trigger={<></>}
				open={connectModalOpen}
				onOpenChange={setConnectModalOpen}
			/>
		</div>
	);
}
