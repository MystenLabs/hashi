import { useState, useCallback } from 'react';
import { useCurrentAccount, useDisconnectWallet, ConnectModal } from '@mysten/dapp-kit';
import { Banner } from '@/components/atoms/Banner';
import { Footer } from '@/components/organisms/Footer';
import { Header } from '@/components/organisms/Header';
import { HelpWidget } from '@/components/organisms/HelpWidget';
interface PageLayoutProps {
	children: React.ReactNode;
}

function truncateAddress(address: string) {
	return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function PageLayout({ children }: PageLayoutProps) {
	const account = useCurrentAccount();
	const { mutate: disconnect } = useDisconnectWallet();
	const [connectModalOpen, setConnectModalOpen] = useState(false);

	const handleDisconnect = useCallback(() => {
		disconnect();
	}, [disconnect]);

	return (
		<div className="flex min-h-dvh flex-col">
			{account ? (
				<Header
					username={truncateAddress(account.address)}
					address={account.address}
					onDisconnect={handleDisconnect}
				/>
			) : (
				<>
					<Banner message="Native Bitcoin. Programmable collateral. Zero custody risk. Hashi Protocol available now." />
					<Header onConnectWalletClick={() => setConnectModalOpen(true)} />
				</>
			)}

			<div className="relative grow px-5 py-10 md:py-20">
				<main className="animate-fade-in">{children}</main>
				<HelpWidget />
			</div>

			<Footer />

			<ConnectModal
				trigger={<></>}
				open={connectModalOpen}
				onOpenChange={setConnectModalOpen}
			/>
		</div>
	);
}
