import { useNavigate } from 'react-router-dom';
import { PageLayout } from '@/components/atoms/PageLayout';
import { PageTitle } from '@/components/atoms/PageTitle';
import { PageContent } from '@/components/atoms/PageContent';
import { TransferForm } from '@/components/molecules/TransferForm';

export function HomePage() {
	const navigate = useNavigate();

	return (
		<PageLayout>
			<PageTitle className="max-w-150">Seamlessly transfer Bitcoin to Sui and back</PageTitle>

			<PageContent>
				<TransferForm
					onSubmit={(data) => {
						const state = {
							amount: data.amount,
							wallet: data.wallet,
							usdValue: '', // TODO: fetch BTC price
						};

						navigate(data.tab === 'withdraw' ? '/withdraw' : '/deposit', { state });
					}}
				/>
			</PageContent>

			<p className="mx-auto mt-4 max-w-93 animate-fade-in stagger-3 text-center text-xs text-shadow-[0_1px_2px_rgb(0_0_0/0.24)]">
				BTC becomes suiBTC in the SUI wallet. This token represents Bitcoin on the Sui network
				and can be used across Sui's DeFi ecosystem. You can withdraw it back as BTC to a Bitcoin
				wallet anytime.
			</p>
		</PageLayout>
	);
}
