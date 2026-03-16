import { CONFIG } from '@/lib/constants';

const networkColors: Record<string, string> = {
	localnet: 'bg-[#A15A00]/24 text-[#FFB252]',
	testnet: 'bg-[#9D9D00]/24 text-[#FFFF7A]',
	devnet: 'bg-[#A15A00]/24 text-[#FFB252]',
};

export function NetworkBadge() {
	const network = CONFIG.DEFAULT_NETWORK;

	// Hide on mainnet — it's the expected default
	if (network === 'mainnet') return null;

	const color = networkColors[network] ?? 'bg-white/12 text-white/60';

	return (
		<span className={`rounded-full px-2 py-0.5 text-xs font-medium leading-none ${color}`}>
			{network}
		</span>
	);
}
