import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';

interface InfoCard {
	icon: React.ReactNode;
	title: string;
	description: string;
}

interface InfoSection {
	title: string;
	cards: InfoCard[];
}

interface HowItWorksProps {
	className?: string;
	onClose?: () => void;
}

const sections: InfoSection[] = [
	{
		title: 'The two directions are:',
		cards: [
			{
				icon: <Icon name="BTC" className="h-10 w-10" />,
				title: 'Bitcoin \u2192 Sui',
				description:
					'You send real BTC and receive an equivalent wrapped token (called suiBTC) into the entered Sui wallet. This token represents their Bitcoin on the Sui network and can be used across Sui\u2019s DeFi ecosystem.',
			},
			{
				icon: <Icon name="suiBTC" className="h-10 w-10" />,
				title: 'Sui \u2192 Bitcoin',
				description:
					'The reverse. You can withdraw your suiBTC back, it gets burned on Sui, and real BTC is released to the entered Bitcoin wallet address.',
			},
		],
	},
	{
		title: 'Why Hashi Exists',
		cards: [
			{
				icon: <Icon name="SUI" className="h-10 w-10" />,
				title: 'Sui is modern & fast',
				description:
					'Bitcoin is the most valuable crypto asset in the world, but the Bitcoin blockchain itself has very limited functionality. You can hold and send BTC, but not much else. Sui, by contrast, is a modern, fast blockchain with a rich DeFi ecosystem. Hashi is the connective tissue that lets Bitcoin holders put their assets to work on Sui without selling their BTC.',
			},
		],
	},
];

function InfoCardItem({ icon, title, description }: InfoCard) {
	return (
		<div className="flex gap-4 rounded-xs bg-white/12 px-4 py-3">
			{icon}
			<div className="flex flex-col gap-1">
				<span className="font-bold text-white">{title}</span>
				<p className="text-xs text-white/80">{description}</p>
			</div>
		</div>
	);
}

export function HowItWorks({ className, onClose }: HowItWorksProps) {
	return (
		<div
			className={cn(
				'flex w-full flex-col gap-6 rounded-xs bg-black p-6 ring-1 ring-white/16 ring-inset',
				className,
			)}
		>
			<div className="flex items-center justify-between gap-4">
				<h3 className="-my-0.5 text-2xl leading-none font-medium text-white">How It Works</h3>
				<button aria-label="Close" className="flex text-white" onClick={onClose}>
					<Icon name="Close" />
				</button>
			</div>

			<p className="font-book -my-0.5 text-sm text-white/60">
				Hashi Protocol lets you move Bitcoin between Bitcoin blockchain and Sui blockchain. Think
				of it as a transfer or exchange experience. You put BTC in one side, and it comes out the
				other side in a form native to SUI network, suiBTC.
			</p>

			{sections.map((section) => (
				<div key={section.title} className="flex flex-col gap-3">
					<h3 className="leading-none text-white">{section.title}</h3>
					{section.cards.map((card) => (
						<InfoCardItem key={card.title} {...card} />
					))}
				</div>
			))}
		</div>
	);
}
