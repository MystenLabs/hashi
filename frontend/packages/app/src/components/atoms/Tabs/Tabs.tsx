import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';

export interface Tab {
	value: string;
	label: string;
	icon: React.ReactNode;
}

interface TabsProps {
	tabs?: Tab[];
	value?: string;
	disabled?: boolean;
	className?: string;
	onChange: (value: string) => void;
}

const defaultTabs: Tab[] = [
	{ value: 'receive', label: 'Receive BTC', icon: <Icon name="BTC" /> },
	{ value: 'withdraw', label: 'Withdraw suiBTC', icon: <Icon name="suiBTC" /> },
];

export function Tabs({ tabs = defaultTabs, value = 'receive', disabled, className, onChange }: TabsProps) {
	return (
		<div className={cn('flex rounded-xs bg-white/5', className)}>
			{tabs.map((tab) => (
				<button
					key={tab.value}
					disabled={disabled}
					onClick={() => onChange(tab.value)}
					className={cn(
						'xs:flex-1 grow rounded-xs py-2.5 text-white transition-all duration-200 hover:bg-white/20 disabled:pointer-events-none',
						value === tab.value
							? 'pointer-events-none bg-white/10 font-bold'
							: 'font-book',
					)}
				>
					<span className={`flex items-center justify-center gap-2 text-sm md:text-base ${disabled ? 'opacity-30' : ''}`}>
						{tab.icon}
						{tab.label}
					</span>
				</button>
			))}
		</div>
	);
}
