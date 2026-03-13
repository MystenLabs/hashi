import { cn } from '@/lib/utils';

interface LegalNavItem {
	href: string;
	label: string;
}

interface LegalNavProps {
	items?: LegalNavItem[];
	className?: string;
}

const defaultItems: LegalNavItem[] = [
	{ label: 'Docs', href: '/docs' },
	{ label: 'Security', href: '/security' },
	{ label: 'Terms', href: '/terms' },
];

export function LegalNav({ items = defaultItems, className }: LegalNavProps) {
	return (
		<nav className={cn('flex items-center gap-8', className)}>
			{items.map((item) => (
				<a
					key={item.label}
					href={item.href}
					className="text-black/60 text-sm hover:text-black/80 transition-colors font-medium"
				>
					{item.label}
				</a>
			))}
		</nav>
	);
}
