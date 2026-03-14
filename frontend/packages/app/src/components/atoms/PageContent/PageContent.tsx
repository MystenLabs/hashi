import { cn } from '@/lib/utils';

interface PageContentProps {
	children: React.ReactNode;
	className?: string;
}

export function PageContent({ children, className }: PageContentProps) {
	return (
		<div
			className={cn(
				'mx-auto flex max-w-120 animate-slide-up flex-col gap-4 rounded-xs bg-black/12 p-4 ring-1 ring-white/12 ring-inset',
				className,
			)}
		>
			{children}
		</div>
	);
}
