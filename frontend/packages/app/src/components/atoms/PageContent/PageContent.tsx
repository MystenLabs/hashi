import { cn } from '@/lib/utils';

interface PageContentProps {
	children: React.ReactNode;
	className?: string;
}

export function PageContent({ children, className }: PageContentProps) {
	return (
		<div
			className={cn(
				'xs:mx-0 xs:p-4 xs:ring-1 xs:ring-white/12 xs:ring-inset xs:w-full -mx-5 flex max-w-120 flex-col gap-4 rounded-xs bg-black/12 p-5',
				className,
			)}
		>
			{children}
		</div>
	);
}
