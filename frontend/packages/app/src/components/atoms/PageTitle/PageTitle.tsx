import { cn } from '@/lib/utils';

interface PageTitleProps {
	children: React.ReactNode;
	className?: string;
}

export function PageTitle({ children, className }: PageTitleProps) {
	return (
		<h1 className={cn('text-h2 md:text-h1 mx-auto mb-10 animate-slide-down text-center', className)}>
			{children}
		</h1>
	);
}
