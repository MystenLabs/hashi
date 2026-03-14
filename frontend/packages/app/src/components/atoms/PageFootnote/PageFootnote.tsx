import { cn } from '@/lib/utils';

interface PageFootnoteProps {
	children: React.ReactNode;
	className?: string;
}

export function PageFootnote({ children, className }: PageFootnoteProps) {
	return (
		<p
			className={cn(
				'mx-auto mt-4 max-w-93 text-center text-xs text-shadow-[0_1px_2px_rgb(0_0_0/0.24)]',
				className,
			)}
		>
			{children}
		</p>
	);
}
