import { Copyright } from '@/components/atoms/Copyright';
import { LegalNav } from '@/components/atoms/LegalNav';
import { cn } from '@/lib/utils';

interface FooterProps {
	className?: string;
}

export function Footer({ className }: FooterProps) {
	return (
		<footer className={cn('animate-fade-in border-t border-black/25 p-5', className)}>
			<div className="flex flex-col items-center justify-between gap-4 text-center md:flex-row">
				<LegalNav />
				<Copyright className="md:order-first" />
			</div>
		</footer>
	);
}
