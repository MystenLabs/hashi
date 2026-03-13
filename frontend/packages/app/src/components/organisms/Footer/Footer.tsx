import { Copyright } from '@/components/atoms/Copyright';
import { LegalNav } from '@/components/atoms/LegalNav';
import { cn } from '@/lib/utils';

interface FooterProps {
	className?: string;
}

export function Footer({ className }: FooterProps) {
	return (
		<footer className={cn('border-t @container border-black/25 p-5', className)}>
			<div className="flex flex-col gap-4 text-center items-center justify-between @md:flex-row">
				<Copyright />
				<LegalNav />
			</div>
		</footer>
	);
}
