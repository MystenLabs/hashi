import { cn } from '@/lib/utils';

interface CopyrightProps {
	year?: number;
	text?: string;
	className?: string;
}

export function Copyright({
	year = new Date().getFullYear(),
	text = 'Hashi Protocol \u2022 All Rights Reserved',
	className,
}: CopyrightProps) {
	return (
		<p className={cn('text-black/60 font-book text-sm', className)}>
			&copy;{year} {text}
		</p>
	);
}
