import { useState } from 'react';
import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';

interface BannerProps {
	message: string;
	className?: string;
	onDismiss?: () => void;
}

export function Banner({ message, onDismiss, className }: BannerProps) {
	const [visible, setVisible] = useState(true);

	if (!visible) return null;

	const handleDismiss = () => {
		setVisible(false);
		onDismiss?.();
	};

	return (
		<div
			className={cn(
				'@container flex items-center justify-between gap-3 bg-[#3b82f6] p-3 text-white',
				className,
			)}
		>
			<p className="mx-auto -my-0.5 text-sm @md:text-base">{message}</p>
			<button aria-label="Dismiss banner" type="button" onClick={handleDismiss} className="flex">
				<Icon name="Close" />
			</button>
		</div>
	);
}
