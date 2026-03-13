import { cn } from '@/lib/utils';

interface HelpButtonProps {
	disabled?: boolean;
	className?: string;
	onClick?: () => void;
}

export function HelpButton({ onClick, disabled, className }: HelpButtonProps) {
	return (
		<button
			onClick={onClick}
			disabled={disabled}
			aria-label="Help"
			className={cn(
				'flex h-14 w-14 items-center justify-center rounded-xs border border-white/25 bg-black text-white transition-colors hover:bg-white hover:text-black disabled:cursor-not-allowed disabled:bg-[#6b7280] disabled:text-white/25',
				className,
			)}
		>
			<svg width="32" height="32" viewBox="0 0 32 32" fill="none">
				<path
					d="M16 20V18C19.8663 18 23 15.3138 23 12C23 8.68625 19.8663 6 16 6C12.1337 6 9 8.68625 9 12"
					stroke="currentcolor"
					strokeWidth="2"
					strokeLinecap="round"
					strokeLinejoin="round"
				/>
				<path
					d="M16 28C17.1046 28 18 27.1046 18 26C18 24.8954 17.1046 24 16 24C14.8954 24 14 24.8954 14 26C14 27.1046 14.8954 28 16 28Z"
					fill="currentcolor"
				/>
			</svg>
		</button>
	);
}
