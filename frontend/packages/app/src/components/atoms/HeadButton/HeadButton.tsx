import { cn } from '@/lib/utils';

interface HeadButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
	disabled?: boolean;
	leadingIcon?: React.ReactNode;
	trailingIcon?: React.ReactNode;
	className?: string;
}

export function HeadButton({
	disabled,
	children,
	leadingIcon,
	trailingIcon,
	className,
	...props
}: HeadButtonProps) {
	return (
		<button
			disabled={disabled}
			className={cn(
				'flex items-center justify-center px-4 py-2 gap-2 rounded-xs bg-white/20 hover:bg-white/35 transition-colors text-white font-bold cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-white/20',
				className,
			)}
			{...props}
		>
			{leadingIcon && <span className="shrink-0 flex -ml-1">{leadingIcon}</span>}
			{children && <span className="leading-none py-0.5">{children}</span>}
			{trailingIcon && (
				<span className="shrink-0 flex -mx-1 first:last:-mx-2">{trailingIcon}</span>
			)}
		</button>
	);
}
