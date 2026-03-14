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
				'flex cursor-pointer items-center justify-center gap-2 rounded-xs bg-white/20 px-4 py-2 font-bold text-white transition-all duration-200 hover:bg-white/35 hover:scale-105 active:scale-95 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-white/20 disabled:hover:scale-100 [&.active]:bg-white [&.active]:text-black',
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
