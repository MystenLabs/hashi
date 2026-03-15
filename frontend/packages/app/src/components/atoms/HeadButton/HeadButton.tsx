import { useRef, useState } from 'react';
import { cn } from '@/lib/utils';
import { useScrambleText, SCRAMBLE_ACCENT } from '@/hooks/useScrambleText';

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
	const text = typeof children === 'string' ? children : '';
	const { chars, scramble, reset } = useScrambleText(text);
	const buttonRef = useRef<HTMLButtonElement>(null);
	const [lockedWidth, setLockedWidth] = useState<number | undefined>();

	const handleMouseEnter = () => {
		if (!text) return;
		if (buttonRef.current) {
			setLockedWidth(buttonRef.current.offsetWidth);
		}
		scramble();
	};

	const handleMouseLeave = () => {
		if (!text) return;
		reset();
		setLockedWidth(undefined);
	};

	return (
		<button
			ref={buttonRef}
			disabled={disabled}
			className={cn(
				'flex cursor-pointer items-center justify-center gap-2 rounded-xs bg-white/20 px-4 py-2 font-bold text-white transition-[background-color] duration-200 hover:bg-white/35 active:scale-95 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-white/20 [&.active]:bg-white [&.active]:text-black',
				className,
			)}
			style={lockedWidth ? { width: lockedWidth, whiteSpace: 'nowrap' } : undefined}
			onMouseEnter={handleMouseEnter}
			onMouseLeave={handleMouseLeave}
			{...props}
		>
			{leadingIcon && <span className="shrink-0 flex -ml-1">{leadingIcon}</span>}
			{text ? (
				<span className="leading-none py-0.5">
					<span className="relative inline-block">
						<span className={lockedWidth ? 'invisible' : undefined}>{text}</span>
						{lockedWidth && (
							<span className="absolute inset-0 text-center overflow-hidden">
								{chars.map((c, i) =>
									!c.resolved && c.colored
										? <span key={i} style={{ color: SCRAMBLE_ACCENT }}>{c.char}</span>
										: <span key={i}>{c.char}</span>
								)}
							</span>
						)}
					</span>
				</span>
			) : children ? (
				<span className="leading-none py-0.5">{children}</span>
			) : null}
			{trailingIcon && (
				<span className="shrink-0 flex -mx-1 first:last:-mx-2">{trailingIcon}</span>
			)}
		</button>
	);
}
