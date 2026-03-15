import { cn } from '@/lib/utils';
import { cva, type VariantProps } from 'class-variance-authority';

const buttonVariants = cva(
	'flex items-center justify-center gap-3 rounded-xs cursor-pointer text-lg font-bold px-5 py-2 tracking-tight active:scale-[0.98] disabled:cursor-not-allowed disabled:hover:scale-100',
	{
		variants: {
			variant: {
				primary: 'btn-cta disabled:opacity-30 disabled:hover:bg-[#298DFF] disabled:hover:text-white',
				secondary: 'bg-white text-black transition-all duration-200 hover:scale-[1.02] disabled:bg-[#67707E] disabled:text-white/30',
				outline:
					'ring-1 ring-inset ring-white/50 text-white transition-all duration-200 hover:scale-[1.02] hover:bg-white/25 disabled:text-white/30 disabled:hover:bg-transparent',
			},
		},
		defaultVariants: {
			variant: 'primary',
		},
	},
);

const ArrowIcon = () => (
	<svg width="20" height="20" viewBox="0 0 20 20" fill="none" className="overflow-hidden">
		<path
			d="M3.8125 10H16.1875M11.125 4.9375L16.1875 10L11.125 15.0625"
			stroke="currentColor"
			strokeWidth="2"
			strokeLinecap="round"
			strokeLinejoin="round"
		/>
		<path
			d="M3.8125 10H16.1875M11.125 4.9375L16.1875 10L11.125 15.0625"
			stroke="currentColor"
			strokeWidth="2"
			strokeLinecap="round"
			strokeLinejoin="round"
		/>
	</svg>
);

interface ButtonProps
	extends React.ButtonHTMLAttributes<HTMLButtonElement>,
		VariantProps<typeof buttonVariants> {
	disabled?: boolean;
	leadingIcon?: React.ReactNode;
	trailingIcon?: React.ReactNode;
	className?: string;
}

export function Button({
	variant,
	disabled,
	children,
	leadingIcon,
	trailingIcon,
	className,
	...props
}: ButtonProps) {
	const isPrimary = (variant ?? 'primary') === 'primary';

	return (
		<button disabled={disabled} className={cn(buttonVariants({ variant }), className)} {...props}>
			{leadingIcon && <span className="-mr-l flex shrink-0 opacity-80">{leadingIcon}</span>}
			{children && <span>{children}</span>}
			{trailingIcon && <span className="-mr-1 flex shrink-0 opacity-80">{trailingIcon}</span>}
			{isPrimary && !trailingIcon && (
				<span className="btn-cta-icon relative flex shrink-0 items-center justify-center overflow-hidden rounded-xs p-1 text-white">
					<span className="relative z-10"><ArrowIcon /></span>
					<span className="btn-cta-icon-bg absolute inset-0 bg-[#298DFF]" />
				</span>
			)}
		</button>
	);
}
