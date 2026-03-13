import { cn } from '@/lib/utils';
import { cva, type VariantProps } from 'class-variance-authority';

const buttonVariants = cva(
	'flex items-center justify-center gap-3 rounded-xs transition-colors cursor-pointer text-lg font-bold px-5 py-2 tracking-tight disabled:cursor-not-allowed',
	{
		variants: {
			variant: {
				primary: 'bg-black text-white disabled:opacity-30',
				secondary: 'bg-white text-black disabled:bg-[#67707E] disabled:text-white/30',
				outline:
					'ring-1 ring-inset ring-white/50 text-white hover:bg-white/25 disabled:text-white/30 disabled:hover:bg-transparent',
			},
		},
		defaultVariants: {
			variant: 'primary',
		},
	},
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
	return (
		<button disabled={disabled} className={cn(buttonVariants({ variant }), className)} {...props}>
			{leadingIcon && <span className="-mr-l flex shrink-0 opacity-80">{leadingIcon}</span>}
			{children && <span>{children}</span>}
			{trailingIcon && <span className="-mr-1 flex shrink-0 opacity-80">{trailingIcon}</span>}
		</button>
	);
}
