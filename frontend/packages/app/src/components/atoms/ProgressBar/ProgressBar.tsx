import { cn } from '@/lib/utils';
import { cva, type VariantProps } from 'class-variance-authority';

const progressVariants = cva(
	'font-book relative flex w-full items-center gap-1.5 rounded-xs bg-current/6 p-3 text-xs leading-none ring-1 ring-inset',
	{
		variants: {
			variant: {
				default: 'ring-orange text-orange',
				warning: 'ring-warning-bg text-warning-bg',
				success: 'ring-valid text-valid',
			},
		},
		defaultVariants: {
			variant: 'default',
		},
	},
);

interface ProgressBarProps extends VariantProps<typeof progressVariants> {
	label?: string;
	message?: string;
	progress?: number;
	className?: string;
}

export function ProgressBar({
	variant,
	label = 'Status',
	message,
	progress = 0,
	className,
}: ProgressBarProps) {
	return (
		<div className={cn(progressVariants({ variant }), className)}>
			<span
				className="absolute top-0 left-0 h-full rounded-xs bg-current/20"
				style={{ width: `${progress}%` }}
			></span>
			<span className="h-3 w-3 rounded-full bg-current"></span>
			<span>{label}</span>
			<span className="ml-auto text-white">{message}</span>
		</div>
	);
}
