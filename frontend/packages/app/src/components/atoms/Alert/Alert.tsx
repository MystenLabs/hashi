import { cn } from '@/lib/utils';
import { cva, type VariantProps } from 'class-variance-authority';
import { Icon } from '@/components/atoms/Icon';

const alertVariants = cva('flex gap-3 rounded-xs p-3 text-xs', {
	variants: {
		variant: {
			warning: 'bg-warning-bg text-warning-text',
			error: 'bg-failed-bg text-failed-text',
		},
	},
	defaultVariants: {
		variant: 'warning',
	},
});

interface AlertProps extends VariantProps<typeof alertVariants> {
	icon?: React.ReactNode;
	className?: string;
	children?: React.ReactNode;
}

export function Alert({
	variant,
	icon = <Icon name="Info" className="h-3.5 w-3.5" />,
	className,
	children,
}: AlertProps) {
	return (
		<div className={cn(alertVariants({ variant }), className)}>
			{icon}
			<p className="-my-px">{children}</p>
		</div>
	);
}
