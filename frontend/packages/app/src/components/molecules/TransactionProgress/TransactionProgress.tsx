import { cn } from '@/lib/utils';
import { Alert } from '@/components/atoms/Alert';
import { Icon } from '@/components/atoms/Icon';

export interface ProgressStep {
	status: 'pending' | 'current' | 'success' | 'error';
	label: string;
	amount?: string;
	currency?: string;
}

interface TransactionProgressProps {
	steps: ProgressStep[];
	alert?: React.ReactNode;
	className?: string;
}

export function TransactionProgress({ steps, alert, className }: TransactionProgressProps) {
	return (
		<div className={cn('flex flex-col gap-8 bg-black/16 p-4 md:p-8', className)}>
			<h3 className="font-book text-xl leading-none">Transaction Progress</h3>
			<div className="font-book text-sm">
				{steps.map((step) => (
					<div
						key={step.label}
						className="mt-3 border-t border-white/12 pt-3 first:mt-0 first:border-0 first:pt-0"
					>
						<div className="flex items-center gap-2.5">
							{step.status === 'pending' && (
								<div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-xs ring-2 ring-white/32 transition-all duration-300 ring-inset"></div>
							)}
							{step.status === 'current' && (
								<div className="flex h-6 w-6 shrink-0 animate-pulse-glow items-center justify-center rounded-xs ring-2 ring-white ring-inset"></div>
							)}
							{step.status === 'success' && (
								<div className="bg-valid flex h-6 w-6 shrink-0 animate-scale-in items-center justify-center rounded-xs text-black">
									<Icon name="Check" className="h-4 w-4" />
								</div>
							)}
							{step.status === 'error' && (
								<div className="bg-error flex h-6 w-6 shrink-0 animate-scale-in items-center justify-center rounded-xs text-black">
									<Icon name="Close" className="h-4 w-4" />
								</div>
							)}
							<span className={step.status === 'current' ? 'font-bold' : ''}>
								{step.label}
								{step.amount && ` — ${step.amount} ${step.currency ?? ''}`}
							</span>
						</div>
					</div>
				))}
			</div>
			{alert && <Alert>{alert}</Alert>}
		</div>
	);
}
