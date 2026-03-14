import { cn } from '@/lib/utils';
import { Alert } from '@/components/atoms/Alert';
import { Icon } from '@/components/atoms/Icon';

interface StepperProps {
	steps: number;
	currentStep: number;
}

function Stepper({ steps, currentStep }: StepperProps) {
	return (
		<div className="flex items-center">
			{Array.from({ length: steps }, (_, i) => {
				const step = i + 1;
				const isActive = step === currentStep;
				const isCompleted = step < currentStep;

				return (
					<>
						<div
							className={cn(
								'font-book flex h-6 w-6 items-center justify-center rounded-xs text-xs transition-all duration-300',
								isCompleted && 'bg-valid text-black animate-scale-in',
								isActive && 'ring-2 ring-white/32 ring-inset animate-pulse-glow',
								!isCompleted && !isActive && 'ring-2 ring-white/32 ring-inset',
							)}
						>
							{isCompleted ? <Icon name="Check" className="h-4 w-4" /> : step}
						</div>

						{step < steps && (
							<div
								className={cn(
									'h-0.5 grow transition-colors md:w-2.5',
									isCompleted ? 'bg-valid' : 'bg-white/32',
								)}
							/>
						)}
					</>
				);
			})}
		</div>
	);
}

interface TransactionConfirmationsProps {
	steps: number;
	currentStep: number;
	timeRemaining?: string;
	btcReceiving?: string;
	alert?: React.ReactNode;
}

export function TransactionConfirmations({
	steps,
	currentStep,
	timeRemaining,
	btcReceiving,
	alert,
}: TransactionConfirmationsProps) {
	return (
		<div className="flex flex-col gap-8 bg-black/16 p-4 md:p-8">
			<div className="font-book leading-none">Transaction Progress</div>
			<div className="flex flex-col gap-3 text-sm leading-none">
				<div className="font-book flex flex-col justify-between gap-3 md:flex-row md:items-center">
					<div className="text-current/60">Confirmations Received</div>
					<Stepper steps={steps} currentStep={currentStep} />
				</div>
				<div className="h-px bg-white/12"></div>
				<div className="font-book flex items-center justify-between">
					<div className="text-current/60">Estimated Time Remaining</div>
					<div>{timeRemaining}</div>
				</div>
			</div>
			{btcReceiving && (
				<>
					<div className="h-px bg-white/12"></div>
					<div className="font-book flex items-center justify-between text-sm leading-none">
						<div className="text-current/60">BTC Receiving</div>
						<div className="flex items-center gap-1.5">
							<Icon name="BTC" className="h-4 w-4" />
							<span>{btcReceiving} BTC</span>
						</div>
					</div>
				</>
			)}
			{alert && <Alert>{alert}</Alert>}
		</div>
	);
}
