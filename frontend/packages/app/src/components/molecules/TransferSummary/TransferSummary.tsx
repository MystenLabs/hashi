import { cn } from '@/lib/utils';
import { Alert } from '@/components/atoms/Alert';
import { Icon } from '@/components/atoms/Icon';

export interface TransferSummaryProps {
	isCompleted?: boolean;
	label: string;
	amount: string;
	currency: 'BTC' | 'suiBTC';
	usdValue?: string;
	bitcoinHash?: string;
	suiHash?: string;
	alert?: string;
	className?: string;
}

export function TransferSummary({
	isCompleted,
	label,
	amount,
	currency,
	usdValue,
	bitcoinHash,
	suiHash,
	alert,
	className,
}: TransferSummaryProps) {
	return (
		<div
			className={cn(
				'flex flex-col items-center justify-center gap-4 bg-black/16 p-4 md:p-8',
				className,
			)}
		>
			{isCompleted && (
				<div className="bg-valid mb-4 flex h-11 w-11 animate-checkmark items-center justify-center rounded-xs text-black">
					<Icon name="Check" className="h-6 w-6" />
				</div>
			)}

			<div className="font-book -my-0.5 text-xl leading-none">{label}</div>

			<div className="mt-2 flex items-center gap-2">
				<Icon name={currency} className="h-6 w-6" />
				<div className="-my-0.5 text-3xl leading-none font-bold">
					{amount} {currency}
				</div>
			</div>

			{usdValue && (
				<div className="font-book -my-0.5 leading-none text-current/60">
					{usdValue}
				</div>
			)}

			{bitcoinHash && (
				<div className="font-book mt-4 flex items-center justify-between self-stretch border-t border-white/12 pt-4 text-sm leading-none">
					<div className="text-current/60">Bitcoin TXN hash</div>
					<div className="group flex items-center gap-1.5">
						{bitcoinHash}
						<button
							type="button"
							className="flex cursor-pointer opacity-60 transition-opacity hover:opacity-100"
						>
							<Icon name="ArrowUpRight" className="h-3.5 w-3.5" />
						</button>
					</div>
				</div>
			)}

			{suiHash && (
				<div className="font-book mt-4 flex items-center justify-between self-stretch border-t border-white/12 pt-4 text-sm leading-none">
					<div className="text-current/60">SUI TXN hash</div>
					<div className="group flex items-center gap-1.5">
						{suiHash}
						<button
							type="button"
							className="flex cursor-pointer opacity-60 transition-opacity hover:opacity-100"
						>
							<Icon name="ArrowUpRight" className="h-3.5 w-3.5" />
						</button>
					</div>
				</div>
			)}

			{alert && <Alert className="mt-2 md:-m-4 md:mt-2">{alert}</Alert>}
		</div>
	);
}
