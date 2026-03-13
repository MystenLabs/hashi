import { cn } from '@/lib/utils';
import { Alert } from '@/components/atoms/Alert';
import { Icon } from '@/components/atoms/Icon';
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard';

export interface TransferDetailsRowProps {
	label: string;
	value: string;
	copyValue?: string;
	action?: 'copy' | 'external';
	tooltip?: string;
	alert?: string;
}

export interface TransferDetailsProps {
	rows: TransferDetailsRowProps[];
	summary?: string;
	amount: string;
	currency: 'BTC' | 'suiBTC';
	usdValue: string;
	className?: string;
}

function TransferDetailsRow({ label, value, copyValue, action, tooltip, alert }: TransferDetailsRowProps) {
	const { copied, copy } = useCopyToClipboard();

	return (
		<div className="font-book mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-current/12 pt-3 text-sm leading-none first:mt-0 first:border-0 first:pt-0">
			<span className="flex items-center gap-1 text-current/60">
				{label}
				{tooltip && (
					<div className="group relative flex">
						<Icon
							name="Info"
							className="h-3.5 w-3.5 transition-colors group-hover:text-white"
						/>
						<div className="shadow-popover pointer-events-none absolute bottom-full left-1/2 mb-2 w-58 -translate-x-1/2 translate-y-1 scale-95 rounded-xs bg-black p-3 text-sm text-white opacity-0 ring-1 ring-white/24 transition ring-inset group-hover:translate-y-0 group-hover:scale-100 group-hover:opacity-100">
							{tooltip}
						</div>
					</div>
				)}
			</span>
			<span className="flex items-center gap-1.5">
				{value}
				{action === 'copy' && (
					<button
						type="button"
						aria-label={copied ? 'Copied' : 'Copy'}
						className="flex cursor-pointer opacity-60 transition-opacity hover:opacity-100"
						onClick={() => copy(copyValue ?? value)}
					>
						{copied ? (
							<Icon name="Check" className="h-3.5 w-3.5 text-valid" />
						) : (
							<Icon name="Copy" className="h-3.5 w-3.5" />
						)}
					</button>
				)}
				{action === 'external' && (
					<button
						type="button"
						aria-label="Open In New Tab"
						className="flex cursor-pointer opacity-60 transition-opacity hover:opacity-100"
					>
						<Icon name="ArrowUpRight" className="h-3.5 w-3.5" />
					</button>
				)}
			</span>
			{alert && <Alert>{alert}</Alert>}
		</div>
	);
}

export function TransferDetails({
	rows,
	summary = 'Receives',
	amount,
	currency,
	usdValue,
	className,
}: TransferDetailsProps) {
	return (
		<div className={cn('flex flex-col gap-8 rounded-xs bg-black/16 p-8', className)}>
			<div>
				{rows.map((row) => (
					<TransferDetailsRow key={row.label} {...row} />
				))}
			</div>

			<div className="flex flex-col gap-3">
				<div className="flex items-center justify-between gap-2">
					<span className="font-book text-xl leading-none">{summary}</span>
					<Icon name={currency} className="ml-auto h-5 w-5" />
					<span className="text-xl leading-none font-bold text-white">
						{amount} {currency}
					</span>
				</div>
				<div className="flex items-center justify-between text-xs leading-none text-current/80">
					<span>1 BTC = 1suiBTC</span>
					<span>{usdValue}</span>
				</div>
			</div>
		</div>
	);
}
