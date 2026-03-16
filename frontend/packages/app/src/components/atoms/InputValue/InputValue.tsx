import { useRef } from 'react';
import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';

interface InputValueProps {
	icon?: React.ReactNode;
	currency?: 'BTC' | 'hBTC';
	name?: string;
	value?: string;
	defaultValue?: string;
	maxValue?: string;
	minValue?: string;
	placeholder?: string;
	usdValue?: string;
	className?: string;
	onChange?: (value: string) => void;
}

export function InputValue({
	icon,
	currency = 'BTC',
	name = 'amount',
	value,
	defaultValue = '',
	maxValue,
	minValue,
	placeholder = '0.00',
	usdValue,
	className,
	onChange,
}: InputValueProps) {
	const inputRef = useRef<HTMLInputElement>(null);

	const resolvedIcon = icon ?? <Icon name={currency} />;

	const handleMaxClick = () => {
		if (!maxValue || !inputRef.current) return;
		inputRef.current.value = maxValue;
		onChange?.(maxValue);
	};

	const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
		e.preventDefault();
		const pasted = e.clipboardData.getData('text');
		const filtered = pasted.replace(/[^0-9.,]/g, '');
		document.execCommand('insertText', false, filtered);
	};

	const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
		const raw = e.target.value;
		const filtered = raw.replace(/[^0-9.,]/g, '');
		const normalized = filtered
			.replace(/[.,]/, 'DECIMAL')
			.replace(/[.,]/g, '')
			.replace('DECIMAL', filtered.match(/[.,]/)?.[0] ?? '');
		e.target.value = normalized;
		onChange?.(normalized);
	};

	const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
		const allowed =
			/[0-9.,]|Backspace|Delete|ArrowLeft|ArrowRight|ArrowUp|ArrowDown|Tab|Enter/;
		if (!allowed.test(e.key)) {
			e.preventDefault();
		}
	};

	return (
		<label
			className={cn(
				'flex w-full cursor-text flex-col gap-4 rounded-xs bg-black/16 p-4 ring-1 ring-black/24 transition-all duration-300 ring-inset hover:ring-white/32 has-focus:ring-white/64 has-focus:shadow-[0_0_0_1px_rgba(255,255,255,0.1)] md:p-8',
				className,
			)}
		>
			<span className="mb-4 flex items-center gap-2 leading-none font-bold text-white">
				{resolvedIcon}
				{currency}
				{maxValue && (
					<div className="ml-auto flex items-center gap-3">
						<div className="font-book flex items-center gap-1 text-sm text-current/60 md:text-base">
							<Icon name="Wallet" />
							{maxValue}
						</div>
						<span
							className="font-book -my-2 flex cursor-pointer items-center justify-center rounded-xs px-4 py-2 leading-tight text-white ring-1 ring-white/24 transition-colors select-none ring-inset hover:bg-white/12"
							onClick={handleMaxClick}
						>
							Max
						</span>
					</div>
				)}
			</span>
			<input
				ref={inputRef}
				type="text"
				inputMode="decimal"
				autoComplete="off"
				name={name}
				{...(value !== undefined ? { value } : { defaultValue })}
				placeholder={placeholder}
				onPaste={handlePaste}
				onChange={handleChange}
				onKeyDown={handleKeyDown}
				className="text-h2 md:text-h1 -my-2 flex h-11 w-full appearance-none bg-transparent leading-none text-white outline-none placeholder:text-white/60 [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
			/>
			{minValue && (
				<span className="leading-none text-white/40 text-xs">
					Min: {minValue} {currency}
				</span>
			)}
			{usdValue && <span className="leading-none text-white/60">{usdValue}</span>}
		</label>
	);
}
