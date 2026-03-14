import { useEffect, useRef, useState } from 'react';
import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';

interface InputWalletProps {
	label?: string;
	isConnect?: boolean;
	connectedAddress?: string;
	defaultValue?: string;
	initialValue?: string;
	placeholder?: string;
	isValid?: boolean;
	isInvalid?: boolean;
	errorMessage?: string;
	className?: string;
	onChange?: (value: string) => void;
	onConnectWallet?: () => void;
}

function formatAddress(address: string) {
	return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function InputWallet({
	label = 'To SUI Wallet',
	isConnect = true,
	connectedAddress,
	defaultValue,
	initialValue,
	placeholder = 'Enter SUI wallet address',
	isValid,
	isInvalid,
	errorMessage,
	className,
	onChange,
	onConnectWallet,
}: InputWalletProps) {
	const contentRef = useRef<HTMLDivElement>(null);
	const resolvedInitial = defaultValue ?? initialValue ?? '';
	const [isEmpty, setIsEmpty] = useState(!resolvedInitial);

	useEffect(() => {
		if (contentRef.current && resolvedInitial) {
			contentRef.current.innerText = resolvedInitial;
		}
	}, []);

	const handleClick = () => {
		if (!connectedAddress) {
			contentRef.current?.focus();
		}
	};

	const handleInput = () => {
		const text = contentRef.current?.innerText ?? '';
		setIsEmpty(text.trim() === '');
		onChange?.(text);
	};

	const handlePaste = (e: React.ClipboardEvent) => {
		e.preventDefault();
		const text = e.clipboardData.getData('text/plain');
		document.execCommand('insertText', false, text);
	};

	const handleKeyDown = (e: React.KeyboardEvent) => {
		if (e.key === 'Enter') {
			e.preventDefault();
		}
	};

	return (
		<div
			className={cn(
				'flex w-full flex-col rounded-xs bg-black/16 p-4 ring-1 ring-black/24 transition-all duration-300 ring-inset md:p-8',
				isConnect ? 'gap-6 md:gap-8' : 'gap-4',
				!connectedAddress && 'cursor-text hover:ring-white/32 has-focus:ring-white/64',
				className,
			)}
			onClick={handleClick}
		>
			<div className="-my-0.5 flex items-center justify-between">
				<span className="leading-none text-white/80">{label}</span>
				{isConnect && !connectedAddress && (
					<button
						type="button"
						className="flex cursor-pointer items-center gap-1 text-xs text-white/80 transition-colors hover:text-white"
						onClick={(e) => {
							e.stopPropagation();
							onConnectWallet?.();
						}}
					>
						Connect Wallet
						<Icon name="CaretDown" className="-mx-0.5 h-4 w-4 -rotate-90" />
					</button>
				)}
			</div>

			{connectedAddress ? (
				<div className="relative -my-0.5 flex items-start gap-4 md:-my-1.5">
					<div className="text-lg leading-tight tracking-tight text-white md:text-2xl">
						{formatAddress(connectedAddress)}
					</div>
					<span className="flex h-6 w-6 shrink-0 translate-y-px items-center justify-center rounded-xs bg-valid md:mt-0.5">
						<svg
							viewBox="0 0 12 12"
							fill="none"
							stroke="black"
							strokeWidth="2"
							strokeLinecap="round"
							strokeLinejoin="round"
							className="h-3 w-3"
						>
							<path d="M1.875 6.75L4.5 9.375L10.5 3.375" />
						</svg>
					</span>
				</div>
			) : (
				<>
					<div className="relative -my-0.5 flex items-start gap-4 md:-my-1.5">
						{isEmpty && (
							<div className="pointer-events-none absolute inset-0 text-lg leading-tight tracking-tight text-white/30 md:text-2xl">
								{placeholder}
							</div>
						)}
						<div
							contentEditable
							suppressContentEditableWarning
							ref={contentRef}
							onInput={handleInput}
							onPaste={handlePaste}
							onKeyDown={handleKeyDown}
							className="min-h-[1.25em] grow bg-transparent text-lg leading-tight tracking-tight break-all text-white outline-none placeholder:text-white/30 md:text-2xl"
						></div>
						{(isValid || isInvalid) && (
							<span
								className={cn(
									'flex h-6 w-6 shrink-0 translate-y-px items-center justify-center rounded-xs md:mt-0.5',
									isValid ? 'bg-valid' : 'bg-error',
								)}
							>
								<svg
									viewBox="0 0 12 12"
									fill="none"
									stroke="black"
									strokeWidth="2"
									strokeLinecap="round"
									strokeLinejoin="round"
									className="h-3 w-3"
								>
									{isValid ? (
										<path d="M1.875 6.75L4.5 9.375L10.5 3.375" />
									) : (
										<>
											<path d="M9.37353 2.62488L2.62354 9.37488" />
											<path d="M9.37353 9.37488L2.62354 2.62488" />
										</>
									)}
								</svg>
							</span>
						)}
					</div>
					{isInvalid && errorMessage && (
						<span className="text-error text-xs leading-none md:text-sm">{errorMessage}</span>
					)}
				</>
			)}
		</div>
	);
}
