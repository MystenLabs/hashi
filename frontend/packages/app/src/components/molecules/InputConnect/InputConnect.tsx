import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';

interface InputConnectProps {
	label?: string;
	isConnected?: boolean;
	username?: string;
	errorMessage?: string;
	className?: string;
	onConnectWallet?: () => void;
	onDisconnectWallet?: () => void;
}

export function InputConnect({
	label = 'From SUI Wallet',
	isConnected = false,
	username,
	errorMessage,
	className,
	onConnectWallet,
	onDisconnectWallet,
}: InputConnectProps) {
	return (
		<div
			className={cn(
				'flex w-full flex-col gap-4 rounded-xs bg-black/16 p-8 ring-1 ring-black/24 transition-shadow ring-inset',
				className,
			)}
		>
			{/* Title */}
			<div className="-my-0.5 flex items-center justify-between">
				<label className="pointer-events-none leading-none text-current/80">
					{label}
				</label>
			</div>

			{/* Connect Button */}
			{!isConnected && (
				<button
					type="button"
					className="-my-0.5 flex cursor-pointer items-center gap-1.5 text-2xl leading-none"
					onClick={onConnectWallet}
				>
					Connect Wallet
					<Icon name="CaretDown" className="h-6 w-6 -rotate-90" />
				</button>
			)}

			{/* User */}
			{isConnected && (
				<div className="flex items-center justify-between">
					<div className="-my-0.5 text-2xl leading-none">{username}</div>
					<button
						type="button"
						className="flex opacity-70 transition-opacity hover:opacity-100"
						onClick={onDisconnectWallet}
					>
						<Icon name="LinkBreak" />
					</button>
				</div>
			)}

			{/* Error message */}
			{errorMessage && (
				<span className="text-error text-sm leading-none">{errorMessage}</span>
			)}
		</div>
	);
}
