import { useState, useRef, useEffect } from 'react';
import { Logo } from '@/components/atoms/Logo';
import { Icon } from '@/components/atoms/Icon';
import { HeadButton } from '@/components/atoms/HeadButton';
import { MainMenu } from '@/components/organisms/MainMenu';
import { NetworkBadge } from '@/components/atoms/NetworkBadge';
import { cn } from '@/lib/utils';

type HeaderProps = {
	username?: string;
	address?: string;
	onDisconnect?: () => void;
	onConnectWalletClick?: () => void;
	className?: string;
};

export function Header({ className, ...props }: HeaderProps) {
	const [dropdownOpen, setDropdownOpen] = useState(false);
	const [copied, setCopied] = useState(false);
	const dropdownRef = useRef<HTMLDivElement>(null);

	useEffect(() => {
		const handleClickOutside = (e: MouseEvent) => {
			if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
				setDropdownOpen(false);
			}
		};
		document.addEventListener('mousedown', handleClickOutside);
		return () => document.removeEventListener('mousedown', handleClickOutside);
	}, []);

	return (
		<header
			className={cn(
				'relative flex w-full items-center justify-between border-b border-white/15 px-3 py-2.5 md:px-5 md:py-3.5',
				className,
			)}
		>
			<div className="flex items-center gap-2.5">
				<Logo />
				<NetworkBadge />
			</div>

			{props.username ? (
				<div className="flex gap-2 md:gap-3">
					<div className="relative" ref={dropdownRef}>
						<HeadButton
							leadingIcon={<Icon name="SUI" />}
							trailingIcon={<Icon name="CaretDown" />}
							onClick={() => setDropdownOpen((prev) => !prev)}
						>
							{props.username}
						</HeadButton>
						{dropdownOpen && (
							<div className="absolute right-0 top-full z-50 mt-2 min-w-48 rounded-xs bg-black p-2 shadow-popover ring-1 ring-white/16 ring-inset">
								<button
									className="flex w-full items-center justify-between gap-2 rounded-xs px-3 py-2 text-left text-sm text-white/80 transition-colors hover:bg-white/10 hover:text-white"
									onClick={() => {
										navigator.clipboard.writeText(props.address ?? '');
										setCopied(true);
										setTimeout(() => setCopied(false), 2000);
									}}
								>
									{copied ? 'Copied!' : 'Copy Address'}
									{copied && <Icon name="Check" className="h-4 w-4 text-valid" />}
								</button>
								<button
									className="flex w-full items-center gap-2 rounded-xs px-3 py-2 text-left text-sm text-white/80 transition-colors hover:bg-white/10 hover:text-white"
									onClick={() => {
										setDropdownOpen(false);
										props.onDisconnect?.();
									}}
								>
									Disconnect
								</button>
							</div>
						)}
					</div>
					<MainMenu />
				</div>
			) : (
				<HeadButton
					leadingIcon={<Icon name="SUI" />}
					onClick={props.onConnectWalletClick}
				>
					Connect Wallet
				</HeadButton>
			)}
		</header>
	);
}
