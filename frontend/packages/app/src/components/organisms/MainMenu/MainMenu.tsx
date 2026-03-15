import { useState, useRef, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';
import { HeadButton } from '@/components/atoms/HeadButton';
import { Modal } from '@/components/atoms/Modal';
import { Settings } from '@/components/organisms/Settings/Settings';
import { useNavigate } from 'react-router-dom';

export interface MainMenuItemProps {
	label: string;
	icon: React.ReactNode;
	external?: boolean;
	href?: string;
	onClick?: () => void;
	mobileOnly?: boolean;
}

export function MainMenu({
	showNotifications = false,
	className,
}: {
	showNotifications?: boolean;
	className?: string;
}) {
	const [isOpen, setIsOpen] = useState(false);
	const [isSettingsOpen, setIsSettingsOpen] = useState(false);
	const containerRef = useRef<HTMLDivElement>(null);
	const navigate = useNavigate();

	const items: MainMenuItemProps[] = [
		...(showNotifications
			? [{ label: 'Notifications', icon: <Icon name="Bell" className="h-4 w-4" />, mobileOnly: true } as MainMenuItemProps]
			: []),
		{
			label: 'Transaction History',
			href: '/history',
			icon: <Icon name="MenuHistory" className="h-4 w-4" />,
		},
		{
			label: 'Settings',
			icon: <Icon name="MenuSettings" className="h-4 w-4" />,
			onClick: () => setIsSettingsOpen(true),
		},
		{
			external: true,
			label: 'Learn about suiBTC',
			icon: <Icon name="MenuLearn" className="h-4 w-4" />,
		},
	];

	// Close on escape press
	useEffect(() => {
		const handleKeyDown = (e: KeyboardEvent) => {
			if (e.key === 'Escape') setIsOpen(false);
		};
		if (isOpen) document.addEventListener('keydown', handleKeyDown);
		return () => document.removeEventListener('keydown', handleKeyDown);
	}, [isOpen]);

	// Close on outside click
	useEffect(() => {
		const handleClickOutside = (e: MouseEvent) => {
			if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
				setIsOpen(false);
			}
		};
		if (isOpen) document.addEventListener('mousedown', handleClickOutside);
		return () => document.removeEventListener('mousedown', handleClickOutside);
	}, [isOpen]);

	return (
		<>
			<div ref={containerRef} className={cn('md:relative', className)}>
				<HeadButton
					trailingIcon={<Icon name="List" />}
					className={isOpen ? 'active' : ''}
					onClick={() => setIsOpen((prev) => !prev)}
				></HeadButton>
				<div
					className={
						'shadow-popover pointer-events-none absolute top-full right-0 z-50 w-full origin-top-right scale-95 opacity-0 transition md:mt-5 md:w-60 md:rounded-xs [&.opened]:pointer-events-auto [&.opened]:scale-100 [&.opened]:opacity-100' +
						(isOpen ? ' opened' : '')
					}
				>
					<div className="rounded-xs bg-black ring-1 ring-white/12 ring-inset">
						{items.map((item) => (
							<button
								key={item.label}
								type="button"
								className={cn(
									'-mt-px flex w-full items-center gap-2 border-t border-white/12 p-3 transition-colors first:mt-0 first:border-0 hover:bg-white/6',
									item.mobileOnly && 'md:hidden',
								)}
								onClick={() => {
									setIsOpen(false);
									if (item.onClick) item.onClick();
									else if (item.href) navigate(item.href);
								}}
							>
								<div className="mb-px flex h-6 w-6 items-center justify-center rounded bg-white/12 p-1 text-current/60">
									{item.icon}
								</div>
								<span>{item.label}</span>
								{item.external && (
									<svg
										viewBox="0 0 16 16"
										fill="none"
										stroke="currentcolor"
										strokeLinecap="round"
										strokeLinejoin="round"
										className="ml-auto h-4 w-4 opacity-60"
									>
										<path d="M4 12L12 4" />
										<path d="M5.5 4H12V10.5" />
									</svg>
								)}
							</button>
						))}
					</div>
				</div>
			</div>
			<Modal isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)}>
				<Settings onClose={() => setIsSettingsOpen(false)} />
			</Modal>
		</>
	);
}
