import { useState, useRef, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';
import { HeadButton } from '@/components/atoms/HeadButton';
import { useNavigate } from 'react-router-dom';

export interface MainMenuItemProps {
	label: string;
	icon: React.ReactNode;
	external?: boolean;
	href?: string;
}

const menuItems: MainMenuItemProps[] = [
	{
		label: 'Transaction History',
		href: '/history',
		icon: (
			<svg
				viewBox="0 0 16 16"
				fill="none"
				stroke="currentcolor"
				strokeLinecap="round"
				strokeLinejoin="round"
			>
				<path d="M7 11L5 13L3 11" />
				<path d="M5 3V13" />
				<path d="M9 5L11 3L13 5" />
				<path d="M11 13V3" />
			</svg>
		),
	},
	{
		label: 'Settings',
		icon: (
			<svg
				viewBox="0 0 16 16"
				fill="none"
				stroke="currentcolor"
				strokeLinecap="round"
				strokeLinejoin="round"
			>
				<path d="M8 10.5C9.38071 10.5 10.5 9.38071 10.5 8C10.5 6.61929 9.38071 5.5 8 5.5C6.61929 5.5 5.5 6.61929 5.5 8C5.5 9.38071 6.61929 10.5 8 10.5Z" />
				<path d="M2.59031 11.1306C2.31405 10.6547 2.10239 10.1442 1.96094 9.61246L3.00969 8.29996C2.99781 8.0993 2.99781 7.89812 3.00969 7.69746L1.96156 6.38496C2.10277 5.85313 2.314 5.34242 2.58969 4.86621L4.25906 4.67871C4.39237 4.52852 4.5345 4.38639 4.68469 4.25309L4.87219 2.58434C5.34771 2.30996 5.85759 2.09999 6.38844 1.95996L7.70094 3.00871C7.9016 2.99684 8.10278 2.99684 8.30344 3.00871L9.61594 1.96059C10.1478 2.1018 10.6585 2.31302 11.1347 2.58871L11.3222 4.25809C11.4724 4.39139 11.6145 4.53352 11.7478 4.68371L13.4166 4.87121C13.6928 5.34706 13.9045 5.85759 14.0459 6.38934L12.9972 7.70184C13.0091 7.90249 13.0091 8.10368 12.9972 8.30434L14.0453 9.61684C13.9051 10.1485 13.6949 10.6592 13.4203 11.1356L11.7509 11.3231C11.6176 11.4733 11.4755 11.6154 11.3253 11.7487L11.1378 13.4175C10.662 13.6937 10.1514 13.9054 9.61969 14.0468L8.30719 12.9981C8.10653 13.01 7.90535 13.01 7.70469 12.9981L6.39219 14.0462C5.86052 13.906 5.34981 13.6958 4.87344 13.4212L4.68594 11.7518C4.53575 11.6185 4.39362 11.4764 4.26031 11.3262L2.59031 11.1306Z" />
			</svg>
		),
	},
	{
		external: true,
		label: 'Learn about suiBTC',
		icon: (
			<svg
				viewBox="0 0 16 16"
				fill="none"
				stroke="currentcolor"
				strokeLinecap="round"
				strokeLinejoin="round"
			>
				<path d="M8 14C11.3137 14 14 11.3137 14 8C14 4.68629 11.3137 2 8 2C4.68629 2 2 4.68629 2 8C2 11.3137 4.68629 14 8 14Z" />
				<path d="M7.5 7.5C7.63261 7.5 7.75979 7.55268 7.85355 7.64645C7.94732 7.74021 8 7.86739 8 8V10.5C8 10.6326 8.05268 10.7598 8.14645 10.8536C8.24021 10.9473 8.36739 11 8.5 11" />
				<path
					d="M7.75 6C8.16421 6 8.5 5.66421 8.5 5.25C8.5 4.83579 8.16421 4.5 7.75 4.5C7.33579 4.5 7 4.83579 7 5.25C7 5.66421 7.33579 6 7.75 6Z"
					fill="currentcolor"
					stroke="0"
				/>
			</svg>
		),
	},
];

export function MainMenu({
	items = menuItems,
	className,
}: {
	items?: MainMenuItemProps[];
	className?: string;
}) {
	const [isOpen, setIsOpen] = useState(false);
	const containerRef = useRef<HTMLDivElement>(null);
	const navigate = useNavigate();

	useEffect(() => {
		const handleClickOutside = (e: MouseEvent) => {
			if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
				setIsOpen(false);
			}
		};
		if (isOpen) document.addEventListener('mousedown', handleClickOutside);
		return () => document.removeEventListener('mousedown', handleClickOutside);
	}, [isOpen]);

	useEffect(() => {
		const handleKeyDown = (e: KeyboardEvent) => {
			if (e.key === 'Escape') setIsOpen(false);
		};
		if (isOpen) document.addEventListener('keydown', handleKeyDown);
		return () => document.removeEventListener('keydown', handleKeyDown);
	}, [isOpen]);

	return (
		<div ref={containerRef} className={cn('relative', className)}>
			<HeadButton
				trailingIcon={<Icon name="List" />}
				onClick={() => setIsOpen((prev) => !prev)}
			></HeadButton>
			<div
				className={
					'shadow-popover pointer-events-none absolute top-full right-0 mt-5 w-60 origin-top-right scale-95 rounded-xs opacity-0 transition [&.opened]:pointer-events-auto [&.opened]:scale-100 [&.opened]:opacity-100' +
					(isOpen ? ' opened' : '')
				}
			>
				<div className="rounded-xs bg-black ring-1 ring-white/12 ring-inset">
					{items.map((item) => (
						<button
							key={item.label}
							type="button"
							className="-mt-px flex w-full items-center gap-2 border-t border-white/12 p-3 transition-colors first:mt-0 first:border-0 hover:bg-white/6"
							onClick={() => {
								setIsOpen(false);
								if (item.href) navigate(item.href);
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
	);
}
