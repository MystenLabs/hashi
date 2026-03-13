import { useState, useRef, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { Icon } from '@/components/atoms/Icon';
import { HeadButton } from '@/components/atoms/HeadButton';
import { Notifications } from '@/components/molecules/Notifications';

export function NotificationsMenu({ className }: { className?: string }) {
	const [isOpen, setIsOpen] = useState(false);
	const containerRef = useRef<HTMLDivElement>(null);

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
				trailingIcon={<Icon name="Bell" />}
				onClick={() => setIsOpen((prev) => !prev)}
			></HeadButton>
			<div className="bg-yellow absolute top-0 right-0 h-2 w-2 rounded-full ring-2 ring-black"></div>
			<div
				className={
					'shadow-popover pointer-events-none absolute top-full right-0 mt-5 w-120 origin-top-right scale-95 rounded-xs opacity-0 transition [&.opened]:pointer-events-auto [&.opened]:scale-100 [&.opened]:opacity-100' +
					(isOpen ? ' opened' : '')
				}
			>
				<Notifications notifications={[]} onClose={() => setIsOpen(false)} />
			</div>
		</div>
	);
}
