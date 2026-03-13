import { useState, useRef, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { HelpButton } from '@/components/atoms/HelpButton';
import { HowItWorks } from '@/components/molecules/HowItWorks';

export function HelpWidget({ className }: { className?: string }) {
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
		<div
			className={cn(
				'fixed top-5 right-5 bottom-5 z-10 flex flex-col justify-end md:absolute',
				className,
			)}
		>
			<div className="sticky bottom-5">
				<div ref={containerRef} className="relative">
					<div
						className={
							'shadow-popover pointer-events-none absolute right-0 bottom-19 w-120 origin-bottom-right scale-95 rounded-xs opacity-0 transition [&.opened]:pointer-events-auto [&.opened]:scale-100 [&.opened]:opacity-100' +
							(isOpen ? ' opened' : '')
						}
					>
						<HowItWorks onClose={() => setIsOpen(false)} />
					</div>
					<HelpButton onClick={() => setIsOpen((prev) => !prev)} />
				</div>
			</div>
		</div>
	);
}
