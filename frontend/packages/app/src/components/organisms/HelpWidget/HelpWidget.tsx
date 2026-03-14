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
				'pointer-events-none fixed right-3 bottom-3 z-20 flex flex-col justify-end md:absolute md:top-5 md:right-5 md:bottom-5',
				className,
			)}
		>
			<div className="sticky bottom-5">
				<div ref={containerRef} className="pointer-events-auto relative">
					<HowItWorks
						onClose={() => setIsOpen(false)}
						className={
							'pointer-events-none absolute -right-3 -bottom-3 h-dvh w-screen origin-bottom-right scale-95 overflow-auto opacity-0 transition md:right-0 md:bottom-full md:mb-5 md:h-auto md:w-120 [&.opened]:pointer-events-auto [&.opened]:scale-100 [&.opened]:opacity-100' +
							(isOpen ? ' opened' : '')
						}
					/>
					<HelpButton onClick={() => setIsOpen((prev) => !prev)} />
				</div>
			</div>
		</div>
	);
}
