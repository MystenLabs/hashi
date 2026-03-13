import { useEffect } from 'react';
import { cn } from '@/lib/utils';

interface ModalProps {
	isOpen: boolean;
	onClose?: () => void;
	children: React.ReactNode;
	className?: string;
}

export function Modal({ isOpen, onClose, children, className }: ModalProps) {
	useEffect(() => {
		if (isOpen) {
			document.body.style.overflow = 'hidden';
		} else {
			document.body.style.overflow = '';
		}
		return () => {
			document.body.style.overflow = '';
		};
	}, [isOpen]);

	useEffect(() => {
		const handleKeyDown = (e: KeyboardEvent) => {
			if (e.key === 'Escape') onClose?.();
		};
		if (isOpen) document.addEventListener('keydown', handleKeyDown);
		return () => document.removeEventListener('keydown', handleKeyDown);
	}, [isOpen, onClose]);

	return (
		<div
			className={
				'group/modal pointer-events-none fixed inset-0 z-50 flex overflow-auto p-5 opacity-0 transition-opacity [&.open]:pointer-events-auto [&.open]:opacity-100' +
				(isOpen ? ' open' : '')
			}
		>
			<div className="fixed inset-0 cursor-pointer bg-black/60 backdrop-blur-sm" onClick={onClose} />
			<div
				className={cn(
					'relative m-auto w-full max-w-140 scale-95 transition-transform group-[&.open]/modal:scale-100',
					className,
				)}
			>
				{children}
			</div>
		</div>
	);
}
