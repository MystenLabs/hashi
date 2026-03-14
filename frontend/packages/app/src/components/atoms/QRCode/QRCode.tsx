import { useEffect, useRef } from 'react';
import QRCodeLib from 'qrcode';
import { cn } from '@/lib/utils';

interface QRCodeProps {
	value: string;
	size?: number;
	className?: string;
}

export function QRCode({ value, size = 120, className }: QRCodeProps) {
	const canvasRef = useRef<HTMLCanvasElement>(null);

	useEffect(() => {
		if (!canvasRef.current || !value) return;
		QRCodeLib.toCanvas(canvasRef.current, value, {
			width: size,
			margin: 2,
			color: { dark: '#000000', light: '#ffffff' },
			errorCorrectionLevel: 'M',
		});
	}, [value, size]);

	if (!value) {
		return (
			<div
				className={cn('flex items-center justify-center rounded-xs bg-white', className)}
				style={{ width: size, height: size }}
			>
				<div className="text-xs text-black/40">No address</div>
			</div>
		);
	}

	return <canvas ref={canvasRef} className={cn('animate-scale-in rounded-xs', className)} />;
}
