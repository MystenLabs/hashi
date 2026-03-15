import { useEffect, useRef } from 'react';
import QRCodeLib from 'qrcode';
import { cn } from '@/lib/utils';

interface QRCodeProps {
	value: string;
	size?: number;
	className?: string;
}

const LOGO_RATIO = 0.22;

function drawLogo(canvas: HTMLCanvasElement, size: number) {
	const ctx = canvas.getContext('2d');
	if (!ctx) return;

	const img = new Image();
	img.onload = () => {
		const logoSize = Math.floor(size * LOGO_RATIO);
		const padding = 4;
		const totalSize = logoSize + padding * 2;
		const x = (canvas.width - totalSize) / 2;
		const y = (canvas.height - totalSize) / 2;

		// White background
		ctx.fillStyle = '#ffffff';
		ctx.beginPath();
		ctx.roundRect(x, y, totalSize, totalSize, 6);
		ctx.fill();

		// Draw logo
		const ix = (canvas.width - logoSize) / 2;
		const iy = (canvas.height - logoSize) / 2;
		ctx.drawImage(img, ix, iy, logoSize, logoSize);
	};
	img.src = '/suibtc-logo.svg';
}

export function QRCode({ value, size = 120, className }: QRCodeProps) {
	const canvasRef = useRef<HTMLCanvasElement>(null);

	useEffect(() => {
		if (!canvasRef.current || !value) return;

		QRCodeLib.toCanvas(canvasRef.current, value, {
			width: size,
			margin: 2,
			color: { dark: '#000000', light: '#ffffff' },
			errorCorrectionLevel: 'H',
		}, () => {
			if (canvasRef.current) drawLogo(canvasRef.current, size);
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
