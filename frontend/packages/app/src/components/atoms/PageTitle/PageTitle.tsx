import { cn } from '@/lib/utils';
import { useScrambleText, SCRAMBLE_ACCENT } from '@/hooks/useScrambleText';

interface PageTitleProps {
	children: React.ReactNode;
	className?: string;
}

export function PageTitle({ children, className }: PageTitleProps) {
	const text = typeof children === 'string' ? children : '';
	const { chars } = useScrambleText(text, { autoPlay: true });

	if (!text) {
		return (
			<h1 className={cn('text-h2 md:text-h1 mx-auto mb-10 text-center', className)}>
				{children}
			</h1>
		);
	}

	// Group characters by word so browser wraps at word boundaries
	const words = text.split(' ');
	let charIndex = 0;

	return (
		<h1 className={cn('text-h2 md:text-h1 mx-auto mb-10 text-center', className)}>
			{words.map((word, wi) => {
				const startIndex = charIndex;
				charIndex += word.length + 1; // +1 for the space
				return (
					<span key={wi}>
						{wi > 0 && ' '}
						<span className="inline-flex">
							{Array.from(word).map((ch, ci) => {
								const i = startIndex + ci;
								const state = chars[i];
								const overlay = state && !state.resolved ? state.char : null;
								return (
									<span key={i} className="relative">
										<span className={overlay ? 'invisible' : undefined}>{ch}</span>
										{overlay && (
											<span
												className="absolute inset-0 text-center"
												style={state.colored ? { color: SCRAMBLE_ACCENT } : undefined}
											>
												{overlay}
											</span>
										)}
									</span>
								);
							})}
						</span>
					</span>
				);
			})}
		</h1>
	);
}
