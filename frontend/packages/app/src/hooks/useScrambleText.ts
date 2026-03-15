import { useState, useCallback, useRef, useEffect } from 'react';

export const SCRAMBLE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*<>[]{}|/~';
export const SCRAMBLE_ACCENT = '#298DFF';

const DURATION = 450; // ms
const SPEED_INTERVAL = 38; // ms between scramble ticks
const SCRAMBLE_RATIO = 0.4; // only scramble ~40% of characters
const COLOR_CHANCE = 0.3; // chance a scrambled char flashes blue

export interface CharState {
	char: string;
	resolved: boolean;
	colored: boolean;
}

interface ScrambleOptions {
	autoPlay?: boolean;
}

/**
 * Core scramble engine — manages character state, timing, and animation lifecycle.
 * Returns raw char states for flexible rendering by consumers.
 */
export function useScrambleText(text: string, options: ScrambleOptions = {}) {
	const { autoPlay = false } = options;

	const [chars, setChars] = useState<CharState[]>(() =>
		Array.from(text).map((ch) => {
			const shouldScramble = autoPlay && ch !== ' ' && Math.random() < SCRAMBLE_RATIO;
			return {
				char: shouldScramble ? SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)] : ch,
				resolved: !shouldScramble,
				colored: shouldScramble && Math.random() < COLOR_CHANCE,
			};
		}),
	);
	const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
	const startRef = useRef(0);

	useEffect(() => {
		return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
	}, []);

	const scramble = useCallback(() => {
		if (!text) return;
		if (intervalRef.current) clearInterval(intervalRef.current);
		startRef.current = performance.now();

		const scrambleMask = Array.from(text).map((ch) =>
			ch === ' ' ? false : Math.random() < SCRAMBLE_RATIO,
		);
		const revealTimes = Array.from(text).map((_, i) =>
			(0.11 + (i / text.length) * 0.3) * 1000,
		);

		const tick = () => {
			const elapsed = performance.now() - startRef.current;
			let allDone = true;
			const next: CharState[] = [];

			for (let i = 0; i < text.length; i++) {
				const ch = text[i];
				if (ch === ' ') {
					next.push({ char: ' ', resolved: true, colored: false });
					continue;
				}
				if (!scrambleMask[i] || elapsed >= revealTimes[i] + DURATION * 0.5) {
					next.push({ char: ch, resolved: true, colored: false });
				} else {
					allDone = false;
					next.push({
						char: SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)],
						resolved: false,
						colored: Math.random() < COLOR_CHANCE,
					});
				}
			}

			setChars(next);

			if (allDone) {
				clearInterval(intervalRef.current!);
				intervalRef.current = null;
				setChars(Array.from(text).map((ch) => ({ char: ch, resolved: true, colored: false })));
			}
		};

		intervalRef.current = setInterval(tick, SPEED_INTERVAL);
		tick();
	}, [text]);

	useEffect(() => {
		if (autoPlay && text) scramble();
	}, []); // eslint-disable-line react-hooks/exhaustive-deps

	const reset = useCallback(() => {
		if (intervalRef.current) {
			clearInterval(intervalRef.current);
			intervalRef.current = null;
		}
		setChars(Array.from(text).map((ch) => ({ char: ch, resolved: true, colored: false })));
	}, [text]);

	return { chars, scramble, reset };
}
