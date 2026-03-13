import { useState, useCallback, useRef } from 'react';

export function useCopyToClipboard(resetMs = 2000) {
	const [copied, setCopied] = useState(false);
	const timeoutRef = useRef<ReturnType<typeof setTimeout>>(undefined);

	const copy = useCallback(
		(text: string) => {
			navigator.clipboard.writeText(text);
			setCopied(true);
			clearTimeout(timeoutRef.current);
			timeoutRef.current = setTimeout(() => setCopied(false), resetMs);
		},
		[resetMs],
	);

	return { copied, copy };
}
