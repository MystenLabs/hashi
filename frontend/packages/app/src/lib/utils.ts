import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
	return twMerge(clsx(inputs));
}

export function truncateAddress(address: string, prefixLen = 6, suffixLen = 4) {
	if (address.length <= prefixLen + suffixLen + 3) return address;
	return `${address.slice(0, prefixLen)}...${address.slice(-suffixLen)}`;
}

export function truncateHash(hash: string) {
	return truncateAddress(hash, 4, 5);
}
