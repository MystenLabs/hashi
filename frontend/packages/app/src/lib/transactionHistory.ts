import { LocalStorageKeys } from './localStorageKeys';

export interface StoredTransaction {
	id: string;
	direction: 'btc-to-sui' | 'sui-to-btc';
	amount: string;
	currency: 'BTC' | 'hBTC';
	date: string;
}

function storageKey(walletAddress: string): string {
	return `${LocalStorageKeys.TransactionHistory}:${walletAddress}`;
}

export function getTransactions(walletAddress: string): StoredTransaction[] {
	try {
		const raw = localStorage.getItem(storageKey(walletAddress));
		return raw ? JSON.parse(raw) : [];
	} catch {
		return [];
	}
}

export function addTransaction(walletAddress: string, tx: StoredTransaction): void {
	const existing = getTransactions(walletAddress);
	// Deduplicate by id
	if (existing.some((t) => t.id === tx.id)) return;
	const updated = [tx, ...existing];
	localStorage.setItem(storageKey(walletAddress), JSON.stringify(updated));
}

export function formatDate(date: Date): string {
	return date.toLocaleDateString('en-US', {
		month: 'short',
		day: 'numeric',
		year: 'numeric',
		hour: 'numeric',
		minute: '2-digit',
	});
}
