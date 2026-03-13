export const CONFIG = {
	DEFAULT_NETWORK: (import.meta.env.VITE_DEFAULT_NETWORK ?? 'testnet') as string,
	HASHI_OBJECT_ID: import.meta.env.VITE_HASHI_OBJECT_ID ?? '',
	HASHI_PACKAGE_ID: import.meta.env.VITE_HASHI_PACKAGE_ID ?? '',
	SUI_RPC_URL: import.meta.env.VITE_SUI_RPC_URL ?? '',
	BTC_RPC_URL: import.meta.env.VITE_BTC_RPC_URL ?? '',
	BTC_RPC_USER: import.meta.env.VITE_BTC_RPC_USER ?? '',
	BTC_RPC_PASSWORD: import.meta.env.VITE_BTC_RPC_PASSWORD ?? '',
} as const;
