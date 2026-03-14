import React from 'react';
import ReactDOM from 'react-dom/client';

import './index.css';
import '@mysten/dapp-kit/dist/index.css';

import { SuiClientProvider, WalletProvider } from '@mysten/dapp-kit';
import { SuiJsonRpcClient } from '@mysten/sui/jsonRpc';
import { getJsonRpcFullnodeUrl } from '@mysten/sui/jsonRpc';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';

import App from './App';
import { CONFIG } from './lib/constants';
import { LocalStorageKeys } from './lib/localStorageKeys';

const networks: Record<string, { url: string; network: string }> = {
	devnet: { url: getJsonRpcFullnodeUrl('devnet'), network: 'devnet' },
	testnet: { url: getJsonRpcFullnodeUrl('testnet'), network: 'testnet' },
	mainnet: { url: getJsonRpcFullnodeUrl('mainnet'), network: 'mainnet' },
};

// Add localnet if a custom RPC URL is provided
if (CONFIG.SUI_RPC_URL && CONFIG.DEFAULT_NETWORK === 'localnet') {
	networks.localnet = { url: CONFIG.SUI_RPC_URL, network: 'localnet' };
}

// Override devnet URL if a custom RPC URL is provided for devnet
if (CONFIG.SUI_RPC_URL && CONFIG.DEFAULT_NETWORK === 'devnet') {
	networks.devnet = { url: CONFIG.SUI_RPC_URL, network: 'devnet' };
}

const storedNetwork =
	localStorage.getItem(LocalStorageKeys.SuiNetwork) || CONFIG.DEFAULT_NETWORK;

const defaultNetwork = storedNetwork in networks ? storedNetwork : CONFIG.DEFAULT_NETWORK;

const queryClient = new QueryClient();

ReactDOM.createRoot(document.getElementById('root')!).render(
	<React.StrictMode>
		<QueryClientProvider client={queryClient}>
			<SuiClientProvider
				networks={networks}
				defaultNetwork={defaultNetwork}
				createClient={(_name, config) =>
					new SuiJsonRpcClient({ url: config.url, network: config.network as 'devnet' | 'testnet' | 'mainnet' })
				}
			>
				<WalletProvider autoConnect enableUnsafeBurner={!!networks.localnet}>
					<App />
				</WalletProvider>
			</SuiClientProvider>
		</QueryClientProvider>
		<Toaster theme="dark" position="bottom-right" />
	</React.StrictMode>,
);
