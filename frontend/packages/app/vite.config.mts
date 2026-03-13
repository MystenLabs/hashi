import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react-swc';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig(({ mode }) => {
	const env = loadEnv(mode, __dirname, 'VITE_');
	const btcRpcUrl = env.VITE_BTC_RPC_URL;

	return {
		plugins: [react(), tailwindcss()],
		resolve: {
			alias: {
				'@': path.resolve(__dirname, './src'),
			},
		},
		server: {
			proxy: btcRpcUrl
				? {
						'/btc-rpc': {
							target: btcRpcUrl,
							changeOrigin: true,
							rewrite: (p: string) => p.replace(/^\/btc-rpc/, ''),
						},
					}
				: undefined,
		},
	};
});
