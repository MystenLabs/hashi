import { useQuery } from '@tanstack/react-query';
import { useSuiClient } from '@mysten/dapp-kit';
import { CONFIG } from '@/lib/constants';

export type DepositOnChainStatus = 'pending' | 'confirmed' | 'expired' | 'unknown';

export interface DepositOnChainData {
	requestId: string;
	amount: string;
	derivationPath: string | null;
	btcTxid: string;
	btcVout: number;
	timestampMs: string;
	status: DepositOnChainStatus;
	suiTxDigest: string;
}

export function useDepositByDigest(txDigest: string | undefined) {
	const client = useSuiClient();
	const pkg = CONFIG.HASHI_PACKAGE_ID;

	return useQuery({
		queryKey: ['deposit-by-digest', txDigest],
		queryFn: async (): Promise<DepositOnChainData | null> => {
			if (!txDigest || !pkg) return null;

			// 1. Fetch the original transaction to get DepositRequestedEvent
			const tx = await client.getTransactionBlock({
				digest: txDigest,
				options: { showEvents: true },
			});

			const depositEvent = tx.events?.find((e) =>
				e.type.includes('::deposit::DepositRequestedEvent'),
			);

			if (!depositEvent?.parsedJson) return null;

			const parsed = depositEvent.parsedJson as {
				request_id: string;
				utxo_id: { txid: string; vout: number };
				amount: string;
				derivation_path: string | null;
				timestamp_ms: string;
			};

			// 2. Check if deposit has been confirmed by querying for DepositConfirmedEvent
			let status: DepositOnChainStatus = 'pending';

			try {
				const confirmedEvents = await client.queryEvents({
					query: {
						MoveEventType: `${pkg}::deposit::DepositConfirmedEvent`,
					},
					limit: 50,
				});

				const isConfirmed = confirmedEvents.data.some(
					(e) =>
						(e.parsedJson as { request_id: string })?.request_id ===
						parsed.request_id,
				);

				if (isConfirmed) status = 'confirmed';
			} catch {
				// queryEvents may fail if event type doesn't exist yet — that's ok
			}

			// 3. Check for expired
			if (status === 'pending') {
				try {
					const expiredEvents = await client.queryEvents({
						query: {
							MoveEventType: `${pkg}::deposit::ExpiredDepositDeletedEvent`,
						},
						limit: 50,
					});

					const isExpired = expiredEvents.data.some(
						(e) =>
							(e.parsedJson as { request_id: string })?.request_id ===
							parsed.request_id,
					);

					if (isExpired) status = 'expired';
				} catch {
					// ok
				}
			}

			return {
				requestId: parsed.request_id,
				amount: (Number(parsed.amount) / 1e8).toString(),
				derivationPath: parsed.derivation_path,
				btcTxid: parsed.utxo_id.txid,
				btcVout: parsed.utxo_id.vout,
				timestampMs: parsed.timestamp_ms,
				status,
				suiTxDigest: txDigest,
			};
		},
		enabled: !!txDigest && !!pkg,
		refetchInterval: (query) => {
			const data = query.state.data;
			// Stop polling once confirmed or expired
			if (data?.status === 'confirmed' || data?.status === 'expired') return false;
			return 15_000;
		},
	});
}
