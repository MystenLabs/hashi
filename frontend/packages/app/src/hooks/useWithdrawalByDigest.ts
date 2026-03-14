import { useQuery } from '@tanstack/react-query';
import { useSuiClient } from '@mysten/dapp-kit';
import { CONFIG } from '@/lib/constants';
import { witnessProgramToAddress } from '@/lib/bitcoin';

export type WithdrawalOnChainStatus =
	| 'requested'
	| 'approved'
	| 'processing'
	| 'signed'
	| 'confirmed'
	| 'cancelled'
	| 'unknown';

export interface WithdrawalOnChainData {
	requestId: string;
	btcAmount: string;
	bitcoinAddress: string;
	requesterAddress: string;
	timestampMs: string;
	status: WithdrawalOnChainStatus;
	suiTxDigest: string;
}

export function useWithdrawalByDigest(txDigest: string | undefined) {
	const client = useSuiClient();
	const pkg = CONFIG.HASHI_PACKAGE_ID;

	return useQuery({
		queryKey: ['withdrawal-by-digest', txDigest],
		queryFn: async (): Promise<WithdrawalOnChainData | null> => {
			if (!txDigest || !pkg) return null;

			// 1. Fetch the original transaction to get WithdrawalRequestedEvent
			const tx = await client.getTransactionBlock({
				digest: txDigest,
				options: { showEvents: true },
			});

			const withdrawEvent = tx.events?.find((e) =>
				e.type.includes('::withdrawal_queue::WithdrawalRequestedEvent'),
			);

			if (!withdrawEvent?.parsedJson) return null;

			const parsed = withdrawEvent.parsedJson as {
				request_id: string;
				btc_amount: string;
				bitcoin_address: number[];
				timestamp_ms: string;
				requester_address: string;
			};

			const btcNetwork = CONFIG.DEFAULT_NETWORK === 'mainnet' ? 'mainnet' : CONFIG.DEFAULT_NETWORK === 'localnet' ? 'regtest' : 'testnet';
			const btcAddr = witnessProgramToAddress(parsed.bitcoin_address, btcNetwork);

			// 2. Determine status by checking for downstream events
			let status: WithdrawalOnChainStatus = 'requested';
			let pendingId: string | null = null;

			// Check events from least to most advanced, updating status as we find matches.
			// WithdrawalConfirmedEvent uses pending_id (not request_ids), so we need to
			// resolve the pending_id from PickedForProcessing first.

			// Check: approved
			try {
				const events = await client.queryEvents({
					query: { MoveEventType: `${pkg}::withdrawal_queue::WithdrawalApprovedEvent` },
					limit: 50,
				});
				if (events.data.some((e) => (e.parsedJson as Record<string, unknown>).request_id === parsed.request_id)) {
					status = 'approved';
				}
			} catch { /* ok */ }

			// Check: cancelled
			try {
				const events = await client.queryEvents({
					query: { MoveEventType: `${pkg}::withdrawal_queue::WithdrawalCancelledEvent` },
					limit: 50,
				});
				if (events.data.some((e) => (e.parsedJson as Record<string, unknown>).request_id === parsed.request_id)) {
					status = 'cancelled';
				}
			} catch { /* ok */ }

			// Check: picked for processing (also resolves pending_id for later)
			try {
				const events = await client.queryEvents({
					query: { MoveEventType: `${pkg}::withdrawal_queue::WithdrawalPickedForProcessingEvent` },
					limit: 50,
				});
				const match = events.data.find((e) => {
					const json = e.parsedJson as Record<string, unknown>;
					return (json.request_ids as string[])?.includes(parsed.request_id);
				});
				if (match) {
					status = 'processing';
					pendingId = (match.parsedJson as Record<string, unknown>).pending_id as string;
				}
			} catch { /* ok */ }

			// Check: signed (uses request_ids)
			try {
				const events = await client.queryEvents({
					query: { MoveEventType: `${pkg}::withdrawal_queue::WithdrawalSignedEvent` },
					limit: 50,
				});
				if (events.data.some((e) => (e.parsedJson as Record<string, unknown>).request_ids && ((e.parsedJson as Record<string, unknown>).request_ids as string[]).includes(parsed.request_id))) {
					status = 'signed';
				}
			} catch { /* ok */ }

			// Check: confirmed (uses pending_id, not request_ids)
			if (pendingId) {
				try {
					const events = await client.queryEvents({
						query: { MoveEventType: `${pkg}::withdrawal_queue::WithdrawalConfirmedEvent` },
						limit: 50,
					});
					if (events.data.some((e) => (e.parsedJson as Record<string, unknown>).pending_id === pendingId)) {
						status = 'confirmed';
					}
				} catch { /* ok */ }
			}

			return {
				requestId: parsed.request_id,
				btcAmount: (Number(parsed.btc_amount) / 1e8).toString(),
				bitcoinAddress: btcAddr,
				requesterAddress: parsed.requester_address,
				timestampMs: parsed.timestamp_ms,
				status,
				suiTxDigest: txDigest,
			};
		},
		enabled: !!txDigest && !!pkg,
		refetchInterval: (query) => {
			const data = query.state.data;
			if (data?.status === 'confirmed' || data?.status === 'cancelled') return false;
			return 15_000;
		},
	});
}
