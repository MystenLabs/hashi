import { useQuery } from '@tanstack/react-query';
import { useSuiClient } from '@mysten/dapp-kit';
import { CONFIG } from '@/lib/constants';

type ComponentStatus = 'pending' | 'confirming' | 'complete' | 'failed';

function mapWithdrawalStatus(status: string): ComponentStatus {
	switch (status) {
		case 'processing':
		case 'signed':
			return 'confirming';
		case 'confirmed':
			return 'complete';
		case 'cancelled':
			return 'failed';
		default:
			return 'pending';
	}
}

export function useTransactionStatus(
	id: string,
	direction: 'btc-to-sui' | 'sui-to-btc',
	enabled: boolean,
) {
	const client = useSuiClient();
	const pkg = CONFIG.HASHI_PACKAGE_ID;

	return useQuery({
		queryKey: ['tx-status', id, direction],
		queryFn: async (): Promise<ComponentStatus> => {
			if (!pkg) return 'pending';

			const tx = await client.getTransactionBlock({
				digest: id,
				options: { showEvents: true },
			});

			if (direction === 'btc-to-sui') {
				const depositEvent = tx.events?.find((e) =>
					e.type.includes('::deposit::DepositRequestedEvent'),
				);
				if (!depositEvent?.parsedJson) return 'pending';
				const requestId = (depositEvent.parsedJson as { request_id: string }).request_id;

				try {
					const confirmed = await client.queryEvents({
						query: { MoveEventType: `${pkg}::deposit::DepositConfirmedEvent` },
						limit: 50,
					});
					if (confirmed.data.some((e) => (e.parsedJson as { request_id: string })?.request_id === requestId)) {
						return 'complete';
					}
				} catch { /* ok */ }

				try {
					const expired = await client.queryEvents({
						query: { MoveEventType: `${pkg}::deposit::ExpiredDepositDeletedEvent` },
						limit: 50,
					});
					if (expired.data.some((e) => (e.parsedJson as { request_id: string })?.request_id === requestId)) {
						return 'failed';
					}
				} catch { /* ok */ }

				return 'pending';
			}

			// sui-to-btc (withdrawal)
			const withdrawEvent = tx.events?.find((e) =>
				e.type.includes('::withdrawal_queue::WithdrawalRequestedEvent'),
			);
			if (!withdrawEvent?.parsedJson) return 'pending';
			const requestId = (withdrawEvent.parsedJson as { request_id: string }).request_id;

			let status = 'requested';
			let pendingId: string | null = null;

			try {
				const events = await client.queryEvents({
					query: { MoveEventType: `${pkg}::withdrawal_queue::WithdrawalApprovedEvent` },
					limit: 50,
				});
				if (events.data.some((e) => (e.parsedJson as Record<string, unknown>).request_id === requestId)) {
					status = 'approved';
				}
			} catch { /* ok */ }

			try {
				const events = await client.queryEvents({
					query: { MoveEventType: `${pkg}::withdrawal_queue::WithdrawalCancelledEvent` },
					limit: 50,
				});
				if (events.data.some((e) => (e.parsedJson as Record<string, unknown>).request_id === requestId)) {
					status = 'cancelled';
				}
			} catch { /* ok */ }

			try {
				const events = await client.queryEvents({
					query: { MoveEventType: `${pkg}::withdrawal_queue::WithdrawalPickedForProcessingEvent` },
					limit: 50,
				});
				const match = events.data.find((e) => {
					const json = e.parsedJson as Record<string, unknown>;
					return (json.request_ids as string[])?.includes(requestId);
				});
				if (match) {
					status = 'processing';
					pendingId = (match.parsedJson as Record<string, unknown>).pending_id as string;
				}
			} catch { /* ok */ }

			try {
				const events = await client.queryEvents({
					query: { MoveEventType: `${pkg}::withdrawal_queue::WithdrawalSignedEvent` },
					limit: 50,
				});
				if (events.data.some((e) => ((e.parsedJson as Record<string, unknown>).request_ids as string[])?.includes(requestId))) {
					status = 'signed';
				}
			} catch { /* ok */ }

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

			return mapWithdrawalStatus(status);
		},
		enabled: enabled && !!pkg,
		refetchInterval: (query) => {
			const data = query.state.data;
			if (data === 'complete' || data === 'failed') return false;
			return 15_000;
		},
	});
}
