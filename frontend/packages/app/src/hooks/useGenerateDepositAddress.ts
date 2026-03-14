import { useQuery } from '@tanstack/react-query';
import { useSuiClient } from '@mysten/dapp-kit';
import { QueryKeys } from '@/lib/queryKeys';
import { CONFIG } from '@/lib/constants';
import { deriveDepositAddress, arkworksToCompressedHex } from '@/lib/bitcoin';

/**
 * Fetches the MPC public key from the Hashi object's CommitteeSet and derives
 * a Bitcoin deposit address for the given recipient Sui address.
 */
export function useGenerateDepositAddress(recipient: string | undefined) {
	const client = useSuiClient();
	const network = CONFIG.DEFAULT_NETWORK === 'mainnet' ? 'mainnet' : CONFIG.DEFAULT_NETWORK === 'localnet' ? 'regtest' : 'testnet';

	return useQuery({
		queryKey: [QueryKeys.DepositAddress, recipient],
		queryFn: async () => {
			if (!recipient || !CONFIG.HASHI_OBJECT_ID) return null;

			// Fetch the Hashi object to get the MPC public key
			const hashiObject = await client.getObject({
				id: CONFIG.HASHI_OBJECT_ID,
				options: { showContent: true },
			});

			const content = hashiObject.data?.content;
			if (!content || content.dataType !== 'moveObject') {
				throw new Error('Failed to fetch Hashi object');
			}

			// Extract mpc_public_key from the committee_set field
			// The Hashi object structure: { committee_set: { mpc_public_key: number[] }, ... }
			const fields = content.fields as Record<string, unknown>;
			const committeeSet = fields.committee_set as Record<string, unknown> | undefined;
			if (!committeeSet) {
				throw new Error('Hashi object missing committee_set');
			}

			const mpcKeyField = (committeeSet.fields as Record<string, unknown>)?.mpc_public_key;
			if (!mpcKeyField) {
				throw new Error('committee_set missing mpc_public_key');
			}

			// mpc_public_key is a 33-byte ark-works compressed secp256k1 point (LE x + flag byte)
			const mpcKeyBytes = mpcKeyField as number[];
			const mpcPubkeyHex = arkworksToCompressedHex(mpcKeyBytes);

			const address = deriveDepositAddress(mpcPubkeyHex, recipient, network);

			return {
				address,
				mpcPublicKey: new Uint8Array(mpcKeyBytes),
			};
		},
		enabled: !!recipient && !!CONFIG.HASHI_OBJECT_ID,
		staleTime: 5 * 60 * 1000, // MPC key doesn't change often
	});
}
