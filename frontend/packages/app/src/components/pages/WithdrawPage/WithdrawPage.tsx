import { useState } from 'react';
import { useNavigate, useLocation, useParams } from 'react-router-dom';
import { Alert } from '@/components/atoms/Alert';
import { Button } from '@/components/atoms/Button';
import { Icon } from '@/components/atoms/Icon';
import { PageLayout } from '@/components/atoms/PageLayout';
import { PageTitle } from '@/components/atoms/PageTitle';
import { PageContent } from '@/components/atoms/PageContent';
import { ProgressBar } from '@/components/atoms/ProgressBar';
import { TransferSummary } from '@/components/molecules/TransferSummary';
import { TransferDetails } from '@/components/molecules/TransferDetails';
import { TransactionProgress } from '@/components/molecules/TransactionProgress';
import type { ProgressStep } from '@/components/molecules/TransactionProgress';
import { useWithdrawalByDigest } from '@/hooks/useWithdrawalByDigest';
import type { WithdrawalOnChainStatus } from '@/hooks/useWithdrawalByDigest';
import { useRequestWithdrawal } from '@/hooks/useRequestWithdrawal';
import { bitcoinAddressToWitnessProgram } from '@/lib/bitcoin';
import { truncateAddress, truncateHash } from '@/lib/utils';

type WithdrawStep =
	| 'review'
	| 'submitting'
	| 'preparing'
	| 'waiting'
	| 'finalizing'
	| 'completed';

const STEP_LABELS = [
	'Sui transaction confirming',
	'Hashi committee processing withdrawal',
	'Constructing transaction',
	'Bitcoin transaction being signed and broadcasted',
	'BTC sent to Bitcoin wallet',
];

export function WithdrawPage() {
	const navigate = useNavigate();
	const location = useLocation();
	const { txDigest } = useParams<{ txDigest: string }>();

	// -- On-chain status mode (has txDigest in URL) --
	const { data: onChainData, isLoading: isLoadingOnChain } = useWithdrawalByDigest(txDigest);

	if (txDigest) {
		return (
			<WithdrawStatusView
				data={onChainData}
				isLoading={isLoadingOnChain}
			/>
		);
	}

	// -- Fresh flow mode (from homepage form) --
	return <WithdrawFlowView entry={location.state} navigate={navigate} />;
}

// =============================================================================
// Status view — loaded from on-chain data via /withdraw/:txDigest
// =============================================================================

function mapOnChainStatusToStep(status: WithdrawalOnChainStatus): WithdrawStep {
	switch (status) {
		case 'requested': return 'submitting';
		case 'approved': return 'preparing';
		case 'processing': return 'preparing';
		case 'signed': return 'waiting';
		case 'confirmed': return 'completed';
		case 'cancelled': return 'completed'; // handled separately in render
		default: return 'submitting';
	}
}

function getProgressSteps(step: WithdrawStep, amount?: string): ProgressStep[] {
	const statusByPhase: Record<string, ProgressStep['status'][]> = {
		submitting: ['current', 'pending', 'pending', 'pending', 'pending'],
		preparing:  ['success', 'current', 'pending', 'pending', 'pending'],
		waiting:    ['success', 'success', 'success', 'success', 'current'],
		finalizing: ['success', 'success', 'success', 'success', 'success'],
		completed:  ['success', 'success', 'success', 'success', 'success'],
	};

	const statuses = statusByPhase[step] ?? ['pending', 'pending', 'pending', 'pending', 'pending'];

	return STEP_LABELS.map((label, i) => ({
		status: statuses[i],
		label,
		...(i === 4 && amount ? { amount, currency: 'BTC' } : {}),
	}));
}

function WithdrawStatusView({
	data,
	isLoading,
}: {
	data: ReturnType<typeof useWithdrawalByDigest>['data'];
	isLoading: boolean;
}) {
	const navigate = useNavigate();

	if (isLoading || !data) {
		return (
			<PageLayout>
				<PageTitle>Loading Withdrawal Status...</PageTitle>
				<PageContent>
					<ProgressBar message="Fetching transaction details..." className="max-w-120" />
				</PageContent>
			</PageLayout>
		);
	}

	const amount = data.btcAmount;
	const btcAddress = data.bitcoinAddress;
	const suiTxHash = data.suiTxDigest;
	const requester = data.requesterAddress;

	const handleCopyStatusLink = () => {
		navigator.clipboard.writeText(window.location.href);
	};

	if (data.status === 'cancelled') {
		return (
			<PageLayout>
				<PageTitle>Withdrawal Cancelled</PageTitle>
				<PageContent>
					<Alert variant="error">This withdrawal request has been cancelled.</Alert>
					<TransferSummary label="Cancelled Withdrawal" amount={amount} currency="suiBTC" />
					<Button onClick={() => navigate('/')}>Start a New Transfer</Button>
				</PageContent>
			</PageLayout>
		);
	}

	if (data.status === 'confirmed') {
		return (
			<PageLayout>
				<PageTitle>Withdraw Completed</PageTitle>
				<PageContent>
					<TransferSummary
						isCompleted
						label="In Bitcoin Wallet"
						amount={amount}
						currency="BTC"
					/>
					<TransferDetails
						rows={[
							{ label: 'From SUI Wallet', value: truncateAddress(requester), action: 'copy' },
							{ label: 'To Bitcoin Wallet', value: truncateAddress(btcAddress), action: 'copy' },
							{ label: 'SUI TXN hash', value: truncateHash(suiTxHash), action: 'external' as const },
						]}
						summary="Burnt"
						currency="suiBTC"
						amount={amount}
						usdValue=""
					/>
					<div className="flex flex-col gap-3">
						<Button onClick={() => navigate('/')}>Make Another Transfer</Button>
					</div>
				</PageContent>
			</PageLayout>
		);
	}

	// In-progress statuses: requested, approved, processing, signed
	const step = mapOnChainStatusToStep(data.status);
	const progressSteps = getProgressSteps(step, amount);

	const alertMessages: Partial<Record<WithdrawalOnChainStatus, string>> = {
		requested: 'Your withdrawal request has been submitted to the Sui network. Waiting for committee approval.',
		approved: 'The Hashi committee has approved your withdrawal and is preparing the Bitcoin transaction.',
		processing: 'Your Bitcoin transaction is being constructed by the committee.',
		signed: 'The Bitcoin transaction has been signed and broadcast. Waiting for confirmations.',
	};

	return (
		<PageLayout>
			<PageTitle>Withdrawal In Progress</PageTitle>
			<PageContent>
				<TransferSummary
					label="Withdrawing"
					amount={amount}
					currency="suiBTC"
					suiHash={truncateHash(suiTxHash)}
				/>
				<TransactionProgress
					steps={progressSteps}
					alert={alertMessages[data.status]}
				/>
				<div className="flex flex-col gap-3 text-center">
					<Button trailingIcon={<Icon name="Copy" />} variant="secondary" onClick={handleCopyStatusLink}>
						Copy Status Link
					</Button>
					<div className="mx-auto max-w-100 text-sm">
						Use this link to check the status of your transaction later. Closing the browser won't cancel the transaction.
					</div>
				</div>
			</PageContent>
		</PageLayout>
	);
}

// =============================================================================
// Fresh flow — step-based state machine for new withdrawals
// =============================================================================

function WithdrawFlowView({
	entry,
	navigate,
}: {
	entry: { amount: string; wallet: string; usdValue?: string } | null;
	navigate: ReturnType<typeof useNavigate>;
}) {
	const [step] = useState<WithdrawStep>('review');
	const [btcAddress, setBtcAddress] = useState('');
	const [submitError, setSubmitError] = useState('');
	const [isSubmitting, setIsSubmitting] = useState(false);
	const { mutateAsync: requestWithdrawal } = useRequestWithdrawal();
	const data = {
		amount: entry?.amount || '0',
		wallet: entry?.wallet || '',
		usdValue: entry?.usdValue || '',
	};

	const handleConfirmWithdraw = async () => {
		if (!btcAddress.trim()) {
			setSubmitError('Please enter a Bitcoin destination address.');
			return;
		}

		setSubmitError('');
		setIsSubmitting(true);

		try {
			const witnessProgram = bitcoinAddressToWitnessProgram(btcAddress.trim());
			const amountSats = BigInt(Math.round(parseFloat(data.amount) * 1e8));

			const result = await requestWithdrawal({
				amountSats,
				bitcoinAddress: witnessProgram,
			});

			// Navigate to status page with the tx digest
			navigate(`/withdraw/${result.digest}`);
		} catch (err) {
			setSubmitError(err instanceof Error ? err.message : 'Withdrawal failed');
		} finally {
			setIsSubmitting(false);
		}
	};

	if (step === 'review') {
		return (
			<PageLayout>
				<PageTitle>Review Transfer</PageTitle>
				<PageContent>
					<TransferSummary
						label="Withdrawing"
						amount={data.amount}
						currency="suiBTC"
						usdValue={data.usdValue}
					/>

					<label className="flex flex-col gap-2">
						<span className="font-book text-sm text-current/60">Bitcoin Destination Address</span>
						<input
							type="text"
							value={btcAddress}
							onChange={(e) => setBtcAddress(e.target.value)}
							placeholder="bc1q... or bcrt1p..."
							className="rounded-xs bg-black/16 px-4 py-3 font-mono text-sm text-white outline-none ring-1 ring-black/24 ring-inset placeholder:text-white/30 focus:ring-white/64"
						/>
					</label>

					<TransferDetails
						rows={[
							{ label: 'From Sui Wallet', value: data.wallet ? truncateAddress(data.wallet) : '—', action: 'copy', copyValue: data.wallet },
							{ label: 'To Bitcoin Wallet', value: btcAddress ? truncateAddress(btcAddress) : '—', action: 'copy', copyValue: btcAddress },
							{ label: 'Estimated Gas', value: '— SUI' },
							{ label: 'Hashi Protocol Fee', value: '— SUI' },
							{
								label: 'Estimated Time',
								tooltip: 'Bitcoin requires 6 confirmations for security. Each confirmation takes approximately 10 minutes.',
								value: '~60-80 min',
							},
						]}
						summary="Receives"
						amount={data.amount}
						currency="BTC"
						usdValue={data.usdValue}
					/>

					{submitError && <Alert variant="error">{submitError}</Alert>}

					<Alert>
						Your wallet will ask you to sign a transaction that burns {data.amount} suiBTC and submits a withdrawal request.
					</Alert>

					<div className="mt-4 flex flex-col gap-3 text-center">
						<Button disabled={!btcAddress.trim() || isSubmitting} onClick={handleConfirmWithdraw}>
							{isSubmitting ? 'Submitting...' : 'Confirm & Send'}
						</Button>
						<Button variant="secondary" onClick={() => navigate('/')}>Cancel</Button>
					</div>
				</PageContent>
			</PageLayout>
		);
	}

	// After successful submission, we navigate to /withdraw/:txDigest
	// which renders WithdrawStatusView. This fallback shouldn't be reached.
	return (
		<PageLayout>
			<PageTitle>Submitting Withdrawal...</PageTitle>
			<PageContent>
				<ProgressBar message="Submitting withdrawal request..." className="max-w-120" />
			</PageContent>
		</PageLayout>
	);
}
