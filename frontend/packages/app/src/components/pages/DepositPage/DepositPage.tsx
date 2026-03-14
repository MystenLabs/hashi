import { useState, useCallback } from 'react';
import { useNavigate, useLocation, useParams } from 'react-router-dom';
import { Alert } from '@/components/atoms/Alert';
import { Button } from '@/components/atoms/Button';
import { Icon } from '@/components/atoms/Icon';
import { PageLayout } from '@/components/atoms/PageLayout';
import { PageTitle } from '@/components/atoms/PageTitle';
import { PageContent } from '@/components/atoms/PageContent';
import { ProgressBar } from '@/components/atoms/ProgressBar';
import { QRCode } from '@/components/atoms/QRCode/QRCode';
import { TransferSummary } from '@/components/molecules/TransferSummary';
import { TransferDetails } from '@/components/molecules/TransferDetails';
import { TransactionProgress } from '@/components/molecules/TransactionProgress';
import { TransactionConfirmations } from '@/components/molecules/TransactionConfirmations';
import { useGenerateDepositAddress } from '@/hooks/useGenerateDepositAddress';
import { useCreateDepositRequest } from '@/hooks/useCreateDepositRequest';
import { useDepositByDigest } from '@/hooks/useDepositByDigest';
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard';
import { lookupVout } from '@/lib/btc-rpc';
import { useDepositFees } from '@/hooks/useDepositFees';
import { truncateAddress, truncateHash } from '@/lib/utils';

type DepositStep =
	| 'review'
	| 'awaiting'
	| 'detecting'
	| 'progress'
	| 'finalizing'
	| 'completed';

const REQUIRED_CONFIRMATIONS = 6;

export function DepositPage() {
	const navigate = useNavigate();
	const location = useLocation();
	const { txDigest } = useParams<{ txDigest: string }>();

	// -- On-chain status mode (has txDigest in URL) --
	const { data: onChainData, isLoading: isLoadingOnChain } = useDepositByDigest(txDigest);

	if (txDigest) {
		return (
			<DepositStatusView
				data={onChainData}
				isLoading={isLoadingOnChain}
			/>
		);
	}

	// -- Fresh flow mode (from homepage form) --
	return <DepositFlowView entry={location.state} navigate={navigate} />;
}

// =============================================================================
// Status view — loaded from on-chain data via /deposit/:txDigest
// =============================================================================

function DepositStatusView({
	data,
	isLoading,
}: {
	data: ReturnType<typeof useDepositByDigest>['data'];
	isLoading: boolean;
}) {
	const navigate = useNavigate();

	if (isLoading || !data) {
		return (
			<PageLayout>
				<PageTitle>Loading Deposit Status...</PageTitle>
				<PageContent>
					<ProgressBar message="Fetching transaction details..." className="max-w-120" />
				</PageContent>
			</PageLayout>
		);
	}

	const amount = data.amount;
	const btcTxHash = data.btcTxid;
	const suiTxHash = data.suiTxDigest;
	const wallet = data.derivationPath || '';

	const handleCopyStatusLink = () => {
		navigator.clipboard.writeText(window.location.href);
	};

	if (data.status === 'confirmed') {
		return (
			<PageLayout>
				<PageTitle>Transfer Completed</PageTitle>
				<PageContent>
					<TransferSummary
						isCompleted
						label="In SUI Wallet"
						amount={amount}
						currency="suiBTC"
						bitcoinHash={truncateHash(btcTxHash)}
					/>
					<TransferDetails
						rows={[
							{ label: 'From Bitcoin', value: truncateHash(btcTxHash), copyValue: btcTxHash, action: 'copy' },
							...(wallet ? [{ label: 'To SUI Wallet', value: truncateAddress(wallet), copyValue: wallet, action: 'copy' as const }] : []),
							{ label: 'SUI TXN hash', value: truncateHash(suiTxHash), action: 'external' as const },
						]}
						summary="Received"
						currency="BTC"
						amount={amount}
						usdValue=""
					/>
					<div className="flex flex-col gap-3">
						<Button trailingIcon={<Icon name="ArrowUpRight" />}>View in Sui Wallet</Button>
						<Button variant="secondary" onClick={() => navigate('/')}>Make Another Transfer</Button>
					</div>
				</PageContent>
			</PageLayout>
		);
	}

	if (data.status === 'expired') {
		return (
			<PageLayout>
				<PageTitle>Deposit Expired</PageTitle>
				<PageContent>
					<Alert variant="error">
						This deposit request has expired. Deposit requests expire after 3 days.
					</Alert>
					<TransferSummary label="Expired Deposit" amount={amount} currency="BTC" bitcoinHash={truncateHash(btcTxHash)} />
					<Button onClick={() => navigate('/')}>Start a New Transfer</Button>
				</PageContent>
			</PageLayout>
		);
	}

	// status === 'pending' — still waiting for committee confirmation
	return (
		<PageLayout>
			<PageTitle>Deposit In Progress</PageTitle>
			<PageContent>
				<TransferSummary
					label="Receiving"
					amount={amount}
					currency="BTC"
					bitcoinHash={truncateHash(btcTxHash)}
				/>
				<TransactionProgress
					steps={[
						{ status: 'success', label: 'Deposit request submitted' },
						{ status: 'current', label: 'Waiting for Bitcoin confirmations & committee verification' },
					]}
					alert="This step is handled automatically. Bitcoin requires 6 confirmations (~60 min), then the Hashi committee will verify and mint suiBTC."
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
// Fresh flow — step-based state machine for new deposits
// =============================================================================

function DepositFlowView({
	entry,
	navigate,
}: {
	entry: { amount: string; wallet: string; usdValue?: string } | null;
	navigate: ReturnType<typeof useNavigate>;
}) {
	const [step, setStep] = useState<DepositStep>('review');
	const [amount] = useState(entry?.amount || '0');
	const [wallet] = useState(entry?.wallet || '');
	const [usdValue] = useState(entry?.usdValue || '');
	const [depositAddress, setDepositAddress] = useState('');
	const [btcTxHash, setBtcTxHash] = useState('');
	const [confirmations] = useState(0);

	const [txidInput, setTxidInput] = useState('');
	const [voutResolved, setVoutResolved] = useState<{ vout: number; amountSats: bigint } | null>(null);
	const [voutOverride, setVoutOverride] = useState('');
	const [showAdvanced, setShowAdvanced] = useState(false);
	const [isLookingUp, setIsLookingUp] = useState(false);
	const [lookupError, setLookupError] = useState('');
	const [submitError, setSubmitError] = useState('');
	const [isSubmitting, setIsSubmitting] = useState(false);

	const { data: depositAddressData, isLoading: isLoadingAddress, error: addressError, fetchStatus } =
		useGenerateDepositAddress(wallet);
	const { mutateAsync: createDeposit } = useCreateDepositRequest();
	const { data: fees } = useDepositFees();

	const generatedAddress = depositAddressData?.address ?? '';
	const isAddressIdle = fetchStatus === 'idle' && !depositAddressData;

	const handleConfirmReview = () => {
		setDepositAddress(generatedAddress);
		setStep('awaiting');
	};

	// Auto-lookup vout when txid changes (if Bitcoin RPC is available)
	const handleTxidChange = useCallback(async (txid: string) => {
		setTxidInput(txid);
		setVoutResolved(null);
		setLookupError('');

		const trimmed = txid.trim();
		if (!trimmed || trimmed.length < 64 || !depositAddress) return;

		setIsLookingUp(true);
		try {
			const result = await lookupVout(trimmed, depositAddress);
			if (result) {
				setVoutResolved(result);
			} else {
				setLookupError('No output found for the deposit address in this transaction.');
			}
		} catch (err) {
			console.warn('[vout-lookup] Failed:', err);
			// RPC not available or CORS blocked — user can manually enter vout via advanced
		} finally {
			setIsLookingUp(false);
		}
	}, [depositAddress]);

	const handleSubmitDeposit = async () => {
		if (!txidInput.trim()) {
			setSubmitError('Please enter the Bitcoin transaction ID.');
			return;
		}

		const vout = showAdvanced && voutOverride !== '' ? parseInt(voutOverride, 10) : voutResolved?.vout ?? 0;
		const amountSats = voutResolved?.amountSats ?? BigInt(Math.round(parseFloat(amount) * 1e8));

		setSubmitError('');
		setIsSubmitting(true);

		try {
			const result = await createDeposit({
				txid: txidInput.trim(),
				vout,
				amountSats,
				recipient: wallet,
				depositFeeMist: fees?.depositFeeMist,
			});

			setBtcTxHash(txidInput.trim());

			// Navigate to the persistent status URL
			navigate(`/deposit/${result.digest}`, { replace: true });
		} catch (err) {
			setSubmitError(err instanceof Error ? err.message : 'Failed to create deposit request.');
			setIsSubmitting(false);
		}
	};

	const { copied: copiedAddress, copy: copyAddress } = useCopyToClipboard();
	const { copied: copiedStatus, copy: copyStatus } = useCopyToClipboard();

	const handleCopyStatusLink = () => copyStatus(window.location.href);
	const handleCopyAddress = () => { if (depositAddress) copyAddress(depositAddress); };

	// -- Render by step --

	if (step === 'review') {
		return (
			<PageLayout>
				<PageTitle>Review Transfer</PageTitle>
				<PageContent>
					<TransferSummary label="To Send" amount={amount} currency="BTC" usdValue={usdValue} />
					<TransferDetails
						rows={[
							{ action: 'copy', label: 'SUI Wallet Address', value: truncateAddress(wallet), copyValue: wallet },
							{
								action: 'copy',
								alert: 'You will be sending BTC to this deposit address generated specifically for the Sui wallet address you entered. Do NOT send BTC from an exchange.',
								label: 'Deposit Address',
								copyValue: generatedAddress,
								value: isLoadingAddress
									? 'Generating...'
									: addressError
										? 'Failed to generate address'
										: isAddressIdle
											? 'Hashi object not configured'
											: truncateAddress(generatedAddress),
							},
							{ label: 'Estimated Gas', value: fees?.gasEstimateSui ?? '— SUI' },
							{ label: 'Hashi Protocol Fee', value: fees?.depositFeeSui ?? '— SUI' },
							{ label: 'Estimated Time', tooltip: 'Bitcoin requires 6 confirmations for security. Each confirmation takes approximately 10 minutes.', value: '~60-80 min' },
						]}
						amount={amount}
						currency="suiBTC"
						summary="Receives"
						usdValue={usdValue}
					/>
					<div className="mt-4 flex flex-col gap-3 text-center">
						<div className="text-sm">This action cannot be undone once submitted.</div>
						<Button onClick={handleConfirmReview} disabled={isLoadingAddress || !generatedAddress}>Confirm & Continue</Button>
						<Button variant="secondary" onClick={() => navigate('/')}>Cancel</Button>
					</div>
				</PageContent>
			</PageLayout>
		);
	}

	if (step === 'awaiting') {
		return (
			<PageLayout>
				<PageTitle>Send BTC to the deposit address</PageTitle>
				<PageContent>
					<div className="flex flex-col items-center gap-4">
						<QRCode value={depositAddress} size={160} className="mx-auto" />
						<div className="rounded-xs bg-black/16 px-4 py-2 font-mono text-lg break-all ring-1 ring-black/24 ring-inset">
							{depositAddress}
						</div>
						<Button
							trailingIcon={copiedAddress ? <Icon name="Check" className="text-valid" /> : <Icon name="Copy" />}
							variant="secondary"
							onClick={handleCopyAddress}
						>
							{copiedAddress ? 'Copied' : 'Copy Address'}
						</Button>
					</div>
					<div className="flex flex-col items-center justify-center gap-3 rounded-xs bg-black/16 p-4">
						<div className="flex items-center gap-2">
							<Icon name="BTC" className="h-5 w-5" />
							<div className="text-xl leading-none font-bold">{amount} BTC</div>
						</div>
						<Alert>
							Send exactly {amount} BTC to the address above from a personal wallet. Do NOT send from an exchange.
						</Alert>
					</div>
					<div className="flex flex-col gap-3">
						<Button onClick={() => setStep('detecting')}>I've Sent the BTC</Button>
						<Button variant="secondary" onClick={() => setStep('review')}>Back</Button>
					</div>
				</PageContent>
			</PageLayout>
		);
	}

	if (step === 'detecting') {
		return (
			<PageLayout>
				<PageTitle>Submit Deposit Request</PageTitle>
				<PageContent>
					{submitError && <Alert variant="error">{submitError}</Alert>}
					<TransferSummary label="Depositing" amount={amount} currency="BTC" />
					<div className="flex flex-col gap-4">
						<label className="flex flex-col gap-2">
							<span className="font-book text-sm text-current/60">Bitcoin Transaction ID (txid)</span>
							<input
								type="text"
								value={txidInput}
								onChange={(e) => handleTxidChange(e.target.value)}
								placeholder="Paste your Bitcoin transaction ID"
								className="rounded-xs bg-black/16 px-4 py-3 font-mono text-sm text-white outline-none ring-1 ring-black/24 ring-inset placeholder:text-white/30 focus:ring-white/64"
							/>
						</label>
						{isLookingUp && (
							<div className="font-book text-sm text-current/60">Looking up transaction...</div>
						)}
						{lookupError && (
							<Alert variant="error">{lookupError}</Alert>
						)}
						{voutResolved && (
							<div className="font-book flex items-center justify-between rounded-xs bg-black/16 px-4 py-3 text-sm">
								<span className="text-current/60">Output found</span>
								<span className="font-mono">vout: {voutResolved.vout}, {Number(voutResolved.amountSats) / 1e8} BTC</span>
							</div>
						)}
						{!voutResolved && !isLookingUp && (
							<button
								type="button"
								className="font-book self-start text-sm text-current/60 underline hover:no-underline"
								onClick={() => setShowAdvanced(!showAdvanced)}
							>
								{showAdvanced ? 'Hide advanced options' : 'Advanced options'}
							</button>
						)}
						{showAdvanced && !voutResolved && (
							<label className="flex flex-col gap-2">
								<span className="font-book text-sm text-current/60">Output Index (vout)</span>
								<input
									type="number"
									value={voutOverride}
									onChange={(e) => setVoutOverride(e.target.value)}
									placeholder="0"
									min="0"
									className="rounded-xs bg-black/16 px-4 py-3 font-mono text-sm text-white outline-none ring-1 ring-black/24 ring-inset placeholder:text-white/30 focus:ring-white/64"
								/>
							</label>
						)}
					</div>
					<Alert>
						This will submit a deposit request on Sui. Your connected wallet will be prompted to sign the transaction.
					</Alert>
					<div className="flex flex-col gap-3">
						<Button onClick={handleSubmitDeposit} disabled={isSubmitting || !txidInput.trim()}>
							{isSubmitting ? 'Submitting...' : 'Submit Deposit Request'}
						</Button>
						<Button variant="secondary" onClick={() => { setSubmitError(''); setStep('awaiting'); }}>Back</Button>
					</div>
				</PageContent>
			</PageLayout>
		);
	}

	// progress / finalizing / completed — these shouldn't be reached in fresh flow
	// (we navigate to /deposit/:txDigest after submission)
	// But handle gracefully in case of edge cases

	if (step === 'progress') {
		const estimatedMins = Math.max(0, (REQUIRED_CONFIRMATIONS - confirmations) * 10);
		const timeRemaining = confirmations >= REQUIRED_CONFIRMATIONS ? '0 min' : `~${estimatedMins} mins`;

		return (
			<PageLayout>
				<PageTitle>Bitcoin Transaction Detected</PageTitle>
				<PageContent>
					<TransferSummary label="Receiving" amount={amount} currency="BTC" usdValue={usdValue} bitcoinHash={btcTxHash ? truncateHash(btcTxHash) : undefined} />
					<TransactionConfirmations steps={REQUIRED_CONFIRMATIONS} currentStep={confirmations} timeRemaining={timeRemaining} btcReceiving={amount} />
					<div className="flex flex-col gap-3 text-center">
						<Button trailingIcon={copiedStatus ? <Icon name="Check" className="text-valid" /> : <Icon name="Copy" />} variant="secondary" onClick={handleCopyStatusLink}>{copiedStatus ? 'Copied' : 'Copy Status Link'}</Button>
						<div className="mx-auto max-w-100 text-sm">Use this link to check the status of your transaction later.</div>
					</div>
				</PageContent>
			</PageLayout>
		);
	}

	// fallback
	return (
		<PageLayout>
			<PageTitle>Transfer Completed</PageTitle>
			<PageContent>
				<TransferSummary isCompleted label="In SUI Wallet" amount={amount} currency="suiBTC" usdValue={usdValue} bitcoinHash={btcTxHash ? truncateHash(btcTxHash) : undefined} />
				<div className="flex flex-col gap-3">
					<Button onClick={() => navigate('/')}>Make Another Transfer</Button>
				</div>
			</PageContent>
		</PageLayout>
	);
}
