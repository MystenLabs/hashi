import { useState, useCallback, useEffect } from 'react';
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
				<PageTitle key="loading">Loading Deposit Status...</PageTitle>
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
				<PageTitle key="confirmed">Transfer Completed</PageTitle>
				<PageContent>
					<TransferSummary
						isCompleted
						label="In SUI Wallet"
						amount={amount}
						currency="hBTC"
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
						<Button variant="secondary">View in Sui Wallet</Button>
						<Button onClick={() => navigate('/')}>Make Another Transfer</Button>
					</div>
				</PageContent>
			</PageLayout>
		);
	}

	if (data.status === 'expired') {
		return (
			<PageLayout>
				<PageTitle key="expired">Deposit Expired</PageTitle>
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
			<PageTitle key="pending">Deposit In Progress</PageTitle>
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
					alert="This step is handled automatically. Bitcoin requires 6 confirmations (~60 min), then the Hashi committee will verify and mint hBTC."
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
	const [wallet] = useState(entry?.wallet || '');
	const [btcTxHash, setBtcTxHash] = useState('');
	const [confirmations] = useState(0);

	useEffect(() => {
		window.scrollTo({ top: 0, behavior: 'smooth' });
	}, [step]);

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

	const depositAddress = depositAddressData?.address ?? '';
	const isAddressIdle = fetchStatus === 'idle' && !depositAddressData;

	const handleCopyAddress = () => { if (depositAddress) copyAddress(depositAddress); };

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
		const amountSats = voutResolved?.amountSats ?? 0n;

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

	// -- Render by step --

	if (step === 'review') {
		return (
			<PageLayout>
				<PageTitle key="review">Deposit BTC</PageTitle>
				<PageContent>
					<div className="flex flex-col items-center gap-4">
						<div className="relative w-full self-start">
							<div className="group absolute left-0 top-1/2 -translate-y-1/2">
								<Icon
									name="Question"
									className="h-5 w-5 transition-colors group-hover:text-white/60"
								/>
								<div className="shadow-popover pointer-events-none absolute bottom-full left-0 mb-2 w-64 translate-y-1 scale-95 rounded-xs bg-black p-3 text-sm font-normal text-white opacity-0 ring-1 ring-white/24 transition ring-inset group-hover:translate-y-0 group-hover:scale-100 group-hover:opacity-100">
									This address is uniquely generated from your SUI wallet address. Only send BTC to this address from a personal wallet — deposits from exchanges are not supported.
								</div>
							</div>
							<h3 className="text-center text-xl font-bold">Deposit Address</h3>
						</div>
						{isLoadingAddress ? (
							<div className="flex h-40 w-40 items-center justify-center rounded-xs bg-white/10">
								<span className="animate-pulse-glow text-sm text-white/60">Generating...</span>
							</div>
						) : depositAddress ? (
							<QRCode value={depositAddress} size={160} className="mx-auto" />
						) : null}
						<div className="flex items-center gap-2 rounded-xs bg-black/16 px-4 py-2 ring-1 ring-black/24 ring-inset">
							<span className="font-mono text-sm break-all">
								{isLoadingAddress
									? 'Generating deposit address...'
									: addressError
										? 'Failed to generate address'
										: isAddressIdle
											? 'Hashi object not configured'
											: depositAddress}
							</span>
							{depositAddress && (
								<button
									type="button"
									aria-label={copiedAddress ? 'Copied' : 'Copy address'}
									className="ml-2 flex shrink-0 cursor-pointer items-center justify-center rounded-xs bg-white/12 p-1.5 transition-colors hover:bg-white/24"
									onClick={handleCopyAddress}
								>
									{copiedAddress
										? <Icon name="Check" className="h-4 w-4 text-valid" />
										: <Icon name="Copy" className="h-4 w-4" />}
								</button>
							)}
						</div>
					</div>
					<Alert>
						Send BTC to the address above from a personal wallet. Do NOT send from an exchange.
					</Alert>
					<TransferDetails
						rows={[
							{ action: 'copy', label: 'SUI Wallet Address', value: truncateAddress(wallet), copyValue: wallet },
							{ label: 'Sui Network Fee', value: fees?.gasEstimateSui ?? '~0.003 SUI' },
							{ label: 'Hashi Protocol Fee', value: fees?.depositFeeSats ?? '— sats' },
							{ label: 'Estimated Time', tooltip: 'Bitcoin requires 6 confirmations for security. Each confirmation takes approximately 10 minutes.', value: '~60-80 min' },
						]}
						hideSummary
					/>
					<div className="flex flex-col gap-3">
						<Button onClick={() => setStep('detecting')} disabled={!depositAddress}>I've Sent the BTC</Button>
						<Button variant="secondary" onClick={() => navigate('/')}>Cancel</Button>
					</div>
				</PageContent>
			</PageLayout>
		);
	}

	if (step === 'detecting') {
		return (
			<PageLayout>
				<PageTitle key="detecting">Submit Deposit Request</PageTitle>
				<PageContent>
					{submitError && <Alert variant="error">{submitError}</Alert>}
					{voutResolved && (
						<TransferSummary label="Depositing" amount={(Number(voutResolved.amountSats) / 1e8).toString()} currency="BTC" />
					)}
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
						<Button variant="secondary" onClick={() => { setSubmitError(''); setStep('review'); }}>Back</Button>
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
				<PageTitle key="progress">Bitcoin Transaction Detected</PageTitle>
				<PageContent>
					<TransferSummary label="Receiving" amount="—" currency="BTC" bitcoinHash={btcTxHash ? truncateHash(btcTxHash) : undefined} />
					<TransactionConfirmations steps={REQUIRED_CONFIRMATIONS} currentStep={confirmations} timeRemaining={timeRemaining} />
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
			<PageTitle key="completed">Transfer Completed</PageTitle>
			<PageContent>
				<TransferSummary isCompleted label="In SUI Wallet" amount="—" currency="hBTC" bitcoinHash={btcTxHash ? truncateHash(btcTxHash) : undefined} />
				<div className="flex flex-col gap-3">
					<Button onClick={() => navigate('/')}>Make Another Transfer</Button>
				</div>
			</PageContent>
		</PageLayout>
	);
}
