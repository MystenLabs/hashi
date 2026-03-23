use super::*;
use bitcoin::blockdata::script::witness_program::WitnessProgram;
use bitcoin::blockdata::script::witness_version::WitnessVersion;
use proptest::prelude::*;

// ── Test helpers ─────────────────────────────────────────────────────────

fn p2tr_recipient() -> Vec<u8> {
    vec![0x02u8; 32]
}

fn p2wpkh_recipient() -> Vec<u8> {
    vec![0x03u8; 20]
}

fn make_change_address() -> BitcoinAddress {
    let wp = WitnessProgram::new(WitnessVersion::V1, &[0x04u8; 32]).unwrap();
    let script = bitcoin::ScriptBuf::new_witness_program(&wp);
    BitcoinAddress::from_script(&script, bitcoin::Network::Bitcoin).unwrap()
}

fn make_p2wpkh_change_address() -> BitcoinAddress {
    let wp = WitnessProgram::new(WitnessVersion::V0, &[0x04u8; 20]).unwrap();
    let script = bitcoin::ScriptBuf::new_witness_program(&wp);
    BitcoinAddress::from_script(&script, bitcoin::Network::Bitcoin).unwrap()
}

fn make_utxo_id(n: u8) -> UtxoId {
    UtxoId {
        txid: Address::new([n; 32]),
        vout: 0,
    }
}

fn confirmed_utxo(n: u8, amount: u64) -> UtxoCandidate {
    UtxoCandidate {
        id: make_utxo_id(n),
        amount,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Confirmed,
    }
}

/// Creates a pending UTXO with one 0-confirmation ancestor (mempool
/// depth 1). The ancestor has weight 1000 WU and fee 500 sat.
fn pending_utxo(n: u8, amount: u64) -> UtxoCandidate {
    UtxoCandidate {
        id: make_utxo_id(n),
        amount,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Pending {
            chain: vec![AncestorTx {
                confirmations: 0,
                tx_weight: Weight::from_wu(1000),
                tx_fee: 500,
            }],
        },
    }
}

/// Creates a pending UTXO with `depth` 0-confirmation ancestors.
/// Each ancestor has weight 1000 WU and fee `fee_per_ancestor` sat.
fn pending_utxo_deep(
    n: u8,
    amount: u64,
    depth: usize,
    fee_per_ancestor: u64,
) -> UtxoCandidate {
    let chain = (0..depth)
        .map(|_| AncestorTx {
            confirmations: 0,
            tx_weight: Weight::from_wu(1000),
            tx_fee: fee_per_ancestor,
        })
        .collect();
    UtxoCandidate {
        id: make_utxo_id(n),
        amount,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Pending { chain },
    }
}

/// Creates a pending UTXO whose ancestors have mixed confirmations.
/// `ancestors` is a slice of (confirmations, weight_wu, fee) tuples.
fn pending_utxo_mixed(
    n: u8,
    amount: u64,
    ancestors: &[(u32, u64, u64)],
) -> UtxoCandidate {
    let chain = ancestors
        .iter()
        .map(|&(confirmations, weight_wu, fee)| AncestorTx {
            confirmations,
            tx_weight: Weight::from_wu(weight_wu),
            tx_fee: fee,
        })
        .collect();
    UtxoCandidate {
        id: make_utxo_id(n),
        amount,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Pending { chain },
    }
}

fn make_request(n: u8, amount: u64, timestamp_ms: u64) -> WithdrawalRequest {
    WithdrawalRequest {
        id: Address::new([n; 32]),
        recipient: p2tr_recipient(),
        amount,
        timestamp_ms,
    }
}

/// Params with generous limits for testing. Uses the standard defaults
/// but overrides `max_fee_per_request` to 500k sats to avoid the fee
/// cap being the binding constraint in most test scenarios.
fn default_params() -> CoinSelectionParams {
    CoinSelectionParams {
        max_fee_per_request: 500_000,
        ..CoinSelectionParams::new(make_change_address())
    }
}

fn default_fee_rate() -> FeeRate {
    FeeRate::from_sat_per_vb_unchecked(5)
}

/// Assert Bitcoin conservation: sum(inputs) == sum(recipients) + change + fee.
fn assert_conservation(result: &CoinSelectionResult) {
    let input_sum: u64 = result.inputs.iter().map(|u| u.amount).sum();
    let recipient_sum: u64 = result.withdrawal_outputs.iter().map(|o| o.amount).sum();
    let change = result.change.unwrap_or(0);
    assert_eq!(
        input_sum,
        recipient_sum + change + result.fee,
        "Bitcoin conservation violated: {input_sum} != \
         {recipient_sum} + {change} + {}",
        result.fee
    );
}

// ── Error path tests ──────────────────────────────────────────────────────

#[test]
fn test_empty_pool() {
    let result = select_coins(
        &[],
        &[make_request(1, 100_000, 0)],
        &default_params(),
        default_fee_rate(),
    );
    assert!(matches!(result, Err(CoinSelectionError::EmptyPool)));
}

#[test]
fn test_no_requests() {
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let result =
        select_coins(&utxos, &[], &default_params(), default_fee_rate());
    assert!(matches!(result, Err(CoinSelectionError::NoRequests)));
}

#[test]
fn test_zero_max_withdrawal_requests_returns_no_requests() {
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let requests = vec![make_request(1, 100_000, 0)];
    let params = CoinSelectionParams {
        max_withdrawal_requests: 0,
        ..default_params()
    };
    let result =
        select_coins(&utxos, &requests, &params, default_fee_rate());
    assert!(matches!(result, Err(CoinSelectionError::NoRequests)));
}

#[test]
fn test_insufficient_funds() {
    let utxos = vec![confirmed_utxo(1, 50_000)];
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    );
    assert!(matches!(
        result,
        Err(CoinSelectionError::InsufficientFunds {
            available: 50_000,
            required: 100_000
        })
    ));
}

#[test]
fn test_request_amount_too_small() {
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let req = WithdrawalRequest {
        id: Address::new([1; 32]),
        recipient: p2tr_recipient(),
        amount: 100, // far below any realistic fee + dust.
        timestamp_ms: 0,
    };
    let result =
        select_coins(&utxos, &[req], &default_params(), default_fee_rate());
    assert!(
        matches!(
            result,
            Err(CoinSelectionError::RequestAmountTooSmall {
                amount: 100,
                ..
            })
        ),
        "expected RequestAmountTooSmall, got {result:?}",
    );
}

#[test]
fn test_fee_exceeds_cap() {
    // A very small max_fee_per_request that cannot cover the
    // transaction's own fee should trigger FeeExceedsCap.
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let requests = vec![make_request(1, 100_000, 0)];
    let params = CoinSelectionParams {
        max_fee_per_request: 1,
        ..default_params()
    };
    let result =
        select_coins(&utxos, &requests, &params, default_fee_rate());
    assert!(
        matches!(result, Err(CoinSelectionError::FeeExceedsCap { .. })),
        "expected FeeExceedsCap, got {result:?}",
    );
}

// ── Happy path tests ──────────────────────────────────────────────────────

#[test]
fn test_single_request_basic() {
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");

    assert_eq!(result.inputs.len(), 1);
    assert_eq!(result.selected_requests.len(), 1);
    assert_eq!(result.withdrawal_outputs.len(), 1);
    assert!(result.fee > 0);
    assert!(result.withdrawal_outputs[0].amount < 100_000);
    assert_conservation(&result);
}

#[test]
fn test_multiple_requests_equal_fee_shares() {
    let utxos = vec![confirmed_utxo(1, 5_000_000)];
    let requests = vec![
        make_request(1, 100_000, 1000),
        make_request(2, 200_000, 2000),
        make_request(3, 300_000, 3000),
    ];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");

    assert_eq!(result.selected_requests.len(), 3);
    assert_eq!(result.withdrawal_outputs.len(), 3);
    assert_conservation(&result);

    // All requests pay equal fees.
    let fees: Vec<u64> = result
        .withdrawal_outputs
        .iter()
        .zip(&result.selected_requests)
        .map(|(o, r)| r.amount - o.amount)
        .collect();
    assert!(
        fees.windows(2).all(|w| w[0] == w[1]),
        "fees not equal: {fees:?}"
    );
}

#[test]
fn test_change_output_emitted_when_above_dust() {
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");

    assert!(result.change.is_some());
    assert!(result.change.unwrap() >= TR_DUST_RELAY_MIN_VALUE);
    assert_conservation(&result);
}

#[test]
fn test_exact_match_no_change() {
    let utxos = vec![confirmed_utxo(1, 100_000)];
    let requests = vec![make_request(1, 100_000, 0)];
    // Use a high fee rate to suppress consolidation so the exact
    // match is preserved.
    let high_fee = CoinSelectionParams::DEFAULT_HIGH_FEE_RATE_THRESHOLD;
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("should succeed");

    assert!(
        result.change.is_none(),
        "exact match should produce no change"
    );
    assert_conservation(&result);
}

#[test]
fn test_p2wpkh_recipient() {
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let req = WithdrawalRequest {
        id: Address::new([1; 32]),
        recipient: p2wpkh_recipient(),
        amount: 100_000,
        timestamp_ms: 0,
    };
    let result = select_coins(
        &utxos,
        &[req],
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");

    assert_conservation(&result);
    assert_eq!(result.withdrawal_outputs[0].recipient.len(), 20);

    // P2WPKH output is lighter (22-byte scriptPubKey vs 34-byte P2TR),
    // so the fee should be lower than an equivalent P2TR request.
    let p2tr_req = make_request(1, 100_000, 0);
    let p2tr_result = select_coins(
        &utxos,
        &[p2tr_req],
        &default_params(),
        default_fee_rate(),
    )
    .expect("P2TR should succeed");
    assert!(
        result.fee <= p2tr_result.fee,
        "P2WPKH fee {} should be <= P2TR fee {}",
        result.fee,
        p2tr_result.fee
    );
}

// ── CPFP tests ────────────────────────────────────────────────────────────

#[test]
fn test_cpfp_pending_utxo_increases_fee() {
    // A pending UTXO with a low-fee ancestor should cause the new
    // transaction to pay a CPFP deficit, increasing the total fee.
    let low_fee_ancestor = UtxoCandidate {
        id: make_utxo_id(1),
        amount: 5_000_000,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Pending {
            chain: vec![AncestorTx {
                confirmations: 0,
                tx_weight: Weight::from_wu(4000),
                tx_fee: 10, // very low fee ancestor
            }],
        },
    };

    let requests = vec![make_request(1, 100_000, 0)];
    let high_fee = CoinSelectionParams::DEFAULT_HIGH_FEE_RATE_THRESHOLD;

    let pending_result = select_coins(
        &[low_fee_ancestor],
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("pending should succeed");

    let confirmed_result = select_coins(
        &[confirmed_utxo(1, 5_000_000)],
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("confirmed should succeed");

    assert!(
        pending_result.fee > confirmed_result.fee,
        "CPFP should increase fee: pending={}, confirmed={}",
        pending_result.fee,
        confirmed_result.fee
    );
    assert_conservation(&pending_result);
    assert_conservation(&confirmed_result);
}

#[test]
fn test_cpfp_confirmed_utxo_zero_deficit() {
    // Confirmed UTXOs have no unconfirmed ancestors, so the CPFP
    // deficit should be zero and the fee should be purely weight-based.
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let requests = vec![make_request(1, 100_000, 0)];

    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");

    assert!(result.fee > 0);
    assert_conservation(&result);
}

#[test]
fn test_cpfp_multiple_pending_utxos_summed() {
    // Two pending UTXOs both selected as inputs. Their ancestor
    // weights and fees should be summed for CPFP deficit.
    let utxo1 = UtxoCandidate {
        id: make_utxo_id(1),
        amount: 200_000,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Pending {
            chain: vec![AncestorTx {
                confirmations: 0,
                tx_weight: Weight::from_wu(2000),
                tx_fee: 100, // underpaying
            }],
        },
    };
    let utxo2 = UtxoCandidate {
        id: make_utxo_id(2),
        amount: 200_000,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Pending {
            chain: vec![AncestorTx {
                confirmations: 0,
                tx_weight: Weight::from_wu(3000),
                tx_fee: 150, // also underpaying
            }],
        },
    };
    let requests = vec![make_request(1, 300_000, 0)];
    let high_fee = CoinSelectionParams::DEFAULT_HIGH_FEE_RATE_THRESHOLD;

    let result = select_coins(
        &[utxo1, utxo2],
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("should succeed with multiple pending inputs");

    assert_eq!(result.inputs.len(), 2);

    // Fee should be higher than a comparable confirmed-only tx.
    let confirmed_utxos = vec![
        confirmed_utxo(1, 200_000),
        confirmed_utxo(2, 200_000),
    ];
    let confirmed_result = select_coins(
        &confirmed_utxos,
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("confirmed should succeed");
    assert!(
        result.fee >= confirmed_result.fee,
        "CPFP fee {} should be >= confirmed-only fee {}",
        result.fee,
        confirmed_result.fee
    );
    assert_conservation(&result);
    assert_conservation(&confirmed_result);
}

#[test]
fn test_all_utxos_pending_no_consolidation() {
    // Every UTXO is pending. Consolidation should not add any extras
    // (only confirmed UTXOs are eligible for consolidation).
    let utxos = vec![
        pending_utxo(1, 500_000),
        pending_utxo(2, 300_000),
    ];
    let requests = vec![make_request(1, 100_000, 0)];
    // Low fee rate would normally trigger consolidation.
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        FeeRate::from_sat_per_vb_unchecked(1),
    )
    .expect("should succeed with all-pending pool");

    // Only the largest UTXO needed.
    assert_eq!(result.inputs.len(), 1);
    assert_eq!(result.inputs[0].amount, 500_000);
    assert_conservation(&result);
}

// ── Consolidation tests ──────────────────────────────────────────────────

#[test]
fn test_low_fee_consolidation_active_smallest_first() {
    // Below long-term rate: consolidation up to `input_budget * N`.
    let utxos = vec![
        confirmed_utxo(1, 5_000_000), // covers request
        confirmed_utxo(2, 5_000),
        confirmed_utxo(3, 10_000),
        confirmed_utxo(4, 20_000),
        confirmed_utxo(5, 50_000),
        confirmed_utxo(6, 100_000),
    ];
    let requests = vec![make_request(1, 200_000, 0)];

    let low_fee = FeeRate::from_sat_per_vb_unchecked(1);
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        low_fee,
    )
    .expect("should succeed");

    // Should consolidate extra confirmed UTXOs.
    assert!(
        result.inputs.len() > 1,
        "expected consolidation inputs at low fee rate"
    );

    // Consolidation picks smallest first.
    let extra_amounts: Vec<u64> = result
        .inputs
        .iter()
        .filter(|u| u.amount != 5_000_000)
        .map(|u| u.amount)
        .collect();
    if extra_amounts.len() >= 2 {
        assert!(
            extra_amounts.contains(&5_000),
            "smallest UTXOs should be consolidated first: {extra_amounts:?}"
        );
        assert!(
            extra_amounts.contains(&10_000),
            "second-smallest should be consolidated: {extra_amounts:?}"
        );
    }
    assert_conservation(&result);
}

#[test]
fn test_moderate_fee_limited_consolidation() {
    // Between long-term (10 sat/vb) and high (30 sat/vb):
    // max consolidation = input_budget * N / 2.
    // With default input_budget=10 and 1 request: 10 * 1 / 2 = 5.
    let utxos: Vec<UtxoCandidate> = (0u8..30)
        .map(|i| confirmed_utxo(i, 100_000))
        .collect();
    let requests = vec![make_request(1, 50_000, 0)];

    let moderate_fee = FeeRate::from_sat_per_vb_unchecked(15);
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        moderate_fee,
    )
    .expect("should succeed");

    let min_inputs = 1usize;
    let extras = result.inputs.len() - min_inputs;
    // input_budget(10) * 1 / 2 = 5.
    assert!(
        extras <= 5,
        "moderate consolidation should cap at input_budget*N/2 = 5; \
         got {extras} extras"
    );
    assert_conservation(&result);
}

#[test]
fn test_high_fee_no_consolidation() {
    // At or above high_fee_rate_threshold, no consolidation.
    let utxos: Vec<UtxoCandidate> = (0u8..20)
        .map(|i| confirmed_utxo(i, 100_000))
        .collect();
    let requests = vec![make_request(1, 50_000, 0)];

    let high_fee = CoinSelectionParams::DEFAULT_HIGH_FEE_RATE_THRESHOLD;
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("should succeed");

    assert_eq!(
        result.inputs.len(),
        1,
        "no consolidation at high fee rate; got {} inputs",
        result.inputs.len()
    );
    assert_conservation(&result);
}

#[test]
fn test_no_consolidation_when_raw_change_zero() {
    // When input_total == total_requested (exact match), raw_change
    // is 0 and consolidation should not run even at low fee rates.
    let utxos = vec![
        confirmed_utxo(1, 100_000), // exactly covers request
        confirmed_utxo(2, 5_000),   // would be consolidation candidate
        confirmed_utxo(3, 10_000),  // would be consolidation candidate
    ];
    let requests = vec![make_request(1, 100_000, 0)];

    let low_fee = FeeRate::from_sat_per_vb_unchecked(1);
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        low_fee,
    )
    .expect("should succeed");

    // select_coins only consolidates when raw_change > 0.
    assert_eq!(
        result.inputs.len(),
        1,
        "no consolidation when raw_change == 0; got {} inputs",
        result.inputs.len()
    );
    assert_conservation(&result);
}

#[test]
fn test_consolidation_only_confirmed_utxos() {
    // Consolidation should only pull in confirmed UTXOs, never pending.
    let utxos = vec![
        confirmed_utxo(1, 1_000_000), // covers request
        pending_utxo(2, 5_000),       // pending, should not be consolidated
        confirmed_utxo(3, 10_000),    // confirmed, eligible for consolidation
    ];
    let requests = vec![make_request(1, 200_000, 0)];

    let low_fee = FeeRate::from_sat_per_vb_unchecked(1);
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        low_fee,
    )
    .expect("should succeed");

    // All extra inputs (beyond the first) must be confirmed.
    for input in &result.inputs {
        if input.amount != 1_000_000 {
            assert!(
                matches!(input.status, UtxoStatus::Confirmed),
                "consolidation should only add confirmed UTXOs, \
                 got pending UTXO with amount {}",
                input.amount
            );
        }
    }
    assert_conservation(&result);
}

// ── Chain depth tests ─────────────────────────────────────────────────────

#[test]
fn test_utxo_at_max_mempool_chain_depth_eligible() {
    // A UTXO at exactly max_mempool_chain_depth should be eligible.
    let utxos = vec![pending_utxo_deep(1, 1_000_000, 5, 500)];
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("UTXO at exactly max depth should be eligible");
    assert_conservation(&result);
}

#[test]
fn test_utxo_exceeding_max_mempool_chain_depth_excluded() {
    // A UTXO one over the limit should be excluded.
    let utxos = vec![pending_utxo_deep(1, 1_000_000, 6, 500)];
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    );
    assert!(matches!(
        result,
        Err(CoinSelectionError::InsufficientFunds { .. })
    ));
}

#[test]
fn test_max_mempool_chain_depth_zero_excludes_all_pending() {
    let confirmed = confirmed_utxo(1, 1_000_000);
    let shallow_pending = pending_utxo(2, 2_000_000); // mempool depth 1

    let requests = vec![make_request(1, 100_000, 0)];
    let params = CoinSelectionParams {
        max_mempool_chain_depth: 0,
        ..default_params()
    };

    // Only the confirmed UTXO is eligible.
    let result = select_coins(
        &[confirmed, shallow_pending],
        &requests,
        &params,
        default_fee_rate(),
    )
    .expect("should succeed with confirmed UTXO");
    assert_eq!(result.inputs[0].amount, 1_000_000);
    assert_conservation(&result);
}

// ── Change/dust tests ─────────────────────────────────────────────────────

#[test]
fn test_sub_dust_change_padded_to_dust_threshold() {
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let requests = vec![make_request(1, 999_700, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");

    assert_eq!(
        result.change,
        Some(TR_DUST_RELAY_MIN_VALUE),
        "sub-dust change must be padded to dust threshold"
    );
    assert_conservation(&result);
}

#[test]
fn test_one_sat_change_padded_to_dust() {
    let utxos = vec![confirmed_utxo(1, 100_001)];
    let requests = vec![make_request(1, 100_000, 0)];
    // Use high fee rate to suppress consolidation.
    let high_fee = CoinSelectionParams::DEFAULT_HIGH_FEE_RATE_THRESHOLD;
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("should succeed");

    assert_eq!(
        result.change,
        Some(TR_DUST_RELAY_MIN_VALUE),
        "even 1 sat of change must be padded to dust threshold"
    );
    assert_conservation(&result);
}

#[test]
fn test_dust_padding_cost_deducted_from_requests() {
    // When change is sub-dust, the padding cost should come from
    // requests (increasing their fee deduction).
    let utxos = vec![confirmed_utxo(1, 100_001)];
    let requests = vec![make_request(1, 100_000, 0)];
    let high_fee = CoinSelectionParams::DEFAULT_HIGH_FEE_RATE_THRESHOLD;

    let padded_result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("padded should succeed");

    // Compare with an exact match that has no dust padding.
    let exact_utxos = vec![confirmed_utxo(1, 100_000)];
    let exact_result = select_coins(
        &exact_utxos,
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("exact should succeed");

    // The padded result's fee should be higher because it includes
    // dust padding cost (plus the additional weight for the change
    // output).
    assert!(
        padded_result.fee > exact_result.fee,
        "padded fee {} should be > exact fee {} due to dust padding + change weight",
        padded_result.fee,
        exact_result.fee
    );
    assert_conservation(&padded_result);
    assert_conservation(&exact_result);
}

// ── Request ordering tests ────────────────────────────────────────────────

#[test]
fn test_oldest_requests_selected_first() {
    let utxos = vec![confirmed_utxo(1, 10_000_000)];
    let requests = vec![
        make_request(1, 100_000, 3000), // newest
        make_request(2, 100_000, 1000), // oldest
        make_request(3, 100_000, 2000), // middle
    ];
    let params = CoinSelectionParams {
        max_withdrawal_requests: 2,
        ..default_params()
    };
    let result = select_coins(
        &utxos,
        &requests,
        &params,
        default_fee_rate(),
    )
    .expect("should succeed");

    let timestamps: std::collections::BTreeSet<u64> = result
        .selected_requests
        .iter()
        .map(|r| r.timestamp_ms)
        .collect();
    assert!(timestamps.contains(&1000));
    assert!(timestamps.contains(&2000));
    assert!(!timestamps.contains(&3000));
}

#[test]
fn test_max_withdrawal_requests_respected() {
    let utxos = vec![confirmed_utxo(1, 10_000_000)];
    let requests: Vec<WithdrawalRequest> = (0u8..8)
        .map(|i| make_request(i, 100_000, i as u64 * 1000))
        .collect();
    let params = CoinSelectionParams {
        max_withdrawal_requests: 3,
        ..default_params()
    };
    let result = select_coins(
        &utxos,
        &requests,
        &params,
        default_fee_rate(),
    )
    .expect("should succeed");

    assert_eq!(result.selected_requests.len(), 3);
    assert_conservation(&result);
}

// ── Fee rate clamping tests ───────────────────────────────────────────────

#[test]
fn test_fee_rate_below_min_clamped_up() {
    let utxos = vec![confirmed_utxo(1, 2_000_000)];
    let requests = vec![make_request(1, 500_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        FeeRate::ZERO,
    )
    .expect("should succeed at zero fee rate (clamped to min)");

    // Fee is nonzero because the rate is clamped to 1 sat/vb.
    assert!(result.fee > 0, "fee should be nonzero after clamping");
    assert_conservation(&result);
}

// ── Property-based tests (test_strategy) ────────────────────────────────

fn arb_confirmed_utxo() -> impl Strategy<Value = UtxoCandidate> {
    (1u8..=200u8, 1_000u64..10_000_000u64)
        .prop_map(|(id, amount)| confirmed_utxo(id, amount))
}

fn arb_pending_utxo() -> impl Strategy<Value = UtxoCandidate> {
    (
        1u8..=200u8,
        1_000u64..1_000_000u64,
        1usize..=5usize,
        100u64..2_000u64,
    )
        .prop_map(|(id, amount, depth, fee_per_ancestor)| {
            let chain = (0..depth)
                .map(|_| AncestorTx {
                    confirmations: 0,
                    tx_weight: Weight::from_wu(1000),
                    tx_fee: fee_per_ancestor,
                })
                .collect();
            UtxoCandidate {
                id: make_utxo_id(id),
                amount,
                spend_path: SpendPath::TaprootScriptPath2of2,
                status: UtxoStatus::Pending { chain },
            }
        })
}

fn arb_utxo() -> impl Strategy<Value = UtxoCandidate> {
    prop_oneof![arb_confirmed_utxo(), arb_pending_utxo()]
}

fn arb_withdrawal_request() -> impl Strategy<Value = WithdrawalRequest> {
    (1u8..=200u8, 100_000u64..500_000u64, 0u64..1_000_000u64)
        .prop_map(|(id, amount, ts)| WithdrawalRequest {
            id: Address::new([id; 32]),
            recipient: p2tr_recipient(),
            amount,
            timestamp_ms: ts,
        })
}

/// Fee rate strategy covering all three consolidation tiers:
/// 1-9 sat/vB (low, below long-term 10), 10-29 (moderate),
/// 30-35 (high, at or above threshold 30).
fn arb_fee_rate() -> impl Strategy<Value = FeeRate> {
    (1u64..=35u64).prop_map(FeeRate::from_sat_per_vb_unchecked)
}

use test_strategy::proptest;

/// Conservation: sum(inputs) == sum(outputs) + change + fee.
#[proptest]
fn prop_conservation(
    #[strategy(prop::collection::vec(arb_utxo(), 1..=15))]
    utxos: Vec<UtxoCandidate>,
    #[strategy(prop::collection::vec(arb_withdrawal_request(), 1..=5))]
    requests: Vec<WithdrawalRequest>,
    #[strategy(arb_fee_rate())] fee_rate: FeeRate,
) {
    if let Ok(r) =
        select_coins(&utxos, &requests, &default_params(), fee_rate)
    {
        let input_sum: u64 = r.inputs.iter().map(|u| u.amount).sum();
        let recipient_sum: u64 =
            r.withdrawal_outputs.iter().map(|o| o.amount).sum();
        let change = r.change.unwrap_or(0);
        assert_eq!(
            input_sum,
            recipient_sum + change + r.fee,
            "conservation violated"
        );
    }
}

/// Fee shares are equal across all requests.
#[proptest]
fn prop_equal_fee_shares(
    #[strategy(prop::collection::vec(arb_confirmed_utxo(), 2..=10))]
    utxos: Vec<UtxoCandidate>,
    #[strategy(prop::collection::vec(arb_withdrawal_request(), 2..=4))]
    requests: Vec<WithdrawalRequest>,
    #[strategy(arb_fee_rate())] fee_rate: FeeRate,
) {
    if let Ok(r) =
        select_coins(&utxos, &requests, &default_params(), fee_rate)
    {
        let shares: Vec<u64> = r
            .selected_requests
            .iter()
            .zip(&r.withdrawal_outputs)
            .map(|(req, out)| req.amount - out.amount)
            .collect();
        if shares.len() > 1 {
            let first = shares[0];
            for s in &shares[1..] {
                assert_eq!(*s, first, "fee shares not equal: {shares:?}");
            }
        }
    }
}

/// Change output, when present, is at or above the dust threshold.
#[proptest]
fn prop_change_above_dust(
    #[strategy(prop::collection::vec(arb_confirmed_utxo(), 1..=10))]
    utxos: Vec<UtxoCandidate>,
    #[strategy(prop::collection::vec(arb_withdrawal_request(), 1..=5))]
    requests: Vec<WithdrawalRequest>,
    #[strategy(arb_fee_rate())] fee_rate: FeeRate,
) {
    if let Ok(r) =
        select_coins(&utxos, &requests, &default_params(), fee_rate)
        && let Some(change) = r.change
    {
        assert!(
            change >= TR_DUST_RELAY_MIN_VALUE,
            "change {change} below dust threshold \
             {TR_DUST_RELAY_MIN_VALUE}"
        );
    }
}

/// Low fee rate consolidates at least as many inputs as high fee rate.
#[proptest]
fn prop_low_fee_consolidates_more_or_equal(
    #[strategy(prop::collection::vec(arb_confirmed_utxo(), 5..=15))]
    utxos: Vec<UtxoCandidate>,
    #[strategy(prop::collection::vec(arb_withdrawal_request(), 1..=2))]
    requests: Vec<WithdrawalRequest>,
) {
    let low = FeeRate::from_sat_per_vb_unchecked(1);
    let high = FeeRate::from_sat_per_vb_unchecked(30);

    let low_r =
        select_coins(&utxos, &requests, &default_params(), low);
    let high_r =
        select_coins(&utxos, &requests, &default_params(), high);

    if let (Ok(l), Ok(h)) = (low_r, high_r) {
        assert!(
            l.inputs.len() >= h.inputs.len(),
            "low-fee used fewer inputs ({}) than high-fee ({})",
            l.inputs.len(),
            h.inputs.len()
        );
    }
}

/// Fee per request never exceeds the configured cap.
#[proptest]
fn prop_fee_per_request_never_exceeds_cap(
    #[strategy(prop::collection::vec(arb_confirmed_utxo(), 1..=15))]
    utxos: Vec<UtxoCandidate>,
    #[strategy(prop::collection::vec(arb_withdrawal_request(), 1..=5))]
    requests: Vec<WithdrawalRequest>,
    #[strategy(arb_fee_rate())] fee_rate: FeeRate,
) {
    let params = default_params();
    if let Ok(r) = select_coins(&utxos, &requests, &params, fee_rate) {
        let n = r.selected_requests.len() as u64;
        let total_fee_from_requests: u64 = r
            .selected_requests
            .iter()
            .zip(&r.withdrawal_outputs)
            .map(|(req, out)| req.amount - out.amount)
            .sum();
        let fee_per_request = total_fee_from_requests / n;
        assert!(
            fee_per_request <= params.max_fee_per_request,
            "fee_per_request {fee_per_request} > cap {}",
            params.max_fee_per_request
        );
    }
}

/// All selected inputs pass the chain depth filter.
#[proptest]
fn prop_inputs_pass_chain_depth_filter(
    #[strategy(prop::collection::vec(arb_utxo(), 1..=15))]
    utxos: Vec<UtxoCandidate>,
    #[strategy(prop::collection::vec(arb_withdrawal_request(), 1..=3))]
    requests: Vec<WithdrawalRequest>,
    #[strategy(arb_fee_rate())] fee_rate: FeeRate,
) {
    let params = default_params();
    if let Ok(r) = select_coins(&utxos, &requests, &params, fee_rate) {
        for input in &r.inputs {
            assert!(
                input.status.mempool_chain_depth()
                    <= params.max_mempool_chain_depth,
                "input exceeds max_mempool_chain_depth"
            );
        }
    }
}

/// The selected requests are a subset of the input requests, and all
/// outputs cover their request amount after fee deduction.
#[proptest]
fn prop_outputs_cover_request_minus_fee(
    #[strategy(prop::collection::vec(arb_confirmed_utxo(), 1..=10))]
    utxos: Vec<UtxoCandidate>,
    #[strategy(prop::collection::vec(arb_withdrawal_request(), 1..=5))]
    requests: Vec<WithdrawalRequest>,
    #[strategy(arb_fee_rate())] fee_rate: FeeRate,
) {
    if let Ok(r) =
        select_coins(&utxos, &requests, &default_params(), fee_rate)
    {
        assert_eq!(r.selected_requests.len(), r.withdrawal_outputs.len());
        for (req, out) in
            r.selected_requests.iter().zip(&r.withdrawal_outputs)
        {
            assert_eq!(req.id, out.request_id);
            assert!(out.amount <= req.amount, "output exceeds request amount");
            assert!(
                out.amount > 0,
                "output amount is zero for request {:?}",
                req.id
            );
        }
    }
}

/// sum(inputs) >= sum(selected request amounts).
#[proptest]
fn prop_inputs_cover_request_amounts(
    #[strategy(prop::collection::vec(arb_confirmed_utxo(), 1..=10))]
    utxos: Vec<UtxoCandidate>,
    #[strategy(prop::collection::vec(arb_withdrawal_request(), 1..=5))]
    requests: Vec<WithdrawalRequest>,
    #[strategy(arb_fee_rate())] fee_rate: FeeRate,
) {
    if let Ok(r) =
        select_coins(&utxos, &requests, &default_params(), fee_rate)
    {
        let input_sum: u64 = r.inputs.iter().map(|u| u.amount).sum();
        let request_sum: u64 =
            r.selected_requests.iter().map(|req| req.amount).sum();
        assert!(
            input_sum >= request_sum,
            "inputs {input_sum} < requested {request_sum}"
        );
    }
}

// ── Error path tests (extended) ───────────────────────────────────────────

#[test]
fn test_insufficient_funds_available_reflects_eligible_pool() {
    // Two UTXOs, but one is too deep in the mempool chain. The
    // `available` field in the error should reflect only the eligible
    // (filtered) pool, not the total.
    let utxos = vec![
        confirmed_utxo(1, 50_000),
        pending_utxo_deep(2, 200_000, 10, 500), // depth 10 > default 5
    ];
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    );
    assert!(matches!(
        result,
        Err(CoinSelectionError::InsufficientFunds {
            available: 50_000,
            required: 100_000
        })
    ));
}

// ── Change address dust threshold tests ──────────────────────────────────

#[test]
fn test_p2wpkh_change_address_dust_threshold() {
    // P2WPKH change address has a lower dust threshold (294 sat) than
    // P2TR (330 sat). A raw change of 310 sat is above P2WPKH dust but
    // below P2TR dust, so the two should behave differently.
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let requests = vec![make_request(1, 999_690, 0)]; // raw_change = 310

    let p2wpkh_params = CoinSelectionParams {
        change_address: make_p2wpkh_change_address(),
        max_fee_per_request: 500_000,
        ..CoinSelectionParams::new(make_p2wpkh_change_address())
    };
    let p2tr_params = default_params();

    let p2wpkh_result = select_coins(
        &utxos,
        &requests,
        &p2wpkh_params,
        default_fee_rate(),
    )
    .expect("P2WPKH should succeed");
    let p2tr_result = select_coins(
        &utxos,
        &requests,
        &p2tr_params,
        default_fee_rate(),
    )
    .expect("P2TR should succeed");

    assert_eq!(
        p2wpkh_result.change,
        Some(310),
        "310 sat >= P2WPKH dust (294): change emitted at raw value"
    );
    assert_eq!(
        p2tr_result.change,
        Some(330),
        "310 sat < P2TR dust (330): change padded to dust threshold"
    );
    assert_conservation(&p2wpkh_result);
    assert_conservation(&p2tr_result);
}

// ── Input selection tests ─────────────────────────────────────────────────

#[test]
fn test_fund_balance_decreases_by_exactly_request_amounts() {
    // The fund balance decreases by exactly sum(request.amounts),
    // not by request amounts plus fees (fees come from the requests).
    let utxos = vec![confirmed_utxo(1, 2_000_000)];
    let requests = vec![
        make_request(1, 300_000, 1000),
        make_request(2, 400_000, 2000),
    ];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");

    let total_selected: u64 =
        result.selected_requests.iter().map(|r| r.amount).sum();
    let input_sum: u64 = result.inputs.iter().map(|u| u.amount).sum();
    let change = result.change.unwrap_or(0);

    assert_eq!(
        input_sum - change,
        total_selected,
        "fund balance did not decrease by exactly the selected \
         request amounts"
    );
    assert_conservation(&result);
}

#[test]
fn test_largest_first_input_selection() {
    let utxos = vec![
        confirmed_utxo(1, 100_000),
        confirmed_utxo(2, 500_000),
        confirmed_utxo(3, 200_000),
    ];
    let requests = vec![make_request(1, 150_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");

    // The 500k UTXO (largest) should be selected first.
    assert_eq!(result.inputs[0].amount, 500_000);
    assert_conservation(&result);
}

#[test]
fn test_multiple_inputs_needed_largest_first() {
    let utxos: Vec<UtxoCandidate> = (0u8..10)
        .map(|i| confirmed_utxo(i, 50_000))
        .collect();
    let requests = vec![make_request(1, 300_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");

    assert!(
        result.inputs.len() >= 6,
        "need at least 6 x 50k to cover 300k"
    );
    assert_conservation(&result);
}

#[test]
fn test_deterministic_tiebreak_by_id() {
    // Two UTXOs of equal value: the one with the smaller ID should
    // appear first (deterministic tiebreak). High fee suppresses
    // consolidation so only one input is selected.
    let utxos = vec![
        confirmed_utxo(5, 1_000_000),
        confirmed_utxo(2, 1_000_000),
    ];
    let requests = vec![make_request(1, 500_000, 0)];
    let high_fee = CoinSelectionParams::DEFAULT_HIGH_FEE_RATE_THRESHOLD;
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("should succeed");

    assert_eq!(result.inputs.len(), 1);
    assert_eq!(
        result.inputs[0].id.txid,
        Address::new([2; 32]),
        "tiebreak should prefer the smaller ID"
    );
    assert_conservation(&result);
}

// ── Pending UTXO selection tests ──────────────────────────────────────────

#[test]
fn test_pending_utxos_eligible_as_inputs() {
    // Pending UTXOs are eligible; largest-first picks the pending one
    // when it is the biggest. High fee suppresses consolidation.
    let utxos = vec![
        pending_utxo(1, 5_000_000),
        confirmed_utxo(2, 200_000),
    ];
    let requests = vec![make_request(1, 1_000_000, 0)];
    let high_fee = CoinSelectionParams::DEFAULT_HIGH_FEE_RATE_THRESHOLD;
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        high_fee,
    )
    .expect("should succeed");

    assert_eq!(result.inputs.len(), 1);
    assert_eq!(result.inputs[0].amount, 5_000_000);
    assert!(matches!(
        result.inputs[0].status,
        UtxoStatus::Pending { .. }
    ));
    assert_conservation(&result);
}

#[test]
fn test_pending_utxo_with_confirmed_ancestors_eligible() {
    // A pending UTXO whose entire ancestor chain has 1+ confirmations
    // has mempool_chain_depth == 0, so it passes even when
    // max_mempool_chain_depth = 0.
    let utxo = pending_utxo_mixed(
        1,
        1_000_000,
        &[(1, 1000, 500), (2, 1000, 500)], // all confirmed ancestors
    );
    assert_eq!(utxo.status.mempool_chain_depth(), 0);

    let requests = vec![make_request(1, 100_000, 0)];
    let params = CoinSelectionParams {
        max_mempool_chain_depth: 0,
        ..default_params()
    };
    let result =
        select_coins(&[utxo], &requests, &params, default_fee_rate())
            .expect("should succeed even with max_mempool_chain_depth = 0");
    assert_conservation(&result);
}

// ── Chain depth filtering tests (extended) ────────────────────────────────

#[test]
fn test_chain_depth_filter_excludes_deep_utxos_from_available() {
    // The deep UTXO is filtered out; `available` in the error should
    // reflect only the eligible pool.
    let utxos = vec![
        confirmed_utxo(1, 50_000),
        pending_utxo_deep(2, 5_000_000, 6, 500), // depth 6 > default 5
    ];
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        default_fee_rate(),
    );
    assert!(matches!(
        result,
        Err(CoinSelectionError::InsufficientFunds {
            available: 50_000,
            ..
        })
    ));
}

#[test]
fn test_mixed_confirmation_ancestors_only_mempool_counted() {
    // 3 ancestors: 2 with 0 confirmations, 1 with 1 confirmation.
    // Mempool depth = 2, chain depth = 3.
    let utxo = pending_utxo_mixed(
        1,
        1_000_000,
        &[(0, 1000, 500), (1, 1000, 500), (0, 1000, 500)],
    );
    assert_eq!(utxo.status.mempool_chain_depth(), 2);
    assert_eq!(utxo.status.chain_depth(), 3);

    let requests = vec![make_request(1, 100_000, 0)];

    // max_mempool_chain_depth = 2 should allow this UTXO.
    let params = CoinSelectionParams {
        max_mempool_chain_depth: 2,
        ..default_params()
    };
    let result = select_coins(
        std::slice::from_ref(&utxo),
        &requests,
        &params,
        default_fee_rate(),
    )
    .expect("should succeed at depth limit");
    assert_conservation(&result);

    // max_mempool_chain_depth = 1 should exclude it.
    let strict_params = CoinSelectionParams {
        max_mempool_chain_depth: 1,
        ..default_params()
    };
    let result = select_coins(
        &[utxo],
        &requests,
        &strict_params,
        default_fee_rate(),
    );
    assert!(matches!(
        result,
        Err(CoinSelectionError::InsufficientFunds { .. })
    ));
}

// ── CPFP tests (extended) ─────────────────────────────────────────────────

#[test]
fn test_cpfp_no_deficit_for_well_paying_ancestor() {
    // An ancestor that already pays at or above the target fee rate
    // produces zero CPFP deficit; the fee should equal a confirmed tx.
    //
    // default_fee_rate() = 5 sat/vb. At 1000 wu = 250 vb, the needed
    // ancestor fee is 250 * 5 = 1250 sat. We pay 2000 sat — well above
    // the target, so the deficit is zero.
    let well_paid = UtxoCandidate {
        id: make_utxo_id(1),
        amount: 5_000_000,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Pending {
            chain: vec![AncestorTx {
                confirmations: 0,
                tx_weight: Weight::from_wu(1000),
                tx_fee: 2000,
            }],
        },
    };

    let requests = vec![make_request(1, 100_000, 0)];

    let pending_result = select_coins(
        &[well_paid],
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("pending should succeed");

    let confirmed_result = select_coins(
        &[confirmed_utxo(1, 5_000_000)],
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("confirmed should succeed");

    // CPFP deficit is zero, so fees should be equal.
    assert_eq!(
        pending_result.fee, confirmed_result.fee,
        "well-paying ancestor should produce zero CPFP deficit"
    );
    assert_conservation(&pending_result);
    assert_conservation(&confirmed_result);
}

#[test]
fn test_cpfp_deficit_exhausts_fee_cap() {
    // A very low-fee, very heavy ancestor creates a CPFP deficit that
    // exceeds max_fee_per_request.
    let heavy_low_fee = UtxoCandidate {
        id: make_utxo_id(1),
        amount: 5_000_000,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Pending {
            chain: vec![AncestorTx {
                confirmations: 0,
                tx_weight: Weight::from_wu(400_000), // huge ancestor
                tx_fee: 1,                           // almost zero fee
            }],
        },
    };

    let requests = vec![make_request(1, 100_000, 0)];
    let params = CoinSelectionParams {
        max_fee_per_request: 5_000, // tight budget
        ..default_params()
    };
    let result =
        select_coins(&[heavy_low_fee], &requests, &params, default_fee_rate());

    assert!(
        matches!(result, Err(CoinSelectionError::FeeExceedsCap { .. })),
        "expected FeeExceedsCap, got {result:?}"
    );
}

#[test]
fn test_cpfp_with_consolidation() {
    // One pending UTXO (primary input) plus confirmed consolidation
    // candidates. Consolidation should add confirmed inputs; CPFP
    // deficit is recomputed on the final weight.
    let utxos = vec![
        pending_utxo(1, 1_000_000),
        confirmed_utxo(2, 5_000),
        confirmed_utxo(3, 10_000),
        confirmed_utxo(4, 15_000),
    ];
    let requests = vec![make_request(1, 200_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        FeeRate::from_sat_per_vb_unchecked(1), // low: consolidation active
    )
    .expect("should succeed");

    assert!(result.inputs.len() > 1, "expected consolidation inputs");
    assert!(result.inputs.iter().any(|u| u.amount == 1_000_000));
    // All extra inputs should be confirmed.
    for input in result.inputs.iter().skip(1) {
        assert!(
            matches!(input.status, UtxoStatus::Confirmed),
            "consolidation should only add confirmed UTXOs"
        );
    }
    assert_conservation(&result);
}

#[test]
fn test_fund_balance_with_cpfp() {
    // With CPFP, the fund balance decreases by more than
    // sum(request.amounts) because the CPFP deficit is charged to
    // requests.
    let utxo = UtxoCandidate {
        id: make_utxo_id(1),
        amount: 2_000_000,
        spend_path: SpendPath::TaprootScriptPath2of2,
        status: UtxoStatus::Pending {
            chain: vec![AncestorTx {
                confirmations: 0,
                tx_weight: Weight::from_wu(5000),
                tx_fee: 100, // severely underpaying
            }],
        },
    };
    let requests = vec![make_request(1, 500_000, 0)];
    let result =
        select_coins(&[utxo], &requests, &default_params(), default_fee_rate())
            .expect("should succeed");

    let input_sum: u64 = result.inputs.iter().map(|u| u.amount).sum();
    let change = result.change.unwrap_or(0);
    let total_selected: u64 =
        result.selected_requests.iter().map(|r| r.amount).sum();

    let fund_decrease = input_sum - change;
    assert!(
        fund_decrease >= total_selected,
        "fund decrease {fund_decrease} should be >= total_selected \
         {total_selected}"
    );
    assert_conservation(&result);
}

// ── Consolidation tests (extended) ────────────────────────────────────────

#[test]
fn test_consolidation_three_tiers_ordering() {
    // Low fee should consolidate >= moderate >= high.
    let utxos: Vec<UtxoCandidate> = (0u8..30)
        .map(|i| confirmed_utxo(i, 100_000))
        .collect();
    let requests = vec![make_request(1, 50_000, 0)];

    let low = FeeRate::from_sat_per_vb_unchecked(1);
    let moderate = FeeRate::from_sat_per_vb_unchecked(15);
    let high = FeeRate::from_sat_per_vb_unchecked(30);

    let low_r = select_coins(&utxos, &requests, &default_params(), low)
        .expect("low should succeed");
    let mod_r = select_coins(&utxos, &requests, &default_params(), moderate)
        .expect("moderate should succeed");
    let high_r = select_coins(&utxos, &requests, &default_params(), high)
        .expect("high should succeed");

    assert!(
        low_r.inputs.len() >= mod_r.inputs.len(),
        "low ({}) should consolidate >= moderate ({})",
        low_r.inputs.len(),
        mod_r.inputs.len()
    );
    assert!(
        mod_r.inputs.len() >= high_r.inputs.len(),
        "moderate ({}) should consolidate >= high ({})",
        mod_r.inputs.len(),
        high_r.inputs.len()
    );
    assert_conservation(&low_r);
    assert_conservation(&mod_r);
    assert_conservation(&high_r);
}

#[test]
fn test_max_inputs_caps_consolidation() {
    let utxos: Vec<UtxoCandidate> = (0u8..20)
        .map(|i| confirmed_utxo(i, 100_000))
        .collect();
    let requests = vec![make_request(1, 50_000, 0)];
    let params = CoinSelectionParams {
        max_inputs: 5,
        ..default_params()
    };

    let low_fee = FeeRate::from_sat_per_vb_unchecked(1);
    let result = select_coins(&utxos, &requests, &params, low_fee)
        .expect("should succeed");

    assert!(
        result.inputs.len() <= 5,
        "total inputs {} exceeded max_inputs 5",
        result.inputs.len()
    );
    assert_conservation(&result);
}

#[test]
fn test_fee_rate_at_long_term_boundary() {
    // fee_rate exactly at long_term_fee_rate (10 sat/vB) is NOT below
    // the long-term rate, so it falls into the moderate consolidation
    // tier: cap = input_budget * N / 2 = 10 * 1 / 2 = 5 extras.
    let utxos: Vec<UtxoCandidate> = (0u8..10)
        .map(|i| confirmed_utxo(i, 100_000))
        .collect();
    let requests = vec![make_request(1, 50_000, 0)];
    let at_lt = FeeRate::from_sat_per_vb_unchecked(10);

    let result =
        select_coins(&utxos, &requests, &default_params(), at_lt)
            .expect("should succeed");

    // 1 min input + at most 5 extras = 6 max.
    assert!(
        result.inputs.len() <= 6,
        "at long-term rate, moderate consolidation: max 6 inputs, got {}",
        result.inputs.len()
    );
    assert_conservation(&result);
}

#[test]
fn test_dust_padding_reclaimed_by_consolidation() {
    // Initial raw_change is sub-dust (requires dust padding from requests).
    // Consolidation adds enough value to push change above dust, eliminating
    // the padding cost.
    let utxos = vec![
        confirmed_utxo(1, 100_100), // 100 sat raw change (sub-dust)
        confirmed_utxo(2, 5_000),
        confirmed_utxo(3, 10_000),
    ];
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        FeeRate::from_sat_per_vb_unchecked(1), // low fee: consolidation active
    )
    .expect("should succeed");

    if result.inputs.len() > 1 {
        assert!(
            result.change.unwrap_or(0) > TR_DUST_RELAY_MIN_VALUE,
            "consolidation should eliminate dust padding need"
        );
    }
    assert_conservation(&result);
}

#[test]
fn test_exact_match_then_consolidation_creates_sub_dust_change() {
    // Regression: input_total exactly matches total_requested before
    // consolidation (no change), then consolidation adds a small UTXO
    // that creates sub-dust change. The dust padding must be budgeted.
    let utxos = vec![
        confirmed_utxo(1, 100_000), // exact match
        confirmed_utxo(2, 100),     // small consolidation candidate
    ];
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &utxos,
        &requests,
        &default_params(),
        FeeRate::from_sat_per_vb_unchecked(1), // low fee: consolidation active
    )
    .expect("should succeed");

    if result.inputs.len() > 1 {
        assert!(
            result.change.unwrap_or(0) >= TR_DUST_RELAY_MIN_VALUE,
            "sub-dust change from consolidation must be padded"
        );
    }
    assert_conservation(&result);
}

// ── Spend path / recipient weight tests ──────────────────────────────────

#[test]
fn test_unknown_recipient_length_uses_p2tr_weight() {
    // A non-standard recipient length falls back to the P2TR weight.
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let req = WithdrawalRequest {
        id: Address::new([1; 32]),
        recipient: vec![0u8; 25],
        amount: 100_000,
        timestamp_ms: 0,
    };
    let result = select_coins(
        &utxos,
        &[req],
        &default_params(),
        default_fee_rate(),
    )
    .expect("unknown recipient length should succeed with P2TR weight");
    assert_conservation(&result);
}

#[test]
fn test_custom_spend_path_weight() {
    let spend_path = SpendPath::Custom(Weight::from_wu(100));
    assert_eq!(spend_path.satisfaction_weight(), Weight::from_wu(100));
    assert_eq!(spend_path.input_weight(), Weight::from_wu(264));

    let utxo = UtxoCandidate {
        id: make_utxo_id(1),
        amount: 1_000_000,
        spend_path: SpendPath::Custom(Weight::from_wu(100)),
        status: UtxoStatus::Confirmed,
    };
    let requests = vec![make_request(1, 100_000, 0)];
    let result = select_coins(
        &[utxo],
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");
    assert_conservation(&result);
}

#[test]
fn test_taproot_key_path_spend() {
    assert_eq!(
        SpendPath::TaprootKeyPath.satisfaction_weight(),
        Weight::from_wu(66)
    );
    assert_eq!(
        SpendPath::TaprootKeyPath.input_weight(),
        Weight::from_wu(230)
    );

    let utxo = UtxoCandidate {
        id: make_utxo_id(1),
        amount: 1_000_000,
        spend_path: SpendPath::TaprootKeyPath,
        status: UtxoStatus::Confirmed,
    };
    let requests = vec![make_request(1, 100_000, 0)];
    let key_path_result = select_coins(
        &[utxo],
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");
    assert_conservation(&key_path_result);

    // Key-path witness is lighter than script-path, so fee should be lower.
    let script_path_result = select_coins(
        &[confirmed_utxo(2, 1_000_000)],
        &requests,
        &default_params(),
        default_fee_rate(),
    )
    .expect("should succeed");
    assert!(
        key_path_result.fee <= script_path_result.fee,
        "key-path fee {} should be <= script-path fee {}",
        key_path_result.fee,
        script_path_result.fee
    );
}

// ── Output dust boundary tests ────────────────────────────────────────────

#[test]
fn test_withdrawal_output_at_dust_boundary_p2tr() {
    // A P2TR withdrawal output exactly at the dust threshold (330 sat)
    // should succeed.
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let req = make_request(1, 1_310, 0);
    let result =
        select_coins(&utxos, &[req], &default_params(), default_fee_rate())
            .expect("output at dust boundary should succeed");
    assert!(
        result.withdrawal_outputs[0].amount >= TR_DUST_RELAY_MIN_VALUE,
        "output {} should be >= dust {}",
        result.withdrawal_outputs[0].amount,
        TR_DUST_RELAY_MIN_VALUE
    );
    assert_conservation(&result);
}

#[test]
fn test_withdrawal_output_below_dust_rejected() {
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let req = make_request(1, 500, 0); // way below fee + dust
    let result =
        select_coins(&utxos, &[req], &default_params(), default_fee_rate());
    assert!(
        matches!(result, Err(CoinSelectionError::RequestAmountTooSmall { .. })),
        "sub-dust output should be rejected, got {result:?}"
    );
}

// ── Weight limit tests ────────────────────────────────────────────────────

#[test]
fn test_exceeds_max_weight_error() {
    // Set max_tx_weight to 1 WU so even a single-request transaction
    // exceeds it, triggering ExceedsMaxWeight.
    let utxos = vec![confirmed_utxo(1, 1_000_000)];
    let requests = vec![make_request(1, 100_000, 0)];
    let params = CoinSelectionParams {
        max_tx_weight: Weight::from_wu(1),
        ..default_params()
    };
    let result =
        select_coins(&utxos, &requests, &params, default_fee_rate());
    assert!(
        matches!(result, Err(CoinSelectionError::ExceedsMaxWeight { .. })),
        "expected ExceedsMaxWeight, got {result:?}"
    );
}

// ── max_inputs in step 2 tests ────────────────────────────────────────────

#[test]
fn test_max_inputs_prevents_covering_request_returns_insufficient_funds() {
    // Pool has many small UTXOs; max_inputs = 2 prevents selecting
    // enough to cover the request. Step 2 is gated by max_inputs
    // before consolidation, so InsufficientFunds is returned.
    let utxos: Vec<UtxoCandidate> = (0u8..10)
        .map(|i| confirmed_utxo(i, 10_000))
        .collect();
    let requests = vec![make_request(1, 50_000, 0)];
    let params = CoinSelectionParams {
        max_inputs: 2,
        ..default_params()
    };
    let result =
        select_coins(&utxos, &requests, &params, default_fee_rate());
    // 2 inputs × 10k = 20k < 50k required.
    assert!(
        matches!(result, Err(CoinSelectionError::InsufficientFunds { .. })),
        "expected InsufficientFunds when max_inputs blocks coverage, got {result:?}"
    );
}

// ── Consolidation undo path tests ─────────────────────────────────────────

#[test]
fn test_consolidation_undo_when_fee_cap_exceeded() {
    // A tight fee cap that the base tx passes, but adding a consolidation
    // input pushes total_deduction over the cap. The input should be
    // popped and consolidation should stop, leaving only the base inputs.
    //
    // One large UTXO covers the request with plenty of change (so
    // consolidation is attempted). Many small confirmed UTXOs are
    // consolidation candidates. We set max_fee_per_request just above
    // the base-tx deduction but below the deduction after one extra input
    // is added. Since inputs are added smallest-first, the extra weight
    // from each additional input raises required_fee incrementally.
    let utxos: Vec<UtxoCandidate> = std::iter::once(confirmed_utxo(0, 5_000_000))
        .chain((1u8..=20).map(|i| confirmed_utxo(i, 5_000)))
        .collect();
    let requests = vec![make_request(1, 100_000, 0)];

    // Use a high fee rate so each extra input noticeably raises the fee.
    let fee_rate = FeeRate::from_sat_per_vb_unchecked(20);

    // Compute the base tx fee (1 input, 1 request) with this fee rate to
    // find a cap that passes base but fails after consolidation.
    let base_result = select_coins(
        &[confirmed_utxo(0, 5_000_000)],
        &requests,
        &default_params(),
        fee_rate,
    )
    .expect("base should succeed");

    let tight_cap = base_result.fee + 10; // just above base, below with extras
    let params = CoinSelectionParams {
        max_fee_per_request: tight_cap,
        ..default_params()
    };

    let result = select_coins(&utxos, &requests, &params, fee_rate)
        .expect("should succeed after consolidation undo");

    // The result should have only the base inputs (consolidation was
    // either skipped or fully undone). Conservation must hold.
    assert_eq!(
        result.inputs.len(),
        1,
        "consolidation inputs should have been undone: got {} inputs",
        result.inputs.len()
    );
    assert_conservation(&result);
}
