// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use clap::Parser;
use fastcrypto::groups::GroupElement;
use fastcrypto::groups::Scalar as ScalarTrait;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::S;
use hashi::communication::fetch_key_generation_certificates;
use hashi::db::Database;
use hashi::mpc::MpcManager;
use hashi::mpc::types::CertificateV1;
use hashi::mpc::types::ProtocolType;
use hashi::mpc::types::ReconstructionOutcome;
use hashi::mpc::types::SessionId;
use hashi::onchain::OnchainState;
use hashi::onchain::types::CommitteeSet;
use hashi::storage::EpochPublicMessagesStore;
use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::Committee;
use hashi_types::committee::EncryptionPublicKey;
use sui_sdk_types::Address;

#[derive(Parser)]
pub struct Args {
    /// Comma-separated paths to validator DB backups.
    #[arg(long, value_delimiter = ',')]
    db_paths: Vec<PathBuf>,

    /// Expected public key in hex (for verification).
    #[arg(long)]
    expected_pubkey: Option<String>,

    /// Override the source epoch (the one whose KeyRotation output we want
    /// to reconstruct). Defaults to the latest encryption-key epoch found
    /// in the first DB.
    #[arg(long)]
    epoch: Option<u64>,
}

pub async fn run(args: Args, onchain_state: &OnchainState, chain_id: &str) -> anyhow::Result<()> {
    if args.db_paths.is_empty() {
        bail!("--db-paths is required");
    }

    let onchain_committee_epochs: Vec<u64> = {
        let state = onchain_state.state();
        state
            .hashi()
            .committees
            .committees()
            .keys()
            .copied()
            .collect()
    };
    println!("On-chain committee epochs: {onchain_committee_epochs:?}");
    for db_path in &args.db_paths {
        let db = Database::open(db_path).with_context(|| {
            format!("failed to open DB for epoch listing: {}", db_path.display())
        })?;
        let latest = db
            .latest_encryption_key_epoch()
            .map_err(|e| anyhow!("failed to scan encryption keys: {e}"))?;
        let mut present = Vec::new();
        let mut rot_present = Vec::new();
        let mut dkg_present = Vec::new();
        if let Some(top) = latest {
            for e in top.saturating_sub(15)..=top {
                if db
                    .get_encryption_key(e)
                    .map_err(|err| anyhow!("get_encryption_key({e}): {err}"))?
                    .is_some()
                {
                    present.push(e);
                }
                if !db
                    .list_all_rotation_messages(e)
                    .map_err(|err| anyhow!("list_all_rotation_messages({e}): {err}"))?
                    .is_empty()
                {
                    rot_present.push(e);
                }
                if !db
                    .list_all_dealer_messages(e)
                    .map_err(|err| anyhow!("list_all_dealer_messages({e}): {err}"))?
                    .is_empty()
                {
                    dkg_present.push(e);
                }
            }
        }
        println!(
            "  {} enc_keys = {present:?} rot_msgs = {rot_present:?} dkg_msgs = {dkg_present:?} (latest enc = {latest:?})",
            db_path.display()
        );
    }

    let previous_epoch = match args.epoch {
        Some(e) => {
            println!("Using --epoch override: {e}");
            e
        }
        None => detect_epoch(&args.db_paths[0])?,
    };
    let reconstruction_epoch = previous_epoch + 1;

    // Build a recovery-local `CommitteeSet` that mirrors the on-chain
    // committees but pins `committees[reconstruction_epoch]` to
    // `previous_epoch`'s committee. `MpcManager::new` requires a committee at
    // `reconstruction_epoch`, and reconstruction decrypts AVSS messages with
    // `previous_epoch`'s encryption keys (per #502). Cloning instead of
    // mutating `onchain_state` keeps the watcher free to rescrape without
    // racing this tool.
    let recovery_committee_set =
        build_recovery_committee_set(onchain_state, previous_epoch, reconstruction_epoch)?;
    let previous_committee = recovery_committee_set
        .committees()
        .get(&previous_epoch)
        .expect("previous_epoch was just inserted by build_recovery_committee_set");

    println!(
        "Previous epoch {previous_epoch}: {} validators, fetching certificates...",
        previous_committee.members().len()
    );

    let raw_certs = fetch_key_generation_certificates(onchain_state, previous_epoch)
        .await
        .map_err(|e| anyhow!("failed to fetch certificates: {e}"))?;
    let certificates: Vec<CertificateV1> = raw_certs.into_iter().map(|(_, cert)| cert).collect();
    println!(
        "Fetched {} certificates for epoch {previous_epoch}",
        certificates.len()
    );

    if certificates.is_empty() {
        bail!("No certificates found for epoch {previous_epoch}. Try a different epoch.");
    }

    // For each validator DB, reconstruct their key shares
    let dummy_signing_key = Bls12381PrivateKey::generate(&mut rand::thread_rng());
    let mut all_shares: Vec<Eval<S>> = Vec::new();
    let mut recovered_pubkey: Option<G> = None;

    for (i, db_path) in args.db_paths.iter().enumerate() {
        println!("\n=== Validator {i}: {} ===", db_path.display());

        let db = Arc::new(
            Database::open(db_path)
                .with_context(|| format!("failed to open DB: {}", db_path.display()))?,
        );
        let Some(encryption_key) = db
            .get_encryption_key(previous_epoch)
            .map_err(|e| anyhow!("failed to read encryption key: {e}"))?
        else {
            println!("  Skipping: no encryption key for epoch {previous_epoch}");
            continue;
        };

        let my_enc_pk = EncryptionPublicKey::from_private_key(&encryption_key);
        let Some(validator_address) =
            find_validator_by_encryption_key(previous_committee, &my_enc_pk)
        else {
            println!(
                "  Skipping: DB encryption key for epoch {previous_epoch} doesn't match any committee member"
            );
            continue;
        };
        println!("  Validator address: {validator_address}");

        let store = EpochPublicMessagesStore::new(db.clone(), previous_epoch);
        let session_id = SessionId::new(chain_id, reconstruction_epoch, &ProtocolType::KeyRotation);
        // `encryption_key` decrypted `previous_epoch`'s AVSS messages, which is
        // what reconstruction reads. Pass it as both `encryption_key` (unused
        // here) and `previous_encryption_key`.
        let metrics = hashi::metrics::Metrics::new_default();
        let mut manager = MpcManager::new(
            validator_address,
            &recovery_committee_set,
            reconstruction_epoch,
            session_id,
            encryption_key.clone(),
            Some(encryption_key),
            dummy_signing_key.clone(),
            Box::new(store),
            chain_id,
            None, // weight_divisor
            0,    // batch_size_per_weight (unused for reconstruction)
            None, // test_corrupt_shares_for
            &metrics,
        )
        .map_err(|e| anyhow!("failed to create MpcManager: {e}"))?;

        // Override previous_epoch to match the backed-up DB's epoch, since
        // the on-chain epoch may have advanced past the backup.
        manager.set_previous_epoch(previous_epoch);

        // Pass an empty complaint cache: the recovery tool runs reconstruction
        // once without retrying through complaint recovery, so there are no
        // recovered outputs to reuse across attempts.
        let outcome = manager
            .reconstruct_previous_output(&certificates, &std::collections::HashMap::new())
            .map_err(|e| anyhow!("reconstruction failed: {e}"))?;

        match outcome {
            ReconstructionOutcome::Success(output) => {
                println!(
                    "  Public key: {}",
                    hex::encode(output.public_key.to_byte_array())
                );
                println!("  Shares: {}", output.key_shares.shares.len());
                println!("  Threshold: {}", output.threshold);

                if let Some(ref pk) = recovered_pubkey
                    && *pk != output.public_key
                {
                    bail!("Public key mismatch between validators!");
                }
                recovered_pubkey = Some(output.public_key);
                all_shares.extend(output.key_shares.shares.iter().cloned());
            }
            ReconstructionOutcome::NeedsDkgComplaintRecovery { dealer_address, .. } => {
                println!(
                    "  Warning: needs DKG complaint recovery for dealer {dealer_address}, skipping"
                );
            }
            ReconstructionOutcome::NeedsRotationComplaintRecovery {
                dealer_address,
                share_index,
                ..
            } => {
                println!(
                    "  Warning: needs rotation complaint recovery for dealer {dealer_address} share {share_index}, skipping"
                );
            }
        }
    }

    // Lagrange interpolation to recover full private key
    let pubkey =
        recovered_pubkey.ok_or_else(|| anyhow!("no shares recovered from any validator"))?;
    println!("\n=== Lagrange Interpolation ===");
    println!("Total shares collected: {}", all_shares.len());

    let secret_key = lagrange_interpolate_at_zero(&all_shares)?;

    // Verify
    let recovered_pk = G::generator() * secret_key;
    println!(
        "Recovered public key:  {}",
        hex::encode(recovered_pk.to_byte_array())
    );
    println!(
        "Expected public key:   {}",
        hex::encode(pubkey.to_byte_array())
    );

    if recovered_pk != pubkey {
        bail!("VERIFICATION FAILED: recovered key does not match expected public key");
    }
    println!("\nVerification PASSED!");

    if let Some(ref expected) = args.expected_pubkey {
        let expected_bytes = hex::decode(expected)?;
        let expected_pk = G::from_byte_array(
            &expected_bytes
                .try_into()
                .map_err(|_| anyhow!("invalid pubkey length"))?,
        )
        .map_err(|e| anyhow!("invalid expected pubkey: {e}"))?;
        if recovered_pk != expected_pk {
            bail!("MISMATCH with --expected-pubkey!");
        }
        println!("Matches --expected-pubkey!");
    }

    println!(
        "\nRecovered private key (hex): {}",
        hex::encode(secret_key.to_byte_array())
    );

    Ok(())
}

/// Clone the on-chain `CommitteeSet`'s committees and pin
/// `committees[reconstruction_epoch]` to `previous_epoch`'s committee.
///
/// `MpcManager::new` requires `committees[reconstruction_epoch]` to exist and
/// to be the committee whose encryption keys decrypt the AVSS messages we're
/// reconstructing — which, per #502, is `previous_epoch`'s committee. This is
/// true regardless of whether the cluster has published its real next-epoch
/// committee yet, so we unconditionally overwrite; a warning is printed if an
/// existing on-chain entry differs.
fn build_recovery_committee_set(
    onchain_state: &OnchainState,
    previous_epoch: u64,
    reconstruction_epoch: u64,
) -> anyhow::Result<CommitteeSet> {
    let state = onchain_state.state();
    let mut committees = state.hashi().committees.committees().clone();
    let previous_committee = committees
        .get(&previous_epoch)
        .cloned()
        .ok_or_else(|| anyhow!("no on-chain committee for epoch {previous_epoch}"))?;
    if let Some(existing) = committees.get(&reconstruction_epoch)
        && existing != &previous_committee
    {
        println!(
            "Warning: on-chain committee[{reconstruction_epoch}] differs from \
             committee[{previous_epoch}]; recovery uses committee[{previous_epoch}]"
        );
    }
    committees.insert(reconstruction_epoch, previous_committee);
    let mut set = CommitteeSet::new(Address::ZERO, Address::ZERO);
    set.set_committees(committees);
    Ok(set)
}

fn detect_epoch(db_path: &std::path::Path) -> anyhow::Result<u64> {
    let db = Database::open(db_path).with_context(|| {
        format!(
            "failed to open DB for epoch detection: {}",
            db_path.display()
        )
    })?;
    let epoch = db
        .latest_encryption_key_epoch()
        .map_err(|e| anyhow!("failed to scan encryption keys: {e}"))?
        .ok_or_else(|| anyhow!("no encryption keys found in DB: {}", db_path.display()))?;
    println!("Auto-detected source epoch: {epoch}");
    Ok(epoch)
}

fn find_validator_by_encryption_key(
    committee: &Committee,
    enc_pk: &EncryptionPublicKey,
) -> Option<Address> {
    committee.members().iter().find_map(|m| {
        if m.encryption_public_key().as_element().to_byte_array()
            == enc_pk.as_element().to_byte_array()
        {
            Some(m.validator_address())
        } else {
            None
        }
    })
}

fn lagrange_interpolate_at_zero(shares: &[Eval<S>]) -> anyhow::Result<S> {
    if shares.is_empty() {
        bail!("no shares to interpolate");
    }
    let indices: Vec<S> = shares
        .iter()
        .map(|s| S::from(s.index.get() as u128))
        .collect();
    let mut result = S::zero();
    for (i, share) in shares.iter().enumerate() {
        let xi = indices[i];
        let one = S::generator();
        let mut numerator = one;
        let mut denominator = one;
        for (j, xj) in indices.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator *= -*xj;
            denominator *= xi - *xj;
        }
        let inv = denominator
            .inverse()
            .map_err(|e| anyhow!("Lagrange denominator inversion failed: {e}"))?;
        let lagrange_coeff = numerator * inv;
        result += share.value * lagrange_coeff;
    }
    Ok(result)
}
