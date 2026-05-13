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
use hashi::communication::fetch_certificates;
use hashi::db::Database;
use hashi::mpc::MpcManager;
use hashi::mpc::types::CertificateV1;
use hashi::mpc::types::ProtocolType;
use hashi::mpc::types::ReconstructionOutcome;
use hashi::mpc::types::SessionId;
use hashi::onchain::OnchainState;
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
}

pub async fn run(args: Args, onchain_state: &OnchainState, chain_id: &str) -> anyhow::Result<()> {
    if args.db_paths.is_empty() {
        bail!("--db-paths is required");
    }

    let previous_epoch = detect_epoch(&args.db_paths[0])?;
    let reconstruction_epoch = previous_epoch + 1;

    let committee = {
        let state = onchain_state.state();
        let committees = state.hashi().committees.committees();
        committees
            .get(&reconstruction_epoch)
            .or_else(|| committees.get(&previous_epoch))
            .ok_or_else(|| {
                anyhow!("no committee found for epoch {reconstruction_epoch} or {previous_epoch}")
            })?
            .clone()
    };

    println!(
        "Previous epoch {previous_epoch}: {} validators, fetching certificates...",
        committee.members().len()
    );

    let raw_certs = fetch_certificates(onchain_state, previous_epoch, None)
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
        let encryption_key = db
            .get_encryption_key(previous_epoch)
            .map_err(|e| anyhow!("failed to read encryption key: {e}"))?
            .ok_or_else(|| {
                anyhow!(
                    "no encryption key found for epoch {previous_epoch} in {}",
                    db_path.display()
                )
            })?;

        let my_enc_pk = EncryptionPublicKey::from_private_key(&encryption_key);
        let validator_address = find_validator_by_encryption_key(&committee, &my_enc_pk)
            .ok_or_else(|| {
                anyhow!(
                    "DB encryption key doesn't match any committee member (epoch {previous_epoch})"
                )
            })?;
        println!("  Validator address: {validator_address}");

        let store = EpochPublicMessagesStore::new(db.clone(), previous_epoch);
        let session_id = SessionId::new(chain_id, reconstruction_epoch, &ProtocolType::KeyRotation);
        let mut manager = {
            let state = onchain_state.state();
            let hashi = state.hashi();
            // The tool reconstructs the previous epoch's output from a DB
            // backup, so `encryption_key` here is the key that decrypted that
            // epoch's AVSS messages. Pass it as both `encryption_key` (unused)
            // and `previous_encryption_key` (the one reconstruction uses).
            MpcManager::new(
                validator_address,
                &hashi.committees,
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
            )
            .map_err(|e| anyhow!("failed to create MpcManager: {e}"))?
        };

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
