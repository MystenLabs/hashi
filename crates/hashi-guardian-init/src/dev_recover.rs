// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Dev-only recovery of a restarted guardian's BTC key from its ceremony shares.
//!
//! Under the ceremony model the guardian generates its master secret *inside* the
//! enclave (`setup_new_key`) and Shamir-splits it to the key-provisioner (KP) PGP
//! keys; the encrypted shares are persisted to `shares/` and the public
//! `SecretSharingInstance` to `ceremony/` in S3. A restart loses the in-memory BTC
//! key, so this tool reconstructs it from S3 instead of generating a fresh one
//! like [`crate::dev_bootstrap`] does.
//!
//! Two modes:
//!   * default (recovery): read the ceremony's `SecretSharingInstance` + encrypted
//!     shares from S3, decrypt `t` of them with a local gpg homedir holding the KP
//!     private keys, then drive the restarted guardian through
//!     `OperatorInit -> GetGuardianInfo -> ProvisionerInit` re-using the ceremony's
//!     instance and a *recovered* limiter state (so a restart doesn't reset the
//!     rate-limit bucket). Asserts the resulting enclave BTC pubkey matches the
//!     on-chain `guardian_btc_public_key`.
//!   * `--print-master-pubkey`: decrypt `t` shares and combine them locally to
//!     print the x-only master BTC pubkey. No chain / RPC / guardian contact. Used
//!     at genesis to capture the pubkey to pin on-chain (a ceremony-mode guardian
//!     never exposes it directly).
//!
//! DEV-SCOPED: this is the centralized-operator analogue of the production
//! distributed KP flow. The real recovery path runs each KP's share through the
//! relay (`crate::provisioner`) — which Luke/Deepak own — rather than decrypting
//! every share from one gpg homedir here. Keep this off the production path.

use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use clap::Parser;
use hashi::config::Config;
use hashi::onchain::OnchainState;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::KPEncryptedShare;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::Share;
use hashi_types::guardian::ShareCommitments;
use hashi_types::guardian::ShareID;
use hashi_types::guardian::WithdrawModeConfig;
use hashi_types::guardian::crypto::combine_shares;
use hashi_types::guardian::crypto::k256_sk_to_btc_keypair;
use hashi_types::guardian::proto_conversions::provisioner_init_request_to_pb;
use hashi_types::guardian::proto_conversions::withdraw_mode_config_to_pb;
use hashi_types::guardian::session_id_from_signing_pubkey;
use hashi_types::pgp::decrypt_with_gpg;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hpke::Deserializable;
use k256::FieldBytes;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use rand::thread_rng;

use crate::dev_bootstrap::decode_mpc_master_g;
use crate::dev_bootstrap::parse_network;
use crate::dev_bootstrap::required_env;
use crate::limiter_recovery;

#[derive(Parser)]
pub struct Args {
    /// gRPC endpoint of the restarted guardian. Unused with `--print-master-pubkey`.
    #[arg(
        long,
        env = "GUARDIAN_ENDPOINT",
        default_value = "http://localhost:3000"
    )]
    guardian_endpoint: String,

    /// Path to a node config TOML (provides sui-rpc + hashi-ids). Required for
    /// recovery; omit it with `--print-master-pubkey` (that mode never touches
    /// the chain).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Token-bucket refill rate (sats / sec). Required for recovery.
    #[arg(long, env = "HASHI_REFILL_RATE_SATS_PER_SEC")]
    refill_rate_sats_per_sec: Option<u64>,

    /// Token-bucket max capacity (sats). Required for recovery.
    #[arg(long, env = "HASHI_MAX_BUCKET_CAPACITY_SATS")]
    max_bucket_capacity_sats: Option<u64>,

    /// Bitcoin network (mainnet/testnet/regtest/signet).
    #[arg(long, env = "BITCOIN_NETWORK", default_value = "signet")]
    bitcoin_network: String,

    /// gpg homedir (GNUPGHOME) holding the KP private keys used to decrypt the
    /// ceremony's `shares/` ciphertexts. Defaults to gpg's default (`~/.gnupg`)
    /// when unset.
    #[arg(long, env = "HASHI_KP_GPG_HOMEDIR")]
    gpg_homedir: Option<PathBuf>,

    /// Decrypt `t` shares, combine them locally, print the x-only master BTC
    /// pubkey (hex) and exit. No chain / RPC / guardian contact.
    #[arg(long)]
    print_master_pubkey: bool,
}

pub async fn run(args: Args) -> Result<()> {
    // AWS creds stay env-only — passing them as CLI flags would leak via `ps`.
    let s3 = s3_config_from_env()?;

    if args.print_master_pubkey {
        return print_master_pubkey(&s3, &args).await;
    }
    recover(&s3, args).await
}

/// `--print-master-pubkey`: reconstruct and print the x-only master BTC pubkey
/// from the latest ceremony's S3 shares. No chain / RPC.
async fn print_master_pubkey(s3: &S3Config, args: &Args) -> Result<()> {
    let mut reader = GuardianReader::new(s3)
        .await
        .context("connect to guardian log bucket")?;
    let (instance, shares) = read_and_decrypt_ceremony_shares(&mut reader, args).await?;
    let master_pubkey = master_pubkey_from_shares(&shares, instance.threshold())?;
    // stdout carries only the pubkey so the deploy workflow can capture it; all
    // context goes through tracing (cf. `fetch_info`).
    println!("{}", hex::encode(master_pubkey.serialize()));
    Ok(())
}

/// Default mode: drive the restarted guardian back to fully-initialized using the
/// ceremony's shares + instance and a recovered limiter state.
async fn recover(s3: &S3Config, args: Args) -> Result<()> {
    let network = parse_network(&args.bitcoin_network)?;
    let limiter_config = limiter_config_from_args(&args)?;

    let config_path = args.config.as_deref().ok_or_else(|| {
        anyhow!(
            "--config <node.toml> is required for recovery (provides sui-rpc + hashi-ids); \
             omit it only with --print-master-pubkey"
        )
    })?;
    let cfg_str = std::fs::read_to_string(config_path)
        .with_context(|| format!("read config {}", config_path.display()))?;
    let cfg: Config = toml::from_str(&cfg_str).context("parse config TOML")?;
    let sui_rpc = cfg
        .sui_rpc
        .as_deref()
        .ok_or_else(|| anyhow!("config missing sui-rpc"))?;
    tracing::info!(sui_rpc, "connecting to Sui RPC");
    // `_watcher` must outlive the run so `onchain_state` keeps refreshing.
    let (onchain_state, _watcher) = OnchainState::new(sui_rpc, cfg.hashi_ids(), None, None, None)
        .await
        .context("failed to connect to Sui RPC")?;

    let committee = onchain_state
        .current_committee()
        .ok_or_else(|| anyhow!("no current committee on chain (DKG not yet complete?)"))?;
    let committee_epoch = committee.epoch();
    // `master_g` is the MPC committee `G` the 2-of-2 scripts derive from — the
    // on-chain MPC `G`, NOT the guardian's own BTC key (matches dev_bootstrap).
    let master_g = decode_mpc_master_g(&onchain_state.mpc_public_key())?;

    let mut reader = GuardianReader::new(s3)
        .await
        .context("connect to guardian log bucket")?;
    let (instance, shares) = read_and_decrypt_ceremony_shares(&mut reader, &args).await?;
    let t = instance.threshold();

    // Pre-flight: confirm the shares we recovered reconstruct the key pinned
    // on-chain BEFORE we touch the guardian. A wrong gpg homedir / stale ceremony
    // would otherwise provision a key the chain rejects.
    let derived_master_pubkey = master_pubkey_from_shares(&shares, t)?;
    if let Some(onchain) = onchain_state.guardian_btc_public_key() {
        anyhow::ensure!(
            derived_master_pubkey.serialize().as_slice() == onchain.as_slice(),
            "recovered master pubkey {} does not match on-chain guardian_btc_public_key {}; \
             wrong gpg homedir or stale ceremony?",
            hex::encode(derived_master_pubkey.serialize()),
            hex::encode(&onchain),
        );
        tracing::info!("recovered master pubkey matches on-chain guardian_btc_public_key");
    } else {
        tracing::warn!(
            "no on-chain guardian_btc_public_key to check the recovered key against; proceeding"
        );
    }

    // Recover the limiter bucket from the prior enclave's `withdraw/` Success logs
    // (same path the prod provisioner uses); genesis only if none exist. Using
    // genesis unconditionally would reset the rate-limit bucket on every restart.
    let limiter_state = match limiter_recovery::recover_limiter_state(&mut reader).await? {
        Some(mut recovered) => {
            recovered.num_tokens_available = recovered
                .num_tokens_available
                .min(limiter_config.max_bucket_capacity);
            tracing::info!(
                next_seq = recovered.next_seq,
                num_tokens_available = recovered.num_tokens_available,
                "recovered limiter state from prior enclave's withdraw logs"
            );
            recovered
        }
        None => {
            tracing::info!("no prior Success withdrawal logs found; limiter starts from genesis");
            LimiterState::genesis(&limiter_config)
        }
    };

    // Build the init state exactly like dev_bootstrap, but with the *ceremony's*
    // instance (not a fresh split) and the recovered limiter state. The digest is
    // the state_hash KPs bind as their share-encryption AAD.
    let config = WithdrawModeConfig::new(
        committee,
        limiter_config,
        limiter_state,
        master_g,
        instance.clone(),
        network,
    )
    .map_err(|e| anyhow!("build WithdrawModeConfig: {e:?}"))?;
    let state_hash = config.state().digest();

    let mut client = GuardianServiceClient::connect(args.guardian_endpoint.clone())
        .await
        .with_context(|| format!("connect to guardian at {}", args.guardian_endpoint))?;

    let operator_init_req = pb::OperatorInitRequest {
        s3_config: Some(pb::S3Config {
            access_key: Some(s3.access_key.clone()),
            secret_key: Some(s3.secret_key.clone()),
            bucket_name: Some(s3.bucket_name().to_string()),
            region: Some(s3.region().to_string()),
        }),
        state: Some(
            withdraw_mode_config_to_pb(config)
                .map_err(|e| anyhow!("encode WithdrawModeConfig: {e:?}"))?,
        ),
    };
    tracing::info!("calling OperatorInit");
    client
        .operator_init(operator_init_req)
        .await
        .context("OperatorInit RPC failed")?;

    let (session_id, enc_pubkey) = verify_guardian_info(&mut client, s3, &instance, state_hash)
        .await
        .context("verify guardian info after OperatorInit")?;

    tracing::info!("submitting ProvisionerInit with {t} shares");
    let mut rng = thread_rng();
    let encrypted_shares = shares
        .iter()
        .take(t)
        .map(|share| {
            ProvisionerInitRequest::build_from_share(share, &enc_pubkey, state_hash, &mut rng)
        })
        .collect();
    let pb_req = provisioner_init_request_to_pb(ProvisionerInitRequest::new(encrypted_shares))
        .map_err(|e| anyhow!("encode ProvisionerInitRequest: {e:?}"))?;
    client
        .provisioner_init(pb_req)
        .await
        .context("ProvisionerInit RPC failed")?;

    // Confirm we're still talking to the same session, then read back the
    // now-provisioned BTC pubkey and assert it matches the chain.
    let post_resp = fetch_verified_info(&mut client).await?;
    let post_session_id = session_id_from_signing_pubkey(&post_resp.signing_pub_key);
    anyhow::ensure!(
        post_session_id == session_id,
        "guardian session changed mid-recovery: started {session_id}, now {post_session_id} \
         (enclave likely restarted; rerun recovery)"
    );
    let enclave_btc_pubkey = post_resp
        .signed_info
        .data
        .enclave_btc_pubkey
        .ok_or_else(|| {
            anyhow!("guardian /info has no enclave_btc_pubkey after ProvisionerInit; threshold not reached?")
        })?;
    if let Some(onchain) = onchain_state.guardian_btc_public_key() {
        anyhow::ensure!(
            enclave_btc_pubkey.serialize().as_slice() == onchain.as_slice(),
            "post-init enclave BTC pubkey {} does not match on-chain guardian_btc_public_key {}",
            hex::encode(enclave_btc_pubkey.serialize()),
            hex::encode(&onchain),
        );
        tracing::info!("post-init enclave BTC pubkey matches on-chain guardian_btc_public_key");
    }

    println!("Guardian recovered.");
    println!("  session_id:        {session_id}");
    println!(
        "  enclave btc pubkey:{}",
        hex::encode(enclave_btc_pubkey.serialize())
    );
    println!("  committee_epoch:   {committee_epoch}");
    println!("  sharing_seq:       {}", instance.sharing_seq());
    Ok(())
}

/// Read the latest ceremony instance + its `shares/` object from S3, then decrypt
/// `threshold` shares with the local gpg homedir, cross-checking each against the
/// ceremony commitments. Shared by both modes.
async fn read_and_decrypt_ceremony_shares(
    reader: &mut GuardianReader,
    args: &Args,
) -> Result<(SecretSharingInstance, Vec<Share>)> {
    let (session_id, instance, _roster) = reader
        .read_latest_ceremony()
        .await?
        .ok_or_else(|| anyhow!("no ceremony logs found in guardian S3 bucket"))?;
    tracing::info!(
        session_id = %session_id,
        sharing_seq = instance.sharing_seq(),
        n = instance.num_shares(),
        t = instance.threshold(),
        "read latest ceremony instance"
    );

    let encrypted_shares = reader
        .read_shares(&session_id, instance.sharing_seq())
        .await
        .context("read encrypted KP shares from S3")?;

    let shares = decrypt_threshold_shares(
        encrypted_shares.as_slice(),
        instance.commitments(),
        instance.threshold(),
        args.gpg_homedir.as_deref(),
    )?;
    Ok((instance, shares))
}

/// `GetGuardianInfo` + verify the enclave self-signature, then check the guardian
/// echoed back the bucket / ceremony instance / state_hash we submitted. Returns
/// the pinned session id and the enclave HPKE encryption key. Mirrors
/// `dev_bootstrap`'s post-OperatorInit checks.
async fn verify_guardian_info(
    client: &mut GuardianServiceClient<tonic::transport::Channel>,
    s3: &S3Config,
    instance: &SecretSharingInstance,
    state_hash: [u8; 32],
) -> Result<(String, EncPubKey)> {
    let resp = fetch_verified_info(client).await?;
    let session_id = session_id_from_signing_pubkey(&resp.signing_pub_key);

    // Verify the enclave's own signature on the info — without it the
    // `encryption_pubkey` would be unauthenticated.
    //
    // TODO(check C): also authenticate `signing_pub_key` against the AWS Nitro
    // attestation. `verify_enclave_attestation` is a no-op today, so a malicious
    // operator could echo our submitted config and serve their own keys; the
    // attestation gate lands when the guardian moves to Nitro.
    let info = resp
        .signed_info
        .verify(&resp.signing_pub_key)
        .map_err(|e| anyhow!("verify GuardianInfo signature (session={session_id}): {e:?}"))?;

    let returned_bucket = info.bucket_info.as_ref().ok_or_else(|| {
        anyhow!("guardian info missing bucket_info; OperatorInit may have silently failed")
    })?;
    anyhow::ensure!(
        returned_bucket.bucket == s3.bucket_name() && returned_bucket.region == s3.region(),
        "bucket mismatch: submitted {}/{}, guardian echoed {}/{}",
        s3.region(),
        s3.bucket_name(),
        returned_bucket.region,
        returned_bucket.bucket,
    );
    let returned_instance = info
        .secret_sharing_instance
        .as_ref()
        .ok_or_else(|| anyhow!("guardian info missing secret_sharing_instance"))?;
    anyhow::ensure!(
        returned_instance == instance,
        "secret-sharing instance mismatch: guardian echoed a different scheme than the ceremony's"
    );
    let returned_state_hash = info
        .state_hash
        .ok_or_else(|| anyhow!("guardian info missing state_hash"))?;
    anyhow::ensure!(
        returned_state_hash == state_hash,
        "state_hash mismatch: guardian echoed a different init state than was submitted"
    );

    let enc_pubkey = EncPubKey::from_bytes(&info.encryption_pubkey)
        .map_err(|e| anyhow!("decode guardian encryption pubkey (session={session_id}): {e:?}"))?;
    tracing::info!(session_id = %session_id, "guardian info verified");
    Ok((session_id, enc_pubkey))
}

async fn fetch_verified_info(
    client: &mut GuardianServiceClient<tonic::transport::Channel>,
) -> Result<GetGuardianInfoResponse> {
    let info_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))
}

/// Decrypt ceremony shares with the local gpg homedir until `threshold` valid
/// shares are collected. Shares the homedir can't decrypt (no matching KP private
/// key) are skipped; a decrypted share that fails its commitment is a hard error
/// (tampering or a share from a different ceremony).
fn decrypt_threshold_shares(
    encrypted_shares: &[KPEncryptedShare],
    commitments: &ShareCommitments,
    threshold: usize,
    gpg_homedir: Option<&Path>,
) -> Result<Vec<Share>> {
    let mut shares: Vec<Share> = Vec::with_capacity(threshold);
    let mut last_err: Option<anyhow::Error> = None;
    for enc in encrypted_shares {
        if shares.len() >= threshold {
            break;
        }
        if shares.iter().any(|s| s.id == enc.id) {
            continue;
        }
        match gpg_decrypt_share(enc, gpg_homedir) {
            Ok(plaintext) => {
                let share = verify_decrypted_share(enc.id, &plaintext, commitments)?;
                shares.push(share);
            }
            Err(e) => {
                tracing::debug!(
                    share_id = enc.id.get(),
                    recipient = %enc.recipient_fingerprint,
                    "skipping share this gpg homedir can't decrypt: {e:#}"
                );
                last_err = Some(e);
            }
        }
    }
    if shares.len() != threshold {
        let hint = last_err
            .map(|e| format!(" (last decrypt error: {e:#})"))
            .unwrap_or_default();
        bail!(
            "decrypted only {} of the required {} ceremony shares; the gpg homedir ({}) must \
             hold at least {threshold} of the KP private keys and gpg must be installed{hint}",
            shares.len(),
            threshold,
            gpg_homedir
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "default ~/.gnupg".to_string()),
        );
    }
    Ok(shares)
}

/// Decrypt one KP share's ciphertext via `gpg --decrypt`, returning the plaintext
/// bytes. Only the ciphertext touches disk (a temp file deleted on drop); the
/// plaintext streams over gpg's stdout into memory (mirrors `ceremony::verify`).
fn gpg_decrypt_share(enc: &KPEncryptedShare, gpg_homedir: Option<&Path>) -> Result<Vec<u8>> {
    let mut ciphertext_file =
        tempfile::NamedTempFile::new().context("create temp file for ciphertext")?;
    ciphertext_file
        .write_all(enc.armored_ciphertext.as_bytes())
        .context("write ciphertext to temp file")?;
    let mut decryptor = decrypt_with_gpg(ciphertext_file.path(), gpg_homedir)?;
    let mut plaintext = Vec::with_capacity(32);
    decryptor
        .read_to_end(&mut plaintext)
        .context("read decrypted share from gpg")?;
    // `ciphertext_file` drops here, unlinking the ciphertext temp file.
    drop(ciphertext_file);
    Ok(plaintext)
}

/// Parse a decrypted share plaintext (`Share::value.to_bytes()` layout: a 32-byte
/// big-endian secp256k1 scalar) into a `Share` and confirm it against the ceremony
/// commitments.
fn verify_decrypted_share(
    id: ShareID,
    plaintext: &[u8],
    commitments: &ShareCommitments,
) -> Result<Share> {
    let scalar_bytes: [u8; 32] = plaintext.try_into().map_err(|_| {
        anyhow!(
            "decrypted share id {} is {} bytes, expected 32",
            id.get(),
            plaintext.len()
        )
    })?;
    let value = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(scalar_bytes)))
        .ok_or_else(|| {
            anyhow!(
                "decrypted share id {} is not a valid secp256k1 scalar",
                id.get()
            )
        })?;
    let share = Share { id, value };
    commitments.verify_share(&share).map_err(|e| {
        anyhow!(
            "decrypted share id {} does not match its ceremony commitment: {e:?}",
            id.get()
        )
    })?;
    Ok(share)
}

/// Reconstruct the x-only master BTC pubkey from `threshold` validated shares.
fn master_pubkey_from_shares(shares: &[Share], threshold: usize) -> Result<BitcoinPubkey> {
    let sk = combine_shares(shares, threshold).map_err(|e| anyhow!("combine shares: {e:?}"))?;
    let (xonly, _parity) = k256_sk_to_btc_keypair(&sk).x_only_public_key();
    Ok(xonly)
}

fn s3_config_from_env() -> Result<S3Config> {
    Ok(S3Config {
        access_key: required_env("AWS_ACCESS_KEY_ID")?,
        secret_key: required_env("AWS_SECRET_ACCESS_KEY")?,
        bucket_info: S3BucketInfo {
            bucket: required_env("AWS_S3_BUCKET")?,
            region: required_env("AWS_REGION")?,
        },
    })
}

fn limiter_config_from_args(args: &Args) -> Result<LimiterConfig> {
    let refill_rate = args.refill_rate_sats_per_sec.ok_or_else(|| {
        anyhow!("--refill-rate-sats-per-sec (or HASHI_REFILL_RATE_SATS_PER_SEC) is required for recovery")
    })?;
    let max_bucket_capacity = args.max_bucket_capacity_sats.ok_or_else(|| {
        anyhow!("--max-bucket-capacity-sats (or HASHI_MAX_BUCKET_CAPACITY_SATS) is required for recovery")
    })?;
    Ok(LimiterConfig {
        refill_rate,
        max_bucket_capacity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Keypair;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::secp256k1::SecretKey as BtcSecretKey;
    use hashi_types::guardian::SecretSharingParams;
    use hashi_types::guardian::crypto::split_secret;

    fn expected_master_xonly(secret: &k256::SecretKey) -> BitcoinPubkey {
        let secp = Secp256k1::new();
        let sk = BtcSecretKey::from_slice(&secret.to_bytes()).unwrap();
        Keypair::from_secret_key(&secp, &sk).x_only_public_key().0
    }

    // The full pure recovery pipeline without gpg/S3: simulate each share's
    // decrypted plaintext (`share.value.to_bytes()` — the exact bytes
    // `encrypt_share_for_provisioner` armors), run it through the same
    // plaintext->Share + commitment check the gpg path uses, then reconstruct.
    #[test]
    fn decrypted_share_plaintexts_verify_and_reconstruct_master_pubkey() {
        const N: usize = 5;
        const T: usize = 3;
        let mut rng = rand::thread_rng();
        let secret = k256::SecretKey::random(&mut rng);
        let expected = expected_master_xonly(&secret);

        let params = SecretSharingParams::new(N, T).unwrap();
        let shares = split_secret(&secret, &params, &mut rng);
        let commitments = ShareCommitments::from_shares(&shares).unwrap();

        // The wire plaintext for each share is its 32-byte scalar.
        let reconstructed: Vec<Share> = shares
            .iter()
            .map(|s| verify_decrypted_share(s.id, &s.value.to_bytes(), &commitments).unwrap())
            .collect();

        let master = master_pubkey_from_shares(&reconstructed[..T], T).unwrap();
        assert_eq!(master, expected);
        // A different (valid) threshold subset reconstructs the same key.
        let master2 = master_pubkey_from_shares(&reconstructed[N - T..], T).unwrap();
        assert_eq!(master2, expected);
    }

    #[test]
    fn verify_decrypted_share_rejects_share_from_another_ceremony() {
        let mut rng = rand::thread_rng();
        let params = SecretSharingParams::new(3, 2).unwrap();
        let our_shares = split_secret(&k256::SecretKey::random(&mut rng), &params, &mut rng);
        let our_commitments = ShareCommitments::from_shares(&our_shares).unwrap();

        // A share with a valid id but a value from a different secret is not in
        // the committed set.
        let foreign = split_secret(&k256::SecretKey::random(&mut rng), &params, &mut rng);
        // `.err().unwrap()` (not `.unwrap_err()`) because `Share` isn't `Debug`.
        let err = verify_decrypted_share(
            foreign[0].id,
            &foreign[0].value.to_bytes(),
            &our_commitments,
        )
        .err()
        .unwrap();
        assert!(format!("{err}").contains("commitment"), "{err}");
    }

    #[test]
    fn verify_decrypted_share_rejects_wrong_length_plaintext() {
        let mut rng = rand::thread_rng();
        let params = SecretSharingParams::new(3, 2).unwrap();
        let shares = split_secret(&k256::SecretKey::random(&mut rng), &params, &mut rng);
        let commitments = ShareCommitments::from_shares(&shares).unwrap();
        let err = verify_decrypted_share(shares[0].id, &[0u8; 31], &commitments)
            .err()
            .unwrap();
        assert!(format!("{err}").contains("expected 32"), "{err}");
    }
}
