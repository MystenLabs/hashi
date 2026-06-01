// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Drive a fresh hashi-guardian from heartbeating-only to fully-initialized.
//! Scrapes the on-chain `HashiCommittee`, generates BTC master + Shamir shares
//! in memory, then runs OperatorInit -> GetGuardianInfo -> ProvisionerInit
//! until the guardian reaches the secret-sharing threshold.

use std::env;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey as BtcSecretKey;
use clap::Parser;
use hashi::onchain::OnchainState;
use hashi_types::guardian::BitcoinPubkey;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::HashiMasterG;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::ProvisionerInitState;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::SecretSharingParams;
use hashi_types::guardian::Share;
use hashi_types::guardian::ShareCommitment;
use hashi_types::guardian::ShareCommitments;
use hashi_types::guardian::crypto::commit_share;
use hashi_types::guardian::crypto::split_secret;
use hashi_types::guardian::proto_conversions::provisioner_init_request_to_pb;
use hashi_types::guardian::proto_conversions::secret_sharing_instance_to_pb;
use hashi_types::guardian::session_id_from_signing_pubkey;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hpke::Deserializable;
use rand::CryptoRng;
use rand::RngCore;
use rand::thread_rng;

#[derive(Parser)]
pub struct Args {
    /// gRPC endpoint of the deployed guardian.
    #[arg(
        long,
        env = "GUARDIAN_ENDPOINT",
        default_value = "http://localhost:3000"
    )]
    guardian_endpoint: String,

    /// Token-bucket refill rate (sats / sec).
    #[arg(long, env = "HASHI_REFILL_RATE_SATS_PER_SEC")]
    refill_rate_sats_per_sec: u64,

    /// Token-bucket max capacity (sats).
    #[arg(long, env = "HASHI_MAX_BUCKET_CAPACITY_SATS")]
    max_bucket_capacity_sats: u64,

    /// Bitcoin network (mainnet/testnet/regtest/signet).
    #[arg(long, env = "BITCOIN_NETWORK", default_value = "signet")]
    bitcoin_network: String,

    /// Total number of key provisioner shares.
    #[arg(long, env = "HASHI_NUM_SHARES", default_value_t = 5)]
    num_shares: usize,

    /// Reconstruction threshold for the BTC key.
    #[arg(long, env = "HASHI_THRESHOLD", default_value_t = 3)]
    threshold: usize,

    /// Pre-generated master secret (32 bytes, hex). Required when the
    /// pubkey was pinned on-chain at publish time; the secret must match
    /// the `guardian_btc_public_key` recorded in `Config`. Omit only for
    /// dev paths that don't pin the pubkey upfront.
    #[arg(long, env = "HASHI_MASTER_SECRET_HEX")]
    master_secret_hex: Option<String>,
}

pub async fn run(args: Args, onchain_state: &OnchainState) -> Result<()> {
    // AWS creds stay env-only — passing them as CLI flags would leak via `ps`.
    let bucket = required_env("AWS_S3_BUCKET")?;
    let region = required_env("AWS_REGION")?;
    let access_key = required_env("AWS_ACCESS_KEY_ID")?;
    let secret_key = required_env("AWS_SECRET_ACCESS_KEY")?;
    let network = parse_network(&args.bitcoin_network)?;

    let committee = onchain_state
        .current_committee()
        .ok_or_else(|| anyhow!("no current committee on chain (DKG not yet complete?)"))?;
    let committee_epoch = committee.epoch();
    tracing::info!(
        committee_epoch,
        committee_total_weight = committee.total_weight(),
        num_members = committee.members().len(),
        "fetched on-chain committee"
    );

    let mut rng = thread_rng();
    let n = args.num_shares;
    let t = args.threshold;
    let existing_secret = args
        .master_secret_hex
        .as_deref()
        .map(parse_master_secret)
        .transpose()?;
    let material = generate_share_material(n, t, &mut rng, existing_secret)?;
    tracing::info!(master_pubkey = %hex::encode(material.master_pubkey.serialize()),
        n, t, "generated share material");

    // Derived key must match the pubkey pinned on-chain at publish; a wrong or
    // missing --master-secret-hex would otherwise provision a key the chain rejects.
    let onchain_btc_pubkey = onchain_state.guardian_btc_public_key();
    if let Some(onchain) = onchain_btc_pubkey {
        let derived = material.master_pubkey.serialize();
        anyhow::ensure!(
            derived.as_slice() == onchain.as_slice(),
            "derived master pubkey {} does not match on-chain \
             guardian_btc_public_key {}; check HASHI_MASTER_SECRET_HEX",
            hex::encode(derived),
            hex::encode(&onchain),
        );
        tracing::info!("master pubkey matches on-chain guardian_btc_public_key");
    }

    let mut client = GuardianServiceClient::connect(args.guardian_endpoint.clone())
        .await
        .with_context(|| format!("connect to guardian at {}", args.guardian_endpoint))?;

    let secret_sharing_instance = SecretSharingInstance::new(material.commitments.clone(), n, t, 0)
        .map_err(|e| anyhow!("build SecretSharingInstance: {e:?}"))?;
    let operator_init_req = pb::OperatorInitRequest {
        s3_config: Some(pb::S3Config {
            access_key: Some(access_key),
            secret_key: Some(secret_key),
            bucket_name: Some(bucket.clone()),
            region: Some(region.clone()),
        }),
        secret_sharing_instance: Some(secret_sharing_instance_to_pb(&secret_sharing_instance)),
        network: Some(network as i32),
    };
    tracing::info!("calling OperatorInit");
    client
        .operator_init(operator_init_req)
        .await
        .context("OperatorInit RPC failed")?;

    let info_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    let resp = GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    let session_id = session_id_from_signing_pubkey(&resp.signing_pub_key);

    // Verify the enclave's own signature on the info — without this the
    // `encryption_pubkey` below would be unauthenticated and a buggy or
    // hostile endpoint could trick us into encrypting shares to a key it
    // controls.
    //
    // TODO: also authenticate `signing_pub_key` against the AWS Nitro
    // attestation once the guardian runs in an enclave. Today
    // `hashi_types::guardian::verify_enclave_attestation` is a no-op, so a
    // malicious operator with their own signing key can pass all the
    // checks below (sign their own GuardianInfo, echo the bucket and
    // commitments we just submitted, return their own encryption key) and
    // capture `t` encrypted shares. The current deployment runs the
    // guardian in a k8s cluster — the attestation gate lands when we move
    // to Nitro.
    let info = resp
        .signed_info
        .verify(&resp.signing_pub_key)
        .map_err(|e| anyhow!("verify GuardianInfo signature (session={session_id}): {e:?}"))?;

    // Match against what we just sent in OperatorInit. Catches a stale or
    // wrong enclave echoing back a different config than the one we set up.
    let returned_bucket = info.bucket_info.as_ref().ok_or_else(|| {
        anyhow!("guardian info missing bucket_info; OperatorInit may have silently failed")
    })?;
    anyhow::ensure!(
        returned_bucket.bucket == bucket && returned_bucket.region == region,
        "bucket mismatch: submitted {region}/{bucket}, guardian echoed {}/{}",
        returned_bucket.region,
        returned_bucket.bucket,
    );
    let returned_instance = info
        .secret_sharing_instance
        .as_ref()
        .ok_or_else(|| anyhow!("guardian info missing secret_sharing_instance"))?;
    anyhow::ensure!(
        *returned_instance.commitments() == material.commitments
            && returned_instance.num_shares() == n
            && returned_instance.threshold() == t
            && returned_instance.sharing_seq() == 0,
        "secret-sharing instance mismatch: guardian echoed different scheme than was submitted"
    );

    let enc_pubkey = EncPubKey::from_bytes(&info.encryption_pubkey)
        .map_err(|e| anyhow!("decode guardian encryption pubkey (session={session_id}): {e:?}"))?;
    tracing::info!(session_id = %session_id, "guardian info verified");

    let limiter_config = LimiterConfig {
        refill_rate: args.refill_rate_sats_per_sec,
        max_bucket_capacity: args.max_bucket_capacity_sats,
    };
    let limiter_state = LimiterState::genesis(&limiter_config);
    // The bootstrap utility builds the guardian's BTC keypair from a fresh
    // bitcoin-lib keypair, which always signs against the even-y projection
    // of its pubkey. Reconstruct the matching `G` point so downstream
    // derivations agree on y-parity.
    let master_g = HashiMasterG::with_even_y_from_x_be_bytes(&material.master_pubkey.serialize())
        .map_err(|e| anyhow!("convert master pubkey to G: {e:?}"))?;
    let state = ProvisionerInitState::new(committee, limiter_config, limiter_state, master_g)
        .map_err(|e| anyhow!("build ProvisionerInitState: {e:?}"))?;

    for (i, share) in material.shares.iter().take(t).enumerate() {
        tracing::info!("submitting ProvisionerInit share {}/{t}", i + 1);
        let req = ProvisionerInitRequest::build_from_share_and_state(
            share,
            &enc_pubkey,
            state.clone(),
            &mut rng,
        );
        let pb_req = provisioner_init_request_to_pb(req)
            .map_err(|e| anyhow!("encode ProvisionerInitRequest: {e:?}"))?;
        client
            .provisioner_init(pb_req)
            .await
            .with_context(|| format!("ProvisionerInit share {} RPC failed", i + 1))?;
    }

    // Pin: confirm we're still talking to the same enclave session we set up.
    // If the guardian restarted between OperatorInit and now, the new session
    // would have a different signing key — and the shares we just submitted
    // would belong to a session that no longer exists.
    let post_resp_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("post-ProvisionerInit GetGuardianInfo RPC failed")?
        .into_inner();
    let post_resp = GetGuardianInfoResponse::try_from(post_resp_pb)
        .map_err(|e| anyhow!("decode post-ProvisionerInit GetGuardianInfoResponse: {e:?}"))?;
    let post_session_id = session_id_from_signing_pubkey(&post_resp.signing_pub_key);
    anyhow::ensure!(
        post_session_id == session_id,
        "guardian session changed mid-bootstrap: started {session_id}, now {post_session_id} \
         (enclave likely restarted; rerun bootstrap)"
    );

    println!("Guardian fully initialized.");
    println!("  session_id:               {session_id}");
    println!(
        "  master pubkey:            {}",
        hex::encode(material.master_pubkey.serialize())
    );
    println!("  committee_epoch:          {committee_epoch}");
    println!(
        "  refill_rate_sats_per_sec: {}",
        args.refill_rate_sats_per_sec
    );
    println!(
        "  max_bucket_capacity_sats: {}",
        args.max_bucket_capacity_sats
    );
    Ok(())
}

struct ShareMaterial {
    shares: Vec<Share>,
    commitments: ShareCommitments,
    master_pubkey: BitcoinPubkey,
}

/// Fresh BTC master key + Shamir shares + matching commitments, all in memory.
/// `master_pubkey` is the x-only key the guardian reconstructs from any `t`
/// shares out of `n`. When `existing_secret` is `Some`, the shares are split
/// from that secret so the resulting `master_pubkey` matches whatever was
/// already pinned on-chain at publish time.
fn generate_share_material<R: CryptoRng + RngCore>(
    n: usize,
    t: usize,
    rng: &mut R,
    existing_secret: Option<k256::SecretKey>,
) -> Result<ShareMaterial> {
    let k256_sk = existing_secret.unwrap_or_else(|| k256::SecretKey::random(&mut *rng));

    let params =
        SecretSharingParams::new(n, t).map_err(|e| anyhow!("invalid sharing params: {e:?}"))?;
    let shares = split_secret(&k256_sk, &params, rng);
    let commitments_vec: Vec<ShareCommitment> = shares.iter().map(commit_share).collect();
    let commitments =
        ShareCommitments::new(commitments_vec).expect("commitments built from a valid share set");

    let secp = Secp256k1::new();
    let btc_sk = BtcSecretKey::from_slice(&k256_sk.to_bytes())
        .expect("k256 secret key bytes are a valid secp256k1 secret");
    let keypair = Keypair::from_secret_key(&secp, &btc_sk);
    let (master_pubkey, _parity) = keypair.x_only_public_key();

    Ok(ShareMaterial {
        shares,
        commitments,
        master_pubkey,
    })
}

fn parse_master_secret(hex_str: &str) -> Result<k256::SecretKey> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .context("invalid hex for --master-secret-hex")?;
    anyhow::ensure!(
        bytes.len() == 32,
        "--master-secret-hex must decode to 32 bytes, got {}",
        bytes.len(),
    );
    k256::SecretKey::from_slice(&bytes)
        .map_err(|e| anyhow!("--master-secret-hex is not a valid secp256k1 scalar: {e}"))
}

fn required_env(name: &str) -> Result<String> {
    env::var(name).map_err(|_| anyhow!("required env var `{name}` is not set"))
}

fn parse_network(s: &str) -> Result<pb::Network> {
    pb::Network::from_str_name(&s.to_ascii_uppercase()).ok_or_else(|| {
        anyhow!("unknown BITCOIN_NETWORK `{s}`; expected mainnet/testnet/regtest/signet")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::crypto::combine_shares;
    use hashi_types::guardian::crypto::k256_sk_to_btc_keypair;

    #[test]
    fn generated_shares_reconstruct_to_master_pubkey() {
        const TEST_N: usize = 5;
        const TEST_T: usize = 3;
        let mut rng = rand::thread_rng();
        let material = generate_share_material(TEST_N, TEST_T, &mut rng, None).unwrap();

        assert_eq!(material.shares.len(), TEST_N);
        let subset = &material.shares[..TEST_T];
        let reconstructed_sk = combine_shares(subset, TEST_T).expect("threshold shares combine");
        let reconstructed_kp = k256_sk_to_btc_keypair(&reconstructed_sk);
        let (reconstructed_xonly, _) = reconstructed_kp.x_only_public_key();
        assert_eq!(reconstructed_xonly, material.master_pubkey);
    }

    #[test]
    fn pre_supplied_secret_round_trips_through_shares() {
        const TEST_N: usize = 5;
        const TEST_T: usize = 3;
        let mut rng = rand::thread_rng();
        let secret = k256::SecretKey::random(&mut rng);
        let expected_xonly = {
            let secp = Secp256k1::new();
            let sk = BtcSecretKey::from_slice(&secret.to_bytes()).unwrap();
            Keypair::from_secret_key(&secp, &sk).x_only_public_key().0
        };

        let material =
            generate_share_material(TEST_N, TEST_T, &mut rng, Some(secret.clone())).unwrap();
        assert_eq!(material.master_pubkey, expected_xonly);

        let subset = &material.shares[..TEST_T];
        let reconstructed = combine_shares(subset, TEST_T).expect("threshold shares combine");
        let reconstructed_kp = k256_sk_to_btc_keypair(&reconstructed);
        let (reconstructed_xonly, _) = reconstructed_kp.x_only_public_key();
        assert_eq!(reconstructed_xonly, expected_xonly);
    }

    #[test]
    fn parse_master_secret_accepts_0x_prefix() {
        let hex = "0x".to_string() + &"11".repeat(32);
        let sk = parse_master_secret(&hex).unwrap();
        assert_eq!(sk.to_bytes().as_slice(), [0x11u8; 32].as_slice());
    }

    #[test]
    fn parse_master_secret_rejects_wrong_length() {
        let err = parse_master_secret(&"ab".repeat(31)).unwrap_err();
        assert!(format!("{err}").contains("32 bytes"));
    }
}
