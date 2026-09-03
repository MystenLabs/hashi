// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `operator rotate-kp-set`: re-deal the ceremony key to a new KP set on a
//! fresh ceremony-mode guardian.
//!
//! `init` operator-initializes the guardian and pins its session; the current
//! KPs then each sign a submission for it (`key-provisioner rotate-kp-set`).
//! `submit` batches threshold-many submissions into one `RotateKpSet`, checks
//! the returned shares and the `ceremony/` + `kp-shares/` logs the guardian
//! wrote, and waits for every new KP to confirm (`key-provisioner ceremony`),
//! exactly as `operator ceremony` does after `SetupNewKey`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_types::guardian::BatchProvisionerRotateKpSetRequest;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::CeremonyStage;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::GuardianSignedResponse;
use hashi_types::guardian::KpCertRoster;
use hashi_types::guardian::KpShareStateLogMessage;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::ProvisionerRotateKpSetRequest;
use hashi_types::guardian::RotateKpSetResponse;
use hashi_types::guardian::SecretSharingParams;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::proto_conversions::batch_provisioner_rotate_kp_set_request_to_pb;
use tracing::info;

use crate::ceremony::CeremonyGuardian;
use crate::config::Config;
use crate::submission;

/// Operator-initialize the ceremony guardian the current KPs will sign for.
pub async fn init(cfg: Config) -> Result<()> {
    cfg.kp_roster.validate()?;
    let new_kp_set = cfg.require_new_kp_roster("operator rotate-kp-set")?;
    new_kp_set.validate()?;
    let guardian_s3 = hashi_guardian::resolve_s3_config(&cfg.guardian_s3).await?;
    let certs_roster = cfg.kp_roster.load_certs_roster()?;
    let new_certs_roster = new_kp_set.load_certs_roster()?;

    let mut guardian = CeremonyGuardian::init(&cfg, &guardian_s3).await?;
    ensure!(
        guardian.lifecycle == CeremonyStage::OperatorInitialized.into(),
        "guardian lifecycle is {:?}; a rotation was already submitted to it",
        guardian.lifecycle
    );
    let live = guardian.live_info().await?;

    let state = guardian.reader.read_latest_ceremony_state().await?;
    state.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
    state.encrypted_shares.verify_recipients(&certs_roster)?;
    let sharing_seq = state.secret_sharing_instance.sharing_seq();
    let threshold = state.secret_sharing_instance.threshold();
    info!(
        phase = "summary",
        session_id = %guardian.session_id,
        sharing_seq,
        threshold,
        new_num_shares = new_kp_set.num_shares,
        new_threshold = new_kp_set.threshold,
        "ceremony guardian ready for the current KPs' rotation submissions",
    );
    println!("Ceremony guardian initialized for a KP-set rotation.");
    println!("  session_id:     {}", guardian.session_id);
    println!(
        "  enc_pubkey:     {}",
        hex::encode(&live.info.encryption_pubkey)
    );
    println!("  sharing_seq:    {sharing_seq} -> {}", sharing_seq + 1);
    println!(
        "  current set:    {threshold}-of-{}",
        state.secret_sharing_instance.num_shares()
    );
    println!(
        "  new set:        {}-of-{}",
        new_kp_set.threshold, new_kp_set.num_shares
    );
    for (index, fingerprint) in new_certs_roster.fingerprints().iter().enumerate() {
        println!("    share {}: {fingerprint}", index + 1);
    }
    println!("Need {threshold} submissions from the current KPs (key-provisioner rotate-kp-set).");
    Ok(())
}

/// Submit threshold-many current-KP submissions, verify what the guardian
/// dealt, and wait for every new KP's confirmation.
pub async fn submit(cfg: Config, submission_paths: &[PathBuf]) -> Result<()> {
    cfg.kp_roster.validate()?;
    let new_kp_set = cfg.require_new_kp_roster("operator rotate-kp-set")?;
    new_kp_set.validate()?;
    let guardian_s3 = hashi_guardian::resolve_s3_config(&cfg.guardian_s3).await?;
    let allowlist = cfg.kp_roster.pcr_allowlist();
    let certs_roster = cfg.kp_roster.load_certs_roster()?;
    let new_certs_roster = new_kp_set.load_certs_roster()?;
    let new_params = new_kp_set.params()?;

    let mut guardian = CeremonyGuardian::init(&cfg, &guardian_s3).await?;
    let new_instance = if guardian.lifecycle == CeremonyStage::OperatorInitialized.into() {
        // The dealt set, as the enclave will read it with the KPs' allowlist.
        let old = guardian.reader.read_latest_ceremony_state().await?;
        old.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
        old.encrypted_shares.verify_recipients(&certs_roster)?;
        let new_sharing_seq = old.secret_sharing_instance.sharing_seq() + 1;

        let submissions = submission_paths
            .iter()
            .map(|path| submission::read(path).map(|signed| (path.display().to_string(), signed)))
            .collect::<Result<Vec<_>>>()?;
        let batch = validate_batch(
            submissions,
            &old,
            &Proposal {
                session_id: &guardian.session_id,
                pcr_allowlist: &allowlist,
                new_certs_roster: &new_certs_roster,
                new_params,
            },
        )?;

        info!(
            phase = "rotate_kp_set",
            submissions = batch.submissions().len(),
            new_sharing_seq,
            "calling RotateKpSet",
        );
        let response_pb = guardian
            .client
            .rotate_kp_set(batch_provisioner_rotate_kp_set_request_to_pb(batch))
            .await
            .context("RotateKpSet RPC failed")?
            .into_inner();
        let response = GuardianSignedResponse::<RotateKpSetResponse>::try_from(response_pb)
            .map_err(|e| anyhow!("decode SignedRotateKpSetResponse: {e:?}"))?
            .verify_into_data(&guardian.signing_pub_key)
            .map_err(|e| anyhow!("verify RotateKpSetResponse signature: {e}"))?
            .response;
        ensure!(
            response.new_instance.sharing_seq() == new_sharing_seq,
            "RotateKpSet returned sharing_seq {}, expected {new_sharing_seq}",
            response.new_instance.sharing_seq()
        );
        response
            .encrypted_shares
            .verify_recipients(&new_certs_roster)?;
        info!(
            phase = "rotate_kp_set",
            share_count = response.encrypted_shares.share_count(),
            "every re-encrypted share verified against the new KP certs (without decrypting)",
        );

        // The state the new KPs will read, verify and confirm.
        let live = CeremonyState::new(
            CeremonyLogMessage::Rotate {
                old_instance: old.secret_sharing_instance,
                new_instance: response.new_instance,
                btc_master_pubkey: old.btc_master_pubkey,
            },
            KpShareStateLogMessage::new(new_sharing_seq, 0, response.encrypted_shares),
        )?;
        live.validate_sharing_params(new_kp_set.num_shares, new_kp_set.threshold)?;
        guardian
            .verify_published(&live, new_kp_set.num_shares, new_kp_set.threshold)
            .await?;
        live.secret_sharing_instance
    } else {
        // An earlier run's batch was accepted; only the wait remains.
        info!(
            phase = "rotate_kp_set",
            lifecycle = ?guardian.lifecycle,
            "rotation already submitted to this guardian; verifying its logs",
        );
        let logged = guardian
            .reader
            .read_latest_ceremony_state_from_current_build()
            .await?;
        logged.validate_sharing_params(new_kp_set.num_shares, new_kp_set.threshold)?;
        logged
            .encrypted_shares
            .verify_recipients(&new_certs_roster)?;
        logged.secret_sharing_instance
    };

    guardian.wait_for_confirmations().await?;

    info!(
        phase = "summary",
        sharing_seq = new_instance.sharing_seq(),
        n = new_instance.num_shares(),
        t = new_instance.threshold(),
        "KP-set rotation complete",
    );
    for commitment in new_instance.commitments().iter() {
        info!(
            phase = "summary",
            share_id = commitment.id.get(),
            commitment = hex::encode(&commitment.digest),
            "share commitment",
        );
    }
    println!("KP-set rotation complete.");
    println!("  sharing_seq:    {}", new_instance.sharing_seq());
    println!(
        "  new set:        {}-of-{}",
        new_instance.threshold(),
        new_instance.num_shares()
    );
    Ok(())
}

/// What every submission must be signed over: the pinned session and the
/// proposal from this config.
struct Proposal<'a> {
    session_id: &'a SessionID,
    pcr_allowlist: &'a PcrAllowlist,
    new_certs_roster: &'a KpCertRoster,
    new_params: SecretSharingParams,
}

/// The checks the enclave repeats, run first so a bad file is named:
/// signature, session, the signer's share assignment in the dealt set, one
/// submission per share, agreement with the proposal, and the old threshold.
fn validate_batch(
    submissions: Vec<(String, KpSigned<ProvisionerRotateKpSetRequest>)>,
    old: &CeremonyState,
    proposal: &Proposal<'_>,
) -> Result<BatchProvisionerRotateKpSetRequest> {
    let mut share_ids = BTreeSet::new();
    let mut verified = Vec::with_capacity(submissions.len());
    for (label, signed) in submissions {
        let signer = signed.signer_fingerprint().to_hex();
        let request = signed
            .verify_signature()
            .map_err(|e| anyhow!("{label}: {e}"))?;
        ensure!(
            request.expected_session_id() == proposal.session_id,
            "{label}: signed for guardian session {}, the pinned session is {}",
            request.expected_session_id(),
            proposal.session_id
        );
        let share_id = request.encrypted_old_share().id;
        old.encrypted_shares
            .validate_share_assignment(&signer, share_id)
            .with_context(|| format!("{label}: signer {signer}"))?;
        ensure!(
            share_ids.insert(share_id),
            "{label}: share id {} was already submitted",
            share_id.get()
        );
        ensure!(
            request.pcr_allowlist() == proposal.pcr_allowlist,
            "{label}: PCR allowlist differs from this config's"
        );
        ensure!(
            request.new_kp_certs_roster() == proposal.new_certs_roster,
            "{label}: proposed KP roster differs from this config's new_kp_roster"
        );
        ensure!(
            *request.new_params() == proposal.new_params,
            "{label}: proposed sharing params differ from this config's new_kp_roster"
        );
        info!(
            phase = "submissions",
            submission = %label,
            share_id = share_id.get(),
            signer_fingerprint = %signer,
            "verified rotation submission",
        );
        verified.push(signed);
    }
    let threshold = old.secret_sharing_instance.threshold();
    ensure!(
        verified.len() >= threshold,
        "{} submissions; the current KP set's threshold is {threshold}",
        verified.len()
    );
    BatchProvisionerRotateKpSetRequest::new(verified)
        .map_err(|e| anyhow!("build RotateKpSet batch: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::BuildPcrs;
    use hashi_types::guardian::Ciphertext;
    use hashi_types::guardian::GuardianEncryptedShare;
    use hashi_types::guardian::KpEncryptedShare;
    use hashi_types::guardian::KpEncryptedShareRoster;
    use hashi_types::guardian::SecretSharingInstance;
    use hashi_types::guardian::ShareCommitments;
    use hashi_types::guardian::ShareID;
    use hashi_types::guardian::crypto::k256_sk_to_btc_xonly_pubkey;
    use hashi_types::guardian::crypto::split_secret;
    use hashi_types::guardian::test_utils::mock_kp_certs_roster;
    use hashi_types::pgp::PgpPublicCert;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;

    const OLD_N: usize = 3;
    const OLD_T: usize = 2;

    struct Fixture {
        old: CeremonyState,
        /// The dealt KPs' (cert, secret), share id `index + 1`.
        kps: Vec<(PgpPublicCert, String)>,
        session_id: SessionID,
        pcr_allowlist: PcrAllowlist,
        new_certs_roster: KpCertRoster,
        new_params: SecretSharingParams,
    }

    impl Fixture {
        fn new() -> Self {
            let sk = k256::SecretKey::random(&mut rand::thread_rng());
            let params = SecretSharingParams::new(OLD_N, OLD_T).unwrap();
            let shares = split_secret(&sk, &params, &mut rand::thread_rng());
            let kps = (0..OLD_N)
                .map(|_| {
                    let (cert, secret) = mock_pgp_keypair();
                    (PgpPublicCert::new(cert).unwrap(), secret)
                })
                .collect::<Vec<_>>();
            let encrypted_shares = KpEncryptedShareRoster::new(
                kps.iter()
                    .enumerate()
                    .map(|(index, (cert, _))| KpEncryptedShare {
                        id: ShareID::new((index + 1) as u16).unwrap(),
                        recipient_fingerprint: cert.fingerprint().to_hex(),
                        armored_ciphertext: "dummy".into(),
                    })
                    .collect(),
            )
            .unwrap();
            Self {
                old: CeremonyState {
                    secret_sharing_instance: SecretSharingInstance::new(
                        ShareCommitments::from_shares(&shares).unwrap(),
                        OLD_N,
                        OLD_T,
                        4,
                    )
                    .unwrap(),
                    btc_master_pubkey: k256_sk_to_btc_xonly_pubkey(&sk),
                    cert_seq: 0,
                    encrypted_shares,
                },
                kps,
                session_id: "session".into(),
                pcr_allowlist: PcrAllowlist::new(BuildPcrs::new("test", vec![0]), []).unwrap(),
                new_certs_roster: mock_kp_certs_roster(4),
                new_params: SecretSharingParams::new(4, 3).unwrap(),
            }
        }

        fn proposal(&self) -> Proposal<'_> {
            Proposal {
                session_id: &self.session_id,
                pcr_allowlist: &self.pcr_allowlist,
                new_certs_roster: &self.new_certs_roster,
                new_params: self.new_params,
            }
        }

        fn request(&self, share_id: u16) -> ProvisionerRotateKpSetRequest {
            ProvisionerRotateKpSetRequest::new(
                self.session_id.clone(),
                self.pcr_allowlist.clone(),
                GuardianEncryptedShare {
                    id: ShareID::new(share_id).unwrap(),
                    ciphertext: Ciphertext {
                        encapsulated_key: vec![1, 2, 3],
                        aes_ciphertext: vec![4, 5, 6],
                    },
                },
                self.new_certs_roster.clone(),
                self.new_params.num_shares(),
                self.new_params.threshold(),
            )
            .unwrap()
        }

        /// KP `signer` (0-based) signs `request`.
        fn signed(
            &self,
            signer: usize,
            request: ProvisionerRotateKpSetRequest,
        ) -> (String, KpSigned<ProvisionerRotateKpSetRequest>) {
            let (cert, secret) = &self.kps[signer];
            let signature = sign_detached_in_process(secret, &KpSigned::signed_bytes(&request));
            (
                format!("kp{}.rotation", signer + 1),
                KpSigned::from_parts(request, cert.clone(), signature),
            )
        }

        /// KP `signer` signs for its own share.
        fn submission(&self, signer: usize) -> (String, KpSigned<ProvisionerRotateKpSetRequest>) {
            self.signed(signer, self.request(signer as u16 + 1))
        }
    }

    #[test]
    fn accepts_threshold_many_valid_submissions() {
        let f = Fixture::new();
        let batch = validate_batch(
            vec![f.submission(0), f.submission(2)],
            &f.old,
            &f.proposal(),
        )
        .unwrap();
        assert_eq!(batch.submissions().len(), 2);
    }

    #[test]
    fn rejects_below_threshold() {
        let f = Fixture::new();
        let err = validate_batch(vec![f.submission(1)], &f.old, &f.proposal()).unwrap_err();
        assert!(err.to_string().contains("threshold is 2"), "{err}");
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let f = Fixture::new();
        let (label, mut signed) = f.submission(0);
        signed.signature = "invalid signature".into();
        let err = validate_batch(
            vec![(label, signed), f.submission(1)],
            &f.old,
            &f.proposal(),
        )
        .unwrap_err();
        assert!(err.to_string().starts_with("kp1.rotation:"), "{err}");
    }

    #[test]
    fn rejects_another_session() {
        let f = Fixture::new();
        let mut other = Fixture::new();
        other.session_id = "other-session".into();
        let err = validate_batch(
            vec![f.submission(0), f.submission(1)],
            &f.old,
            &other.proposal(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("pinned session is other-session"),
            "{err}"
        );
    }

    #[test]
    fn rejects_a_signer_not_assigned_to_the_share() {
        let f = Fixture::new();
        let err = validate_batch(
            vec![f.signed(0, f.request(2)), f.submission(1)],
            &f.old,
            &f.proposal(),
        )
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.starts_with("kp1.rotation:"), "{message}");
        assert!(message.contains("assigned share id 1"), "{message}");
    }

    #[test]
    fn rejects_a_signer_outside_the_dealt_set() {
        let f = Fixture::new();
        let (cert, secret) = mock_pgp_keypair();
        let request = f.request(1);
        let signature = sign_detached_in_process(&secret, &KpSigned::signed_bytes(&request));
        let stranger = KpSigned::from_parts(request, PgpPublicCert::new(cert).unwrap(), signature);
        let err = validate_batch(
            vec![("stranger".into(), stranger), f.submission(1)],
            &f.old,
            &f.proposal(),
        )
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("not present in the encrypted-share roster"),
            "{message}"
        );
    }

    #[test]
    fn rejects_a_share_submitted_twice() {
        let f = Fixture::new();
        let err = validate_batch(
            vec![f.submission(0), f.submission(0)],
            &f.old,
            &f.proposal(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("share id 1 was already submitted"),
            "{err}"
        );
    }

    #[test]
    fn rejects_a_proposal_that_differs_from_the_config() {
        let f = Fixture::new();
        let mut config = Fixture::new();
        config.new_certs_roster = mock_kp_certs_roster(4);
        let err = validate_batch(
            vec![f.submission(0), f.submission(1)],
            &f.old,
            &config.proposal(),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("differs from this config's new_kp_roster"),
            "{err}"
        );

        let mut config = Fixture::new();
        config.new_params = SecretSharingParams::new(4, 2).unwrap();
        config.new_certs_roster = f.new_certs_roster.clone();
        let err = validate_batch(
            vec![f.submission(0), f.submission(1)],
            &f.old,
            &config.proposal(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("sharing params differ"), "{err}");

        let mut config = Fixture::new();
        config.pcr_allowlist = PcrAllowlist::new(BuildPcrs::new("other", vec![1]), []).unwrap();
        config.new_certs_roster = f.new_certs_roster.clone();
        let err = validate_batch(
            vec![f.submission(0), f.submission(1)],
            &f.old,
            &config.proposal(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("PCR allowlist differs"), "{err}");
    }
}
