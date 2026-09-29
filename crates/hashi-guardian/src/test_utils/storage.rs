// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! In-memory S3 read-back for tests that serve multiple withdrawals.

use super::*;
use aws_sdk_s3::operation::get_object::GetObjectOutput;
use aws_sdk_s3::operation::list_object_versions::ListObjectVersionsOutput;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::primitives::DateTime;
use aws_sdk_s3::types::CommonPrefix;
use aws_sdk_s3::types::ObjectLockMode;
use aws_sdk_s3::types::ObjectVersion;
use aws_sdk_s3::Client;
use aws_smithy_mocks::mock;
use aws_smithy_mocks::mock_client;
use aws_smithy_mocks::RuleMode;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Mutex;

/// Mock S3 storage supporting PutObject, GetObject and delimiter-aware listing.
/// Intended for one enclave's serialized writes; unlike S3 it does not model
/// conditional-write conflicts, deletion, or pagination.
pub fn mock_storage() -> GuardianS3Client {
    let records = Arc::new(Mutex::new(BTreeMap::<String, Vec<u8>>::new()));
    let writes = records.clone();
    let put = mock!(Client::put_object)
        .match_requests(move |req| {
            writes.lock().unwrap().insert(
                req.key().unwrap().to_owned(),
                req.body().bytes().unwrap().to_vec(),
            );
            true
        })
        .then_output(|| PutObjectOutput::builder().build());

    // The mocks API separates request matching from output construction. Build
    // each response in the predicate, then hand it to the output factory.
    let listing = Arc::new(Mutex::new(None));
    let listing_out = listing.clone();
    let listed = records.clone();
    let list = mock!(Client::list_object_versions)
        .match_requests(move |req| {
            let prefix = req.prefix().unwrap_or_default();
            let mut prefixes = BTreeSet::new();
            let mut versions = Vec::new();
            for key in listed.lock().unwrap().keys() {
                let Some(rest) = key.strip_prefix(prefix) else {
                    continue;
                };
                if let (Some("/"), Some(slash)) = (req.delimiter(), rest.find('/')) {
                    prefixes.insert(format!("{prefix}{}", &rest[..=slash]));
                    continue;
                }
                versions.push(ObjectVersion::builder().key(key).is_latest(true).build());
            }
            *listing.lock().unwrap() = Some(
                ListObjectVersionsOutput::builder()
                    .set_common_prefixes(Some(
                        prefixes
                            .into_iter()
                            .map(|p| CommonPrefix::builder().prefix(p).build())
                            .collect(),
                    ))
                    .set_versions(Some(versions))
                    .build(),
            );
            true
        })
        .then_output(move || listing_out.lock().unwrap().take().unwrap());

    let response = Arc::new(Mutex::new(None));
    let response_out = response.clone();
    let get = mock!(Client::get_object)
        .match_requests(move |req| {
            let records = records.lock().unwrap();
            let Some(body) = records.get(req.key().unwrap()) else {
                return false;
            };
            let record: LogRecord = serde_json::from_slice(body).unwrap();
            let policy = S3ObjectLockPolicy::for_environment(S3RetentionEnvironment::Testnet);
            *response.lock().unwrap() = Some(
                GetObjectOutput::builder()
                    .object_lock_mode(ObjectLockMode::Compliance)
                    .object_lock_retain_until_date(DateTime::from(
                        record.object_lock_expiry(policy),
                    ))
                    .body(ByteStream::from(body.clone()))
                    .build(),
            );
            true
        })
        .then_output(move || response_out.lock().unwrap().take().unwrap());
    GuardianS3Client::from_client(
        S3BucketInfo::mock_for_testing(),
        S3RetentionEnvironment::Testnet,
        mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put, &list, &get]),
    )
}

/// Write the initialization records that verified withdrawal read-back needs,
/// then install the serving state. Requires mock attestation verification
/// (`non-enclave-dev`), as this fixture does not have a Nitro-signed document.
pub async fn activate_enclave_with_logs_for_testing(
    enclave: &Arc<Enclave>,
    committee: HashiCommittee,
    limiter_config: LimiterConfig,
    limiter_state: LimiterState,
) -> GuardianResult<()> {
    let pending = enclave.temporary_init_state()?;
    let instance = pending.ceremony_state.secret_sharing_instance;
    let info = enclave.info().await;
    let activation = ActivationState::new(
        pending.config_hash,
        instance.clone(),
        committee.clone().into(),
        limiter_state,
    );
    let oi = OperatorInitInfo {
        deployment: enclave.config.deployment()?.clone(),
        encryption_pubkey: info.encryption_pubkey,
        mode: OperatorInitMode::Withdraw(Box::new(WithdrawOperatorInitInfo {
            secret_sharing_instance: instance.clone(),
            config_hash: pending.config_hash,
            limiter_config,
            hashi_object_id: info.hashi_object_id.unwrap(),
            mpc_master_g: info.mpc_master_g.unwrap(),
            genesis_state_hash: info.genesis_state_hash,
        })),
    };
    for message in [
        InitLogMessage::OIAttestationUnsigned {
            attestation: NitroAttestation::new(b"mock_attestation_document_hex".to_vec()),
            signing_public_key: enclave.signing_pubkey(),
        },
        InitLogMessage::OIGuardianInfo(Box::new(oi)),
        InitLogMessage::PIEnclaveFullyInitialized {
            sharing_seq: instance.sharing_seq(),
            share_ids: instance.commitments().iter().map(|c| c.id).collect(),
            enclave_btc_pubkey: info.enclave_btc_pubkey.unwrap(),
        },
        InitLogMessage::OAActivated {
            state_hash: activation.digest(),
            config_hash: pending.config_hash,
            sharing_seq: instance.sharing_seq(),
            committee_epoch: committee.epoch(),
            limiter_state,
        },
    ] {
        enclave.log_init(message).await?;
    }
    activate_enclave_for_testing(enclave, committee, limiter_config, limiter_state)
}
