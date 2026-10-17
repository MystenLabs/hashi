// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A current KP's signed rotation submission, carried to the operator as a
//! file: the prost-encoded wire message, decoded with the conversion the
//! enclave applies. It holds nothing secret.

use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use aws_credential_types::CredentialsBuilder;
use aws_sdk_s3::config::BehaviorVersion;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::error::DisplayErrorContext;
use aws_sdk_s3::primitives::ByteStream;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::ProvisionerRotateKpSetRequest;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Credentials;
use hashi_types::guardian::SessionID;
use hashi_types::proto as pb;
use prost::Message;

/// Where submissions go in the KP bucket, under the session they sign for.
/// KP uploads otherwise go under user IDs, which never start with `_`.
pub const BUCKET_PREFIX: &str = "_rotate-kp-set";

pub fn encode(signed: KpSigned<ProvisionerRotateKpSetRequest>) -> Vec<u8> {
    pb::SignedProvisionerRotateKpSetRequest::from(signed).encode_to_vec()
}

pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)
        .with_context(|| format!("write rotation submission to {}", path.display()))
}

pub fn read(path: &Path) -> Result<KpSigned<ProvisionerRotateKpSetRequest>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read rotation submission at {}", path.display()))?;
    let message = pb::SignedProvisionerRotateKpSetRequest::decode(bytes.as_slice())
        .with_context(|| format!("decode rotation submission at {}", path.display()))?;
    KpSigned::try_from(message)
        .map_err(|e| anyhow!("invalid rotation submission at {}: {e}", path.display()))
}

/// The KP-bucket key of a signer's submission for a session.
pub fn bucket_key(session_id: &SessionID, signer_fingerprint: &str) -> String {
    format!("{BUCKET_PREFIX}/{session_id}/{signer_fingerprint}.rotation")
}

/// A client for the KP bucket with only the config's credentials: like
/// download-config.sh, it reads no other AWS configuration on this machine.
pub fn kp_bucket_client(bucket: &S3BucketInfo, credentials: &S3Credentials) -> aws_sdk_s3::Client {
    let mut creds = CredentialsBuilder::default()
        .access_key_id(credentials.access_key.clone())
        .secret_access_key(credentials.secret_key.clone())
        .provider_name("hashi-guardian-init");
    creds.set_session_token(credentials.session_token.clone());
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(bucket.region.clone()))
        .credentials_provider(creds.build())
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

pub async fn upload(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    bytes: Vec<u8>,
) -> Result<()> {
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_type("application/octet-stream")
        .body(ByteStream::from(bytes))
        .send()
        .await
        .map_err(|e| anyhow!("upload to s3://{bucket}/{key}: {}", DisplayErrorContext(e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_smithy_mocks::RuleMode;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;

    #[test]
    fn rejects_a_file_that_is_not_a_submission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage");
        std::fs::write(&path, b"not a submission").unwrap();
        assert!(read(&path).is_err());
        assert!(read(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn keys_a_submission_by_session_and_signer() {
        let session_id = SessionID::from("0123456789abcdef");
        assert_eq!(
            bucket_key(&session_id, "0123456789ABCDEF0123456789ABCDEF01234567"),
            "_rotate-kp-set/0123456789abcdef/0123456789ABCDEF0123456789ABCDEF01234567.rotation"
        );
    }

    #[tokio::test]
    async fn uploads_the_submission_bytes_to_its_key() {
        let put = mock!(aws_sdk_s3::Client::put_object)
            .match_requests(|req| {
                req.bucket() == Some("kp-bucket")
                    && req.key() == Some("_rotate-kp-set/s/F.rotation")
                    && req.body().bytes() == Some(b"submission".as_slice())
            })
            .then_output(|| PutObjectOutput::builder().build());
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put]);
        upload(
            &client,
            "kp-bucket",
            "_rotate-kp-set/s/F.rotation",
            b"submission".to_vec(),
        )
        .await
        .unwrap();
        assert_eq!(put.num_calls(), 1);
    }

    #[tokio::test]
    async fn names_the_key_a_failed_upload_was_for() {
        let denied = mock!(aws_sdk_s3::Client::put_object)
            .sequence()
            .http_status(403, None)
            .build();
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&denied]);
        let error = upload(&client, "kp-bucket", "k", Vec::new())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("s3://kp-bucket/k"), "{error}");
    }
}
