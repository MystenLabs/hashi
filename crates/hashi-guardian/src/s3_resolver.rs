// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Client-local S3 routing through the enclave's existing VSOCK forwarders.

use aws_smithy_runtime_api::client::dns::DnsFuture;
use aws_smithy_runtime_api::client::dns::ResolveDns;
use aws_smithy_runtime_api::client::dns::ResolveDnsError;
use hashi_types::guardian::S3BucketInfo;
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub(crate) struct EnclaveS3Resolver {
    hosts: BTreeMap<String, IpAddr>,
}

impl EnclaveS3Resolver {
    pub(crate) fn new(bucket: &S3BucketInfo) -> Self {
        // These IPs reach the S3 forwarders in docker/hashi-guardian/run.sh;
        // keep the mappings in sync with that script.
        Self {
            hosts: BTreeMap::from([
                (
                    format!("s3.{}.amazonaws.com", bucket.region),
                    IpAddr::from([127, 0, 0, 64]),
                ),
                (
                    format!("{}.s3.{}.amazonaws.com", bucket.name, bucket.region),
                    IpAddr::from([127, 0, 0, 65]),
                ),
                ("s3.amazonaws.com".into(), IpAddr::from([127, 0, 0, 66])),
            ]),
        }
    }
}

impl ResolveDns for EnclaveS3Resolver {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        DnsFuture::ready(
            self.hosts
                .get(name)
                .copied()
                .map(|ip| vec![ip])
                .ok_or_else(|| {
                    ResolveDnsError::new(format!("unmapped enclave S3 hostname: {name}"))
                }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn routes_only_the_configured_s3_endpoints() {
        let resolver = EnclaveS3Resolver::new(&S3BucketInfo {
            name: "guardian-logs".into(),
            region: "us-west-2".into(),
        });
        for (name, suffix) in [
            ("s3.us-west-2.amazonaws.com", 64),
            ("guardian-logs.s3.us-west-2.amazonaws.com", 65),
            ("s3.amazonaws.com", 66),
        ] {
            assert_eq!(
                resolver.resolve_dns(name).await.unwrap(),
                vec![IpAddr::from([127, 0, 0, suffix])]
            );
        }
        for name in [
            "other.s3.us-west-2.amazonaws.com",
            "s3.us-east-1.amazonaws.com",
            "example.com",
        ] {
            assert!(resolver.resolve_dns(name).await.is_err());
        }
        let next = EnclaveS3Resolver::new(&S3BucketInfo {
            name: "other".into(),
            region: "us-east-1".into(),
        });
        assert!(next
            .resolve_dns("other.s3.us-east-1.amazonaws.com")
            .await
            .is_ok());
        assert!(resolver
            .resolve_dns("other.s3.us-east-1.amazonaws.com")
            .await
            .is_err());
    }
}
