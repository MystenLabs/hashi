// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::OnceLock;

pub(crate) const HEALTH_AND_REFLECTION_DECODE_LIMIT: usize = 4 * 1024 * 1024;

pub(crate) const SMALL_MPC_REQUEST_LIMIT: usize = 64 * 1024;

pub(crate) const SMALL_MPC_METHODS: [&str; 5] = [
    "GetPartialSignatures",
    "RetrieveMessages",
    "GetPublicMpcOutput",
    "GetReconfigCompletionSignature",
    "GetPresigDealerSetSignature",
];

pub(crate) const MPC_WORK_METHODS: [&str; 4] = [
    "SendMessages",
    "Complain",
    "RetrieveMessages",
    "GetPublicMpcOutput",
];

#[derive(Debug, Default)]
pub(crate) struct RouteLimits {
    services: HashMap<&'static str, usize>,
    methods: HashMap<String, usize>,
    mpc_work: HashSet<String>,
}

impl RouteLimits {
    pub(crate) fn service(&mut self, name: &'static str, limit: usize) -> usize {
        self.services.insert(name, limit);
        limit
    }

    pub(crate) fn method(&mut self, service: &'static str, method: &str, limit: usize) {
        self.methods.insert(format!("/{service}/{method}"), limit);
    }

    pub(crate) fn mpc_work(&mut self, service: &'static str, method: &str) {
        self.mpc_work.insert(format!("/{service}/{method}"));
    }

    pub(crate) fn mpc_work_paths(&self) -> impl Iterator<Item = &str> {
        self.mpc_work.iter().map(String::as_str)
    }

    pub(crate) fn has_service(&self, name: &str) -> bool {
        self.services.contains_key(name)
    }

    pub(crate) fn limit(&self, path: &str) -> Option<usize> {
        let service = self.services.get(service_of(path)?).copied()?;
        Some(
            self.methods
                .get(path)
                .map_or(service, |&method| method.min(service)),
        )
    }

    pub(crate) fn largest(&self) -> usize {
        self.services.values().copied().max().unwrap_or(0)
    }
}

fn service_of(path: &str) -> Option<&str> {
    let (service, _) = path.strip_prefix('/')?.split_once('/')?;
    Some(service)
}

pub(crate) struct GrpcMethod {
    pub(crate) path: Box<str>,
    pub(crate) client_streaming: bool,
}

pub(crate) fn grpc_methods() -> &'static [GrpcMethod] {
    static METHODS: OnceLock<Vec<GrpcMethod>> = OnceLock::new();
    METHODS.get_or_init(|| {
        use prost::Message as _;

        let mut methods = Vec::new();
        for encoded in [
            hashi_types::proto::FILE_DESCRIPTOR_SET,
            tonic_health::pb::FILE_DESCRIPTOR_SET,
            tonic_reflection::pb::v1::FILE_DESCRIPTOR_SET,
            tonic_reflection::pb::v1alpha::FILE_DESCRIPTOR_SET,
        ] {
            let Ok(set) = prost_types::FileDescriptorSet::decode(encoded) else {
                continue;
            };
            for file in set.file {
                let package = file.package();
                for service in &file.service {
                    for method in &service.method {
                        methods.push(GrpcMethod {
                            path: format!("/{package}.{}/{}", service.name(), method.name())
                                .into_boxed_str(),
                            client_streaming: method.client_streaming(),
                        });
                    }
                }
            }
        }
        methods
    })
}

pub(crate) fn streams_requests(path: &str) -> bool {
    static PATHS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    PATHS
        .get_or_init(|| {
            grpc_methods()
                .iter()
                .filter(|method| method.client_streaming)
                .map(|method| &*method.path)
                .collect()
        })
        .contains(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_reflection_streams_requests_and_every_listed_mpc_method_exists() {
        let streaming: Vec<_> = grpc_methods()
            .iter()
            .filter(|method| method.client_streaming)
            .map(|method| &*method.path)
            .collect();
        assert_eq!(
            streaming,
            [
                "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
                "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            ]
        );

        let mpc = hashi_types::proto::mpc_service_server::SERVICE_NAME;
        for method in SMALL_MPC_METHODS.into_iter().chain(MPC_WORK_METHODS) {
            let path = format!("/{mpc}/{method}");
            assert!(
                grpc_methods().iter().any(|known| *known.path == path),
                "{path}"
            );
        }
    }

    #[test]
    fn a_method_cap_never_exceeds_its_service_limit() {
        let mut limits = RouteLimits::default();
        limits.service("pkg.Big", 1024);
        limits.service("pkg.Small", 16);
        limits.method("pkg.Big", "Capped", 64);
        limits.method("pkg.Small", "Capped", 64);

        assert_eq!(limits.limit("/pkg.Big/Capped"), Some(64));
        assert_eq!(limits.limit("/pkg.Big/Other"), Some(1024));
        assert_eq!(limits.limit("/pkg.Small/Capped"), Some(16));
        assert_eq!(limits.limit("/pkg.Unknown/Capped"), None);
        assert_eq!(limits.limit("/health"), None);
        assert_eq!(limits.largest(), 1024);
    }
}
