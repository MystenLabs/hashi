// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tonic::transport::Channel;
use tonic::transport::Endpoint;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Lazy gRPC channel to a `hashi-guardian`.
#[derive(Clone, Debug)]
pub struct GuardianClient {
    endpoint: String,
    channel: Channel,
}

impl GuardianClient {
    pub fn new(endpoint: &str) -> Result<Self, tonic::Status> {
        let channel = Endpoint::from_shared(endpoint.to_string())
            .map_err(Into::<BoxError>::into)
            .map_err(tonic::Status::from_error)?
            .connect_timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Duration::from_secs(5))
            .connect_lazy();
        Ok(Self {
            endpoint: endpoint.to_string(),
            channel,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn guardian_service_client(&self) -> GuardianServiceClient<Channel> {
        GuardianServiceClient::new(self.channel.clone())
    }
}
