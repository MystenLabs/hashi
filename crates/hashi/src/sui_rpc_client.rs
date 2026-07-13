// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

const SUI_RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub fn new_sui_rpc_client(url: &str) -> Result<sui_rpc::Client, tonic::Status> {
    new_client_with_deadline(url, SUI_RPC_REQUEST_TIMEOUT)
}

fn new_client_with_deadline(
    url: &str,
    deadline: Duration,
) -> Result<sui_rpc::Client, tonic::Status> {
    Ok(sui_rpc::Client::new(url)?.request_layer(tower::timeout::TimeoutLayer::new(deadline)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::task::Context;
    use std::task::Poll;
    use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;
    use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;

    #[derive(Clone)]
    struct HangingLedgerService;

    impl tonic::server::NamedService for HangingLedgerService {
        const NAME: &'static str = "sui.rpc.v2.LedgerService";
    }

    impl tower::Service<http::Request<tonic::body::Body>> for HangingLedgerService {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = futures::future::Pending<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<tonic::body::Body>) -> Self::Future {
            futures::future::pending()
        }
    }

    struct PendingBody;

    impl http_body::Body for PendingBody {
        type Data = bytes::Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    #[derive(Clone)]
    struct SilentSubscriptionService;

    impl tonic::server::NamedService for SilentSubscriptionService {
        const NAME: &'static str = "sui.rpc.v2.SubscriptionService";
    }

    impl tower::Service<http::Request<tonic::body::Body>> for SilentSubscriptionService {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<tonic::body::Body>) -> Self::Future {
            std::future::ready(Ok(http::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .body(tonic::body::Body::new(PendingBody))
                .unwrap()))
        }
    }

    async fn spawn_server<S>(svc: S) -> std::net::SocketAddr
    where
        S: tower::Service<
                http::Request<tonic::body::Body>,
                Response = http::Response<tonic::body::Body>,
                Error = Infallible,
            > + tonic::server::NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = futures::stream::unfold(listener, |listener| async move {
            let result = listener.accept().await.map(|(stream, _)| stream);
            Some((result, listener))
        });
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_incoming(incoming),
        );
        addr
    }

    #[tokio::test]
    async fn deadline_fails_stuck_request_instead_of_hanging() {
        let addr = spawn_server(HangingLedgerService).await;
        let url = format!("http://{addr}");

        let mut plain = sui_rpc::Client::new(url.as_str()).unwrap();
        let hung = tokio::time::timeout(
            Duration::from_secs(2),
            plain
                .ledger_client()
                .get_service_info(GetServiceInfoRequest::default()),
        )
        .await;
        assert!(
            hung.is_err(),
            "un-deadlined request should still be pending"
        );

        let mut client =
            new_client_with_deadline(url.as_str(), Duration::from_millis(500)).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .ledger_client()
                .get_service_info(GetServiceInfoRequest::default()),
        )
        .await
        .expect("deadline should fire well before 5s");
        assert!(result.is_err(), "stuck request must surface an error");
    }

    #[tokio::test]
    async fn deadline_spares_established_subscription_stream() {
        let addr = spawn_server(SilentSubscriptionService).await;
        let mut client = new_client_with_deadline(
            format!("http://{addr}").as_str(),
            Duration::from_millis(500),
        )
        .unwrap();

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .subscription_client()
                .subscribe_checkpoints(SubscribeCheckpointsRequest::default()),
        )
        .await
        .expect("subscription accept should be fast")
        .expect("subscription should be accepted");

        let mut messages = response.into_inner();
        let past_deadline = tokio::time::timeout(Duration::from_secs(2), messages.message()).await;
        assert!(
            past_deadline.is_err(),
            "established stream should still be pending past the deadline, got {past_deadline:?}"
        );
    }
}
