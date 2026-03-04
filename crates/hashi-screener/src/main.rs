use anyhow::Result;
use hashi_screener::cache::ScreenerCache;
use hashi_screener::chain::ChainName;
use hashi_screener::chain::lookup_environment;
use hashi_screener::error::HashiScreenerError;
use hashi_screener::merkle::RISK_THRESHOLD;
use hashi_screener::merkle::TransactionType;
use hashi_screener::merkle::query_address_risk_level;
use hashi_screener::merkle::query_transaction_risk_level;
use hashi_screener::metrics::ScreenerMetrics;
use reqwest::Client;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Server;
use tonic_health::server::health_reporter;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use hashi_types::proto::screener::ApproveRequest;
use hashi_types::proto::screener::ApproveResponse;
use hashi_types::proto::screener::FILE_DESCRIPTOR_SET;
use hashi_types::proto::screener::TransactionType as ProtoTransactionType;
use hashi_types::proto::screener::screener_service_server::ScreenerService;
use hashi_types::proto::screener::screener_service_server::ScreenerServiceServer;

#[derive(Clone)]
struct AppState {
    metrics: ScreenerMetrics,
    http_client: Client,
    api_key: Arc<String>,
    cache: ScreenerCache,
}

struct ScreenerServiceImpl {
    state: AppState,
}

impl ScreenerServiceImpl {
    fn new(state: AppState) -> Self {
        Self { state }
    }

    fn record_result(&self, approved: bool) {
        if approved {
            self.state.metrics.approved_transactions.inc();
        } else {
            self.state.metrics.rejected_transactions.inc();
        }
    }

    async fn screen_request(
        &self,
        req: &ApproveRequest,
        transaction_type: TransactionType,
    ) -> Result<Response<ApproveResponse>, Status> {
        self.state.metrics.requests.inc();

        let request_type = transaction_type.as_str();
        let tx_hash = &req.source_transaction_hash;
        let dest_addr = &req.destination_address;

        info!(
            source_tx = %tx_hash,
            destination_address = %dest_addr,
            source_chain = %req.source_chain_id,
            destination_chain = %req.destination_chain_id,
            "Processing {request_type} approval request"
        );

        // Parse CAIP-2 chain IDs to determine chain name and environment.
        let (source_chain, source_suffix) =
            ChainName::from_caip2(&req.source_chain_id).map_err(|e| {
                self.state.metrics.validation_errors.inc();
                e.to_grpc_status()
            })?;
        let (dest_chain, dest_suffix) =
            ChainName::from_caip2(&req.destination_chain_id).map_err(|e| {
                self.state.metrics.validation_errors.inc();
                e.to_grpc_status()
            })?;

        // Auto-approve for non-mainnet networks.
        // Unknown suffixes are treated as non-mainnet.
        let source_env = lookup_environment(source_chain, source_suffix);
        let dest_env = lookup_environment(dest_chain, dest_suffix);
        let both_mainnet =
            source_env.is_some_and(|e| e.is_mainnet()) && dest_env.is_some_and(|e| e.is_mainnet());

        if !both_mainnet {
            info!("Non-mainnet request, auto-approving {request_type}");
            self.state.metrics.non_mainnet_auto_approvals.inc();
            self.record_result(true);
            return Ok(Response::new(ApproveResponse { approved: true }));
        }

        // Check cache.
        let cache_key = format!("{request_type}:{tx_hash}:{dest_addr}");
        if let Some(approved) = self.state.cache.get(&cache_key).await {
            self.record_result(approved);
            return Ok(Response::new(ApproveResponse { approved }));
        }

        debug!(cache_key = %cache_key, "Cache miss, querying MerkleScience API");

        // Screen source transaction and destination address in parallel.
        let (tx_risk, addr_risk) = tokio::try_join!(
            query_transaction_risk_level(
                &self.state.http_client,
                &self.state.api_key,
                tx_hash,
                source_chain.merkle_blockchain_id(),
                transaction_type,
            ),
            query_address_risk_level(
                &self.state.http_client,
                &self.state.api_key,
                dest_addr,
                dest_chain.merkle_blockchain_id(),
                transaction_type,
            ),
        )
        .map_err(|e| {
            self.state.metrics.api_errors.inc();
            error!(error = %e, "MerkleScience API screening failed");
            e.to_grpc_status()
        })?;

        let max_risk_level = tx_risk.max(addr_risk);
        let approved = max_risk_level <= RISK_THRESHOLD;

        self.state.cache.insert(cache_key, approved).await;
        self.record_result(approved);

        if !approved {
            warn!(
                source_tx = %tx_hash,
                destination_address = %dest_addr,
                max_risk_level = max_risk_level,
                threshold = RISK_THRESHOLD,
                "{request_type} rejected"
            );
        }

        Ok(Response::new(ApproveResponse { approved }))
    }
}

#[tonic::async_trait]
impl ScreenerService for ScreenerServiceImpl {
    async fn approve(
        &self,
        request: Request<ApproveRequest>,
    ) -> Result<Response<ApproveResponse>, Status> {
        let req = request.into_inner();

        // Parse transaction type from proto enum.
        let proto_type = ProtoTransactionType::try_from(req.transaction_type)
            .unwrap_or(ProtoTransactionType::Unspecified);
        let transaction_type = match proto_type {
            ProtoTransactionType::Deposit => TransactionType::Deposit,
            ProtoTransactionType::Withdrawal => TransactionType::Withdrawal,
            _ => {
                self.state.metrics.validation_errors.inc();
                return Err(Status::invalid_argument(
                    "transaction_type must be DEPOSIT or WITHDRAWAL",
                ));
            }
        };

        // Validate required fields.
        if req.source_transaction_hash.is_empty() {
            return Err(HashiScreenerError::ValidationError(
                "source_transaction_hash is required".to_string(),
            )
            .to_grpc_status());
        }
        if req.destination_address.is_empty() {
            return Err(HashiScreenerError::ValidationError(
                "destination_address is required".to_string(),
            )
            .to_grpc_status());
        }

        // Type-specific validation.
        match transaction_type {
            TransactionType::Deposit => {
                // Deposit: BTC (source) → Sui (destination).
                hashi_screener::validation::validate_btc_tx_hash(&req.source_transaction_hash)
                    .map_err(|e| {
                        self.state.metrics.validation_errors.inc();
                        error!(error = %e, "Validation failed");
                        e.to_grpc_status()
                    })?;
                hashi_screener::validation::validate_sui_address(&req.destination_address)
                    .map_err(|e| {
                        self.state.metrics.validation_errors.inc();
                        error!(error = %e, "Validation failed");
                        e.to_grpc_status()
                    })?;
            }
            TransactionType::Withdrawal => {
                // Withdrawal: Sui (source) → BTC (destination).
                hashi_screener::validation::validate_sui_tx_hash(&req.source_transaction_hash)
                    .map_err(|e| {
                        self.state.metrics.validation_errors.inc();
                        error!(error = %e, "Validation failed");
                        e.to_grpc_status()
                    })?;
                hashi_screener::validation::validate_btc_address(&req.destination_address)
                    .map_err(|e| {
                        self.state.metrics.validation_errors.inc();
                        error!(error = %e, "Validation failed");
                        e.to_grpc_status()
                    })?;
            }
        }

        self.screen_request(&req, transaction_type).await
    }
}

fn init_tracing_subscriber() {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_file(true)
        .with_line_number(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("unable to initialize tracing subscriber");
}

fn start_metrics_server(registry: prometheus::Registry) -> sui_http::ServerHandle {
    let addr: SocketAddr = "0.0.0.0:9184".parse().unwrap();
    info!("Prometheus metrics server listening on {}", addr);

    let router = axum::Router::new()
        .route("/metrics", axum::routing::get(metrics_handler))
        .with_state(registry);

    sui_http::Builder::new().serve(addr, router).unwrap()
}

async fn metrics_handler(
    axum::extract::State(registry): axum::extract::State<prometheus::Registry>,
) -> (axum::http::StatusCode, String) {
    let metrics_families = registry.gather();
    match prometheus::TextEncoder.encode_to_string(&metrics_families) {
        Ok(metrics) => (axum::http::StatusCode::OK, metrics),
        Err(error) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("unable to encode metrics: {error}"),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing_subscriber();

    let api_key = env::var("MERKLE_SCIENCE_API_KEY")
        .map_err(|_| anyhow::anyhow!("MERKLE_SCIENCE_API_KEY environment variable is not set"))?;

    let registry = prometheus::Registry::new();
    let metrics = ScreenerMetrics::new(&registry);
    let _metrics_handle = start_metrics_server(registry);

    let http_client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client");

    let state = AppState {
        metrics,
        http_client,
        api_key: Arc::new(api_key),
        cache: ScreenerCache::new(),
    };

    // Create gRPC health reporter
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<ScreenerServiceServer<ScreenerServiceImpl>>()
        .await;

    let addr: SocketAddr = "0.0.0.0:50051".parse()?;
    info!("Starting hashi-screener gRPC service on {}", addr);

    let service = ScreenerServiceImpl::new(state);

    // Enable gRPC reflection for debugging (v1 and v1alpha for compatibility)
    let reflection_v1 = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    let reflection_v1alpha = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .build_v1alpha()?;

    Server::builder()
        .add_service(health_service)
        .add_service(reflection_v1)
        .add_service(reflection_v1alpha)
        .add_service(ScreenerServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
