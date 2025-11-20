use anyhow::{Context, Result};
use hashi_guardian_shared::{
    EncPubKey, EncSecKey, EncryptedShare, GetAttestationResponse, HealthCheckResponse,
    InitExternalRequest, InitExternalRequestState, InitInternalRequest, S3Config,
    SetupNewKeyRequest, SetupNewKeyResponse, ShareCommitment, WithdrawConfig, SECRET_SHARING_N,
    SECRET_SHARING_T,
};
use hpke::kem::X25519HkdfSha256;
use hpke::Kem;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

// Shared state for the client session
struct ClientState {
    kp_private_keys: Vec<EncSecKey>,
    encrypted_shares: Vec<EncryptedShare>,
    share_commitments: Vec<ShareCommitment>,
    enclave_encryption_key: Option<EncPubKey>,
}

impl ClientState {
    fn new() -> Self {
        ClientState {
            kp_private_keys: vec![],
            encrypted_shares: vec![],
            share_commitments: vec![],
            enclave_encryption_key: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing_subscriber();

    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let base_url = args
        .get(2)
        .map(|s| s.as_str())
        .unwrap_or("http://localhost:3000");

    // Check for --strict flag
    let strict = args.iter().any(|arg| arg == "--strict");

    info!("🔍 Connecting to server at: {}", base_url);
    if strict {
        info!("   Mode: STRICT (requires real enclave attestation)");
    } else {
        info!("   Mode: PERMISSIVE (development-friendly)");
    }
    info!("");

    // Create shared state
    let state = Arc::new(Mutex::new(ClientState::new()));

    match command {
        "ping" => ping(base_url).await?,
        "health_check" => health_check(base_url).await?,
        "configure_s3" => configure_s3(base_url, state.clone()).await?,
        "setup_new_key" => setup_new_key(base_url, state.clone()).await?,
        "get_attestation" => get_enclave_key(base_url, state.clone(), strict).await?,
        "init" => init_enclave(base_url, state.clone()).await?,
        "full_setup" => full_setup(base_url, state.clone(), strict).await?,
        "help" | "--help" | "-h" => print_help(),
        _ => {
            warn!("Unknown command: {}", command);
            print_help();
        }
    }

    Ok(())
}

fn print_help() {
    println!("Guardian Client - Usage:");
    println!("  cargo run [COMMAND] [BASE_URL] [--strict]");
    println!("\nCommands:");
    println!("  ping              - Test server connectivity");
    println!("  health_check      - Get server health and status");
    println!("  configure_s3      - Send S3 configuration to server");
    println!("  setup_new_key     - Generate and split a new Bitcoin key");
    println!("  get_attestation   - Get enclave key (attestation or health_check)");
    println!("  init              - Initialize enclave with shares and state");
    println!("  full_setup        - Run complete setup workflow");
    println!("  help              - Show this help message");
    println!("\nFlags:");
    println!("  --strict          - Require real enclave attestation (production mode)");
    println!("\nExamples:");
    println!("  cargo run full_setup http://localhost:3000");
    println!("  cargo run full_setup http://production:3000 --strict");
}

/// Test server connectivity
async fn ping(base_url: &str) -> Result<()> {
    info!("🏓 Pinging server...");
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/ping", base_url))
        .send()
        .await
        .context("Failed to send ping request")?;

    if response.status().is_success() {
        let body = response.text().await?;
        info!("✅ Server responded: {}", body);
    } else {
        warn!("❌ Ping failed with status: {}", response.status());
    }
    Ok(())
}

/// Configure S3 credentials and bucket info
async fn configure_s3(base_url: &str, state: Arc<Mutex<ClientState>>) -> Result<()> {
    info!("📤 Configuring S3...");

    let share_commitments = {
        let state = state.lock().unwrap();
        state.share_commitments.clone()
    };

    let s3_config_request = InitInternalRequest {
        config: S3Config {
            access_key: env::var("AWS_ACCESS_KEY_ID")
                .context("AWS_ACCESS_KEY_ID not found in environment")?,
            secret_key: env::var("AWS_SECRET_ACCESS_KEY")
                .context("AWS_SECRET_ACCESS_KEY not found in environment")?,
            bucket_name: env::var("AWS_BUCKET_NAME")
                .context("AWS_BUCKET_NAME not found in environment")?,
        },
        share_commitments,
    };

    info!("   Bucket: {}", s3_config_request.config.bucket_name);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/configure_s3", base_url))
        .json(&s3_config_request)
        .send()
        .await
        .context("Failed to send S3 configuration")?;

    if response.status().is_success() {
        info!("✅ S3 configuration sent successfully!");
        let body = response.text().await?;
        info!("   Response: {}", body);
    } else {
        let status = response.status();
        let error_body = response.text().await?;
        warn!("❌ Failed to configure S3: {} - {}", status, error_body);
    }

    Ok(())
}

/// Setup a new Bitcoin key by generating key provisioner keys and requesting key shares
async fn setup_new_key(base_url: &str, state: Arc<Mutex<ClientState>>) -> Result<()> {
    info!("🔑 Setting up new key...");

    // Generate key provisioner encryption keys
    let mut rng = rand::thread_rng();
    let mut kp_private_keys = vec![];
    let mut kp_public_keys = vec![];

    for i in 0..SECRET_SHARING_N {
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        kp_private_keys.push(sk);
        kp_public_keys.push(pk);
        info!("   Generated key pair {} of {}", i + 1, SECRET_SHARING_N);
    }

    let request: SetupNewKeyRequest = kp_public_keys.into();

    info!("📤 Sending setup request to server...");
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/setup_new_key", base_url))
        .json(&request)
        .send()
        .await
        .context("Failed to send setup_new_key request")?;

    if response.status().is_success() {
        let setup_response: SetupNewKeyResponse = response
            .json()
            .await
            .context("Failed to parse setup response")?;

        info!(
            "✅ Received {} encrypted shares",
            setup_response.encrypted_shares.len()
        );
        info!(
            "✅ Received {} share commitments",
            setup_response.share_commitments.len()
        );

        // Store in state
        let mut state = state.lock().unwrap();
        state.kp_private_keys = kp_private_keys;
        state.encrypted_shares = setup_response.encrypted_shares;
        state.share_commitments = setup_response.share_commitments;
        info!("💾 Stored shares and commitments in session state");
    } else {
        let status = response.status();
        let error_body = response.text().await?;
        warn!("❌ Failed to setup new key: {} - {}", status, error_body);
    }

    Ok(())
}

/// Health check - get server status and encryption key
async fn health_check(base_url: &str) -> Result<()> {
    info!("🏯 Checking server health...");

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/health_check", base_url))
        .send()
        .await
        .context("Failed to request health check")?;

    if response.status().is_success() {
        let health_response: HealthCheckResponse = response
            .json()
            .await
            .context("Failed to parse health check response")?;

        info!("✅ Server is healthy");
        info!("   S3 configured: {}", health_response.s3_configured);
        info!("   Initialized: {}", health_response.btc_key_configured);
        info!(
            "   Shares received: {}/{}",
            health_response.shares_received, SECRET_SHARING_T
        );
        if let Some(ref pk) = health_response.enc_public_key {
            info!("   Encryption public key: {} bytes", pk.len());
        }
    } else {
        let status = response.status();
        let error_body = response.text().await?;
        warn!("❌ Health check failed: {} - {}", status, error_body);
    }

    Ok(())
}

/// Get enclave encryption key - tries attestation first (strict), falls back to health_check
async fn get_enclave_key(
    base_url: &str,
    state: Arc<Mutex<ClientState>>,
    strict: bool,
) -> Result<()> {
    info!("🔑 Getting enclave encryption key...");

    let client = reqwest::Client::new();

    // Try attestation first
    info!("📜 Trying attestation endpoint...");
    let attestation_response = client
        .get(format!("{}/get_attestation", base_url))
        .send()
        .await;

    match attestation_response {
        Ok(response) if response.status().is_success() => {
            let attestation: GetAttestationResponse = response
                .json()
                .await
                .context("Failed to parse attestation response")?;

            info!("✅ Received attestation document");
            info!("   Length: {} characters", attestation.attestation.len());
            info!(
                "   Attestation (hex): {}...",
                &attestation.attestation[..64.min(attestation.attestation.len())]
            );

            // TODO: Extract encryption key from attestation user_data
            // For now, need to parse the attestation document to get the user_data
            warn!("⚠️  TODO: Extract encryption key from attestation user_data");
            warn!("⚠️  Falling back to health_check endpoint...");

            // Fall through to health_check
        }
        _ => {
            if strict {
                return Err(anyhow::anyhow!(
                    "Attestation required in strict mode, but attestation endpoint failed"
                ));
            }
            info!("🔄 Attestation not available, using health_check endpoint...");
        }
    }

    // Use health_check endpoint
    let health_response = client
        .get(format!("{}/health_check", base_url))
        .send()
        .await
        .context("Failed to request health check")?;

    if health_response.status().is_success() {
        let health: HealthCheckResponse = health_response
            .json()
            .await
            .context("Failed to parse health check response")?;

        if let Some(enc_pk_bytes) = health.enc_public_key {
            use hpke::Deserializable;
            let enc_pk = EncPubKey::from_bytes(&enc_pk_bytes).map_err(|e| {
                anyhow::anyhow!("Failed to parse enclave encryption public key: {}", e)
            })?;

            let mut state = state.lock().unwrap();
            state.enclave_encryption_key = Some(enc_pk);
            info!(
                "✅ Stored enclave encryption public key ({} bytes)",
                enc_pk_bytes.len()
            );

            if !strict {
                warn!("\n⚠️  Note: Using health_check endpoint for development.");
                warn!("⚠️  In production, use --strict flag to require attestation verification!");
            }
        } else {
            return Err(anyhow::anyhow!(
                "No encryption public key in health check response"
            ));
        }
    } else {
        let status = health_response.status();
        let error_body = health_response.text().await?;
        return Err(anyhow::anyhow!(
            "Health check failed: {} - {}",
            status,
            error_body
        ));
    }

    Ok(())
}

/// Initialize the enclave with encrypted shares and configuration
/// This simulates sending shares from multiple key provisioners
async fn init_enclave(base_url: &str, state: Arc<Mutex<ClientState>>) -> Result<()> {
    info!("🚀 Initializing enclave...");

    // Get data from state
    let (kp_private_keys, encrypted_shares, enclave_encryption_key) = {
        let state = state.lock().unwrap();
        if state.encrypted_shares.is_empty() {
            warn!("❌ No encrypted shares found. Run 'setup_new_key' first!");
            return Ok(());
        }
        if state.kp_private_keys.is_empty() {
            warn!("❌ No KP private keys found. Run 'setup_new_key' first!");
            return Ok(());
        }
        if state.enclave_encryption_key.is_none() {
            warn!("❌ No enclave encryption key found. Run 'get_attestation' first!");
            return Ok(());
        }

        (
            state.kp_private_keys.clone(),
            state.encrypted_shares.clone(),
            state.enclave_encryption_key.clone().unwrap(),
        )
    };

    // Create init state
    let init_state = InitExternalRequestState {
        hashi_committee_info: hashi_guardian_shared::HashiCommittee::default(),
        withdraw_config: WithdrawConfig {
            min_delay: Duration::from_secs(60),
            max_delay: Duration::from_secs(3600),
        },
        withdraw_state: hashi_guardian_shared::WithdrawalState::default(),
        cached_bytes: std::sync::OnceLock::new(),
    };

    info!("📦 Initialization config:");
    info!("   Min delay: {:?}", init_state.withdraw_config.min_delay);
    info!("   Max delay: {:?}", init_state.withdraw_config.max_delay);
    info!(
        "   Withdrawal counter: {}",
        init_state.withdraw_state.counter
    );

    // Send threshold number of shares
    let client = reqwest::Client::new();
    let threshold = SECRET_SHARING_T as usize;

    info!(
        "📤 Sending {} shares (threshold) to enclave...\n",
        threshold
    );

    for i in 0..threshold {
        let kp_sk = &kp_private_keys[i];
        let encrypted_share = &encrypted_shares[i];

        info!("🔑 Processing share {} of {}...", i + 1, threshold);

        // Decrypt the share with KP's private key
        info!("   Decrypting share with KP private key...");
        let serialized_share =
            decrypt_share(encrypted_share, kp_sk).context("Failed to decrypt share with KP key")?;

        // Re-encrypt for the enclave's public key
        info!("   Re-encrypting share for enclave...");
        let new_ciphertext = encrypt_share(&serialized_share, &enclave_encryption_key, &init_state)
            .context("Failed to encrypt share for enclave")?;

        let new_encrypted_share = EncryptedShare {
            id: *encrypted_share.id(),
            ciphertext: new_ciphertext,
        };

        let request = InitExternalRequest {
            encrypted_share: new_encrypted_share,
            state: init_state.clone(),
        };

        info!("   Sending to server...");
        let response = client
            .post(format!("{}/init", base_url))
            .json(&request)
            .send()
            .await
            .context("Failed to send init request")?;

        if response.status().is_success() {
            info!("✅ Share {} accepted by enclave\n", i + 1);
            if i + 1 >= threshold {
                info!("🎉 Threshold reached! Enclave should now be initialized!");
            }
        } else {
            let status = response.status();
            let error_body = response.text().await?;
            warn!(
                "❌ Failed to send share {}: {} - {}",
                i + 1,
                status,
                error_body
            );
            return Ok(());
        }
    }

    Ok(())
}

/// Full setup workflow: setup_new_key + configure_s3 + get_enclave_key + init
async fn full_setup(base_url: &str, state: Arc<Mutex<ClientState>>, strict: bool) -> Result<()> {
    info!("🚀 Running full setup workflow...\n");

    info!("Step 1: Setup new key");
    info!("{}\n", "=".repeat(50));
    setup_new_key(base_url, state.clone()).await?;

    info!("\nStep 2: Get enclave encryption key");
    info!("{}\n", "=".repeat(50));
    get_enclave_key(base_url, state.clone(), strict).await?;

    info!("\nStep 3: Configure S3");
    info!("{}\n", "=".repeat(50));
    configure_s3(base_url, state.clone()).await?;

    info!("\nStep 4: Initialize enclave");
    info!("{}\n", "=".repeat(50));
    init_enclave(base_url, state.clone()).await?;

    info!("\n🎊 Full setup complete!");
    Ok(())
}

// Helper functions for encryption/decryption
use fastcrypto::hash::{Blake2b256, HashFunction};
use hashi_guardian_shared::Ciphertext;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha384;

fn decrypt_share(encrypted_share: &EncryptedShare, sk: &EncSecKey) -> Result<Vec<u8>> {
    use hpke::Deserializable;
    let (encapped_key, aes_ciphertext): (<X25519HkdfSha256 as Kem>::EncappedKey, &[u8]) =
        encrypted_share
            .ciphertext()
            .try_into()
            .map_err(|e: hpke::HpkeError| anyhow::anyhow!("Failed to parse ciphertext: {}", e))?;

    let decrypted = hpke::single_shot_open::<AesGcm256, HkdfSha384, X25519HkdfSha256>(
        &hpke::OpModeR::Base,
        sk,
        &encapped_key,
        &[],
        aes_ciphertext,
        &[0; 32],
    )
    .map_err(|e| anyhow::anyhow!("Failed to decrypt share: {}", e))?;

    Ok(decrypted)
}

fn encrypt_share(
    bytes: &[u8],
    pk: &EncPubKey,
    state: &InitExternalRequestState,
) -> Result<Ciphertext> {
    let state_hash = Blake2b256::digest(state);
    let mut rng = rand::thread_rng();

    let (encapsulated_key, aes_ciphertext) =
        hpke::single_shot_seal::<AesGcm256, HkdfSha384, X25519HkdfSha256, _>(
            &hpke::OpModeS::Base,
            pk,
            &[],
            bytes,
            &state_hash.digest,
            &mut rng,
        )
        .map_err(|e| anyhow::anyhow!("Failed to encrypt share: {}", e))?;

    Ok((encapsulated_key, aes_ciphertext).into())
}

fn init_tracing_subscriber() {
    let subscriber = ::tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .finish();
    ::tracing::subscriber::set_global_default(subscriber)
        .expect("unable to initialize tracing subscriber");
}

#[cfg(test)]
mod tests {
    #[test]
    fn dummy_test() {
        assert_eq!(2 + 2, 4);
    }
}
