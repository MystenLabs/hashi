use anyhow::Context;
use anyhow::Result;
use hashi_guardian_shared::crypto::decrypt_share;
use hashi_guardian_shared::test_utils::gen_dummy_share_data;
use hashi_guardian_shared::test_utils::mock_init_external_state;
use hashi_guardian_shared::*;
use hpke::kem::X25519HkdfSha256;
use hpke::Kem;
use std::env;
use tracing::info;
use tracing::warn;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing_subscriber(false);

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

    match command {
        "health_check" => {
            _ = health_check(base_url).await?;
        }
        "configure_s3" => configure_s3(base_url, None).await?,
        "get_attestation" => {
            _ = get_attestation(base_url).await?;
        }
        "init_with_test_key" => init_with_test_key(base_url, strict).await?,
        "init_with_new_key" => init_with_new_key(base_url, strict).await?,
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
    println!("  health_check      - Get server health and status");
    println!("  configure_s3      - Send S3 configuration to server");
    println!("  get_attestation   - Get enclave attestation document");
    println!("  init_with_test_key - Initialize enclave with dummy test key");
    println!("  init_with_new_key - Initialize enclave with freshly generated key");
    println!("  help              - Show this help message");
    println!("\nFlags:");
    println!("  --strict          - Require real enclave attestation (production mode)");
    println!("\nExamples:");
    println!("  cargo run init_with_test_key http://localhost:3000");
    println!("  cargo run init_with_new_key http://localhost:3000");
    println!("  cargo run init_with_new_key http://production:3000 --strict");
}

/// Configure S3 credentials and bucket info
async fn configure_s3(
    base_url: &str,
    share_commitments: Option<Vec<ShareCommitment>>,
) -> Result<()> {
    info!("📤 Configuring S3...");
    let share_commitments = share_commitments.unwrap_or(gen_dummy_share_data()?.1);

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
async fn setup_new_key(base_url: &str) -> Result<(Vec<MyShare>, Vec<ShareCommitment>)> {
    info!("🔑 Setting up new key...");

    // Generate key provisioner encryption keys
    let mut rng = rand::thread_rng();
    let mut kp_private_keys = vec![];
    let mut kp_public_keys = vec![];

    for i in 0..LIMIT {
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        kp_private_keys.push(sk);
        kp_public_keys.push(pk);
        info!("   Generated key pair {} of {}", i + 1, LIMIT);
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

        // Decrypt the shares with the KP private keys
        info!("🔓 Decrypting shares...");
        let mut decrypted_shares = vec![];

        for (i, encrypted_share) in setup_response.encrypted_shares.iter().enumerate() {
            let kp_sk = &kp_private_keys[i];
            let share = decrypt_share(encrypted_share, kp_sk, None)
                .context(format!("Failed to decrypt share {}", i))?;
            decrypted_shares.push(share);
        }

        info!("✅ Decrypted {} shares", decrypted_shares.len());
        info!("\n💡 In production:");
        info!("   - Each key provisioner stores their share securely");
        info!("   - Share commitments are used to configure the enclave");

        return Ok((decrypted_shares, setup_response.share_commitments));
    } else {
        let status = response.status();
        let error_body = response.text().await?;
        return Err(anyhow::anyhow!(
            "Failed to setup new key: {} - {}",
            status,
            error_body
        ));
    }
}

/// Health check - get server status and encryption key
async fn health_check(base_url: &str) -> Result<HealthCheckResponse> {
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
            health_response.shares_received, THRESHOLD
        );
        if let Some(ref pk) = health_response.enc_public_key {
            info!("   Encryption public key: {} bytes", pk.len());
        }

        Ok(health_response)
    } else {
        let status = response.status();
        let error_body = response.text().await?;
        Err(anyhow::anyhow!(
            "Health check failed: {} - {}",
            status,
            error_body
        ))
    }
}

/// Get attestation document from enclave
async fn get_attestation(base_url: &str) -> Result<GetAttestationResponse> {
    info!("📜 Getting attestation document...");

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/get_attestation", base_url))
        .send()
        .await
        .context("Failed to request attestation")?;

    if response.status().is_success() {
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

        Ok(attestation)
    } else {
        let status = response.status();
        let error_body = response.text().await?;
        Err(anyhow::anyhow!(
            "Failed to get attestation: {} - {}",
            status,
            error_body
        ))
    }
}

/// Get enclave encryption key - tries attestation first (strict), falls back to health_check
async fn get_enclave_key(base_url: &str, strict: bool) -> Result<EncPubKey> {
    info!("🔑 Getting enclave encryption key...");

    // Try attestation first
    info!("📜 Trying attestation endpoint...");
    let attestation_result = get_attestation(base_url).await;

    match attestation_result {
        Ok(_attestation) => {
            // TODO: Extract encryption key from attestation user_data
            // For now, need to parse the attestation document to get the user_data
            warn!("⚠️  TODO: Extract encryption key from attestation user_data");
            warn!("⚠️  Falling back to health_check endpoint...");

            // Fall through to health_check
        }
        Err(_) => {
            if strict {
                return Err(anyhow::anyhow!(
                    "Attestation required in strict mode, but attestation endpoint failed"
                ));
            }
            info!("🔄 Attestation not available, using health_check endpoint...");
        }
    }

    // Use health_check endpoint
    let health = health_check(base_url).await?;

    if let Some(enc_pk_bytes) = health.enc_public_key {
        use hpke::Deserializable;
        let enc_pk = EncPubKey::from_bytes(&enc_pk_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse enclave encryption public key: {}", e))?;

        info!(
            "✅ Retrieved enclave encryption public key ({} bytes)",
            enc_pk_bytes.len()
        );
        if !strict {
            warn!("\n⚠️  Note: Using health_check endpoint for development.");
            warn!("⚠️  In production, use --strict flag to require attestation verification!");
        }
        Ok(enc_pk)
    } else {
        Err(anyhow::anyhow!(
            "No encryption public key in health check response"
        ))
    }
}

/// Initialize the enclave with shares and configuration
/// Takes enclave public key and shares as arguments
async fn init_enclave(
    base_url: &str,
    enclave_pub_key: &EncPubKey,
    shares: Vec<MyShare>,
) -> Result<()> {
    info!("🚀 Initializing enclave with {} shares...", shares.len());

    // Create init state
    let init_state = mock_init_external_state();

    info!("📦 Initialization config: {:?}", init_state);

    let client = reqwest::Client::new();
    assert!(shares.len() >= THRESHOLD);

    info!(
        "📤 Sending {} shares (threshold) to enclave...\n",
        THRESHOLD
    );

    for i in 0..THRESHOLD.min(shares.len()) {
        let share = &shares[i];
        info!("🔑 Processing share {} of {}...", i + 1, THRESHOLD);

        // Encrypt with the enclave's public key
        info!("   Encrypting share for enclave...");
        let request = InitExternalRequest::new(share, enclave_pub_key, init_state.clone())
            .map_err(|e| anyhow::anyhow!("Failed to create init request: {}", e))?;

        info!("   Sending to server...");
        let response = client
            .post(format!("{}/init", base_url))
            .json(&request)
            .send()
            .await
            .context("Failed to send init request")?;

        if response.status().is_success() {
            info!("✅ Share {} accepted by enclave\n", i + 1);
            if i + 1 >= THRESHOLD {
                info!("🎉 Threshold reached! Enclave should now be initialized!");
            }
        } else {
            let status = response.status();
            let error_body = response.text().await?;
            return Err(anyhow::anyhow!(
                "Failed to send share {}: {} - {}",
                i + 1,
                status,
                error_body
            ));
        }
    }

    Ok(())
}

/// Initialize enclave with dummy test key (for testing)
async fn init_with_test_key(base_url: &str, strict: bool) -> Result<()> {
    info!("🚀 Initializing with test key...\n");

    // Step 1: Get enclave encryption key
    info!("Step 1: Get enclave encryption key");
    info!("{}\n", "=".repeat(50));
    let enclave_pub_key = get_enclave_key(base_url, strict).await?;

    // Step 2: Generate dummy shares
    info!("Step 2: Generate dummy test shares locally");
    info!("{}\n", "=".repeat(50));
    info!("🧪 Creating dummy shares from test secret [1u8; 32]...");
    info!("⚠️  Note: NOT FOR PRODUCTION!");
    let (shares, commitments) = test_utils::gen_dummy_share_data().unwrap();
    for d in &commitments {
        info!("Share {} Digest {}", d.id, d.digest);
    }

    info!("Step 3: Configure S3");
    info!("{}\n", "=".repeat(50));
    configure_s3(base_url, Some(commitments)).await?;

    // Step 3: Initialize enclave
    info!("Step 4: Initialize enclave");
    info!("{}\n", "=".repeat(50));
    init_enclave(base_url, &enclave_pub_key, shares).await?;

    info!("\n🎊 Initialization with test key complete!");
    Ok(())
}

/// Initialize enclave with freshly generated key
/// Full E2E flow: setup_new_key + configure_s3 + get_enclave_key + init
async fn init_with_new_key(base_url: &str, strict: bool) -> Result<()> {
    info!("🚀 Initializing with freshly generated key...\n");

    info!("Step 1: Setup new key");
    info!("{}\n", "=".repeat(50));
    let (shares, share_commitments) = setup_new_key(base_url).await?;

    info!("\nStep 2: Get enclave encryption key");
    info!("{}\n", "=".repeat(50));
    let enclave_pub_key = get_enclave_key(base_url, strict).await?;

    info!("\nStep 3: Configure S3");
    info!("{}\n", "=".repeat(50));
    configure_s3(base_url, Some(share_commitments)).await?;

    info!("\nStep 4: Initialize enclave");
    info!("{}\n", "=".repeat(50));
    init_enclave(base_url, &enclave_pub_key, shares).await?;

    info!("🎊 Initialization with new key complete!");
    Ok(())
}
