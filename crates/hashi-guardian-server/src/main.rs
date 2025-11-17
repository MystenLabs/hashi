use anyhow::Result;
use axum::routing::get;
use axum::routing::post;
use axum::Router;
use hashi_guardian_shared::S3Config;
use std::sync::Arc;
use std::sync::OnceLock;
use tracing::info;

mod s3_logger;
use s3_logger::configure_s3;

#[derive(Clone)]
struct AppState {
    pub s3_config: Arc<OnceLock<S3Config>>,
}

async fn hello() -> &'static str {
    "Hello world!"
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing_subscriber();

    let state = AppState {
        s3_config: Arc::new(OnceLock::new()),
    };

    let app = Router::new()
        .route("/", get(hello))
        .route("/configure", post(configure_s3))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Server listening on {}", listener.local_addr().unwrap());
    info!("Waiting for S3 configuration from client...");
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

fn init_tracing_subscriber() {
    let subscriber = ::tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_file(true)
        .with_line_number(true)
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

    // https://github.com/rozbb/rust-hpke/tree/main
    use hpke::aead::AesGcm256;
    use hpke::kdf::HkdfSha384;
    use hpke::kem::X25519HkdfSha256;
    use hpke::Kem;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    #[test]
    fn test_hpke() {
        let plaintext = b"Hello, world!";
        let aad = b"aad";

        let mut rng = StdRng::from_os_rng();
        let keys = X25519HkdfSha256::gen_keypair(&mut rng);

        // TODO: Should we use hkdf sha256 or sha384 or sha512?
        // TODO: Should we use aead aes-256-gcm or chacha20-poly1305?
        let (encapped_key, ciphertext) =
            hpke::single_shot_seal::<AesGcm256, HkdfSha384, X25519HkdfSha256, _>(
                &hpke::OpModeS::Base,
                &keys.1,
                // TODO: What is the info?
                &[],
                plaintext,
                aad,
                &mut rng,
            )
            .unwrap();
        let decrypted = hpke::single_shot_open::<AesGcm256, HkdfSha384, X25519HkdfSha256>(
            &hpke::OpModeR::Base,
            &keys.0,
            &encapped_key,
            &[],
            &ciphertext,
            aad,
        )
        .unwrap();
        println!("decrypted: {:?}", decrypted);
        assert_eq!(plaintext, decrypted.as_slice());
    }

    use elliptic_curve::ff::PrimeField;
    use p256::{NonZeroScalar, Scalar, SecretKey};
    use vsss_rs::{shamir, *};

    #[test]
    fn secret_sharing() {
        type P256Share = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;

        let mut osrng = rand_core::OsRng::default();
        let sk = SecretKey::random(&mut osrng);
        let nzs = sk.to_nonzero_scalar();
        let shared_secret = IdentifierPrimeField(*nzs.as_ref());
        let res = shamir::split_secret::<P256Share>(2, 3, &shared_secret, &mut osrng);
        assert!(res.is_ok());
        let shares = res.unwrap();
        println!("{:?}", shares);
        let res = shares.combine();
        assert!(res.is_ok());
        let scalar = res.unwrap();
        let nzs_dup = NonZeroScalar::from_repr(scalar.0.to_repr()).unwrap();
        let sk_dup = SecretKey::from(nzs_dup);
        assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
    }
}
