// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generate a fresh BTC master keypair for the guardian. The pubkey is
//! pinned on-chain at publish time via `hashi publish
//! --guardian-btc-public-key`; the secret is fed back to
//! `bootstrap-guardian --master-secret-hex` after DKG so the shares it
//! splits cover the *same* key already on chain.

use anyhow::Result;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey as BtcSecretKey;
use clap::Parser;
use clap::ValueEnum;
use rand::thread_rng;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum OutputFormat {
    /// `{"secret_hex":"…","pubkey_hex":"…"}` on one line.
    Json,
    /// `MASTER_SECRET_HEX=…\nMASTER_PUBKEY_HEX=…` — sourceable by shell.
    Env,
}

#[derive(Parser)]
pub struct Args {
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,
}

pub fn run(args: Args) -> Result<()> {
    let mut rng = thread_rng();
    let k256_sk = k256::SecretKey::random(&mut rng);
    let secret_bytes = k256_sk.to_bytes();

    let secp = Secp256k1::new();
    let btc_sk = BtcSecretKey::from_slice(&secret_bytes)
        .expect("k256 secret key bytes are a valid secp256k1 secret");
    let keypair = Keypair::from_secret_key(&secp, &btc_sk);
    let (master_pubkey, _parity) = keypair.x_only_public_key();

    let secret_hex = hex::encode(secret_bytes);
    let pubkey_hex = hex::encode(master_pubkey.serialize());

    match args.format {
        OutputFormat::Json => {
            println!("{{\"secret_hex\":\"{secret_hex}\",\"pubkey_hex\":\"{pubkey_hex}\"}}");
        }
        OutputFormat::Env => {
            println!("MASTER_SECRET_HEX={secret_hex}");
            println!("MASTER_PUBKEY_HEX={pubkey_hex}");
        }
    }
    Ok(())
}
