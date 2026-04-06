// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::Weight;
use bitcoin::Witness;
use bitcoin::absolute::LockTime;
use bitcoin::consensus;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::secp256k1::{self};
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::Signature;
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use clap::Parser;
use fastcrypto::groups::GroupElement;
use fastcrypto::hmac::HkdfIkm;
use fastcrypto::hmac::hkdf_sha3_256;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::S;
use futures::stream::StreamExt;
use futures::stream::{self};
use hashi::onchain::types::Utxo;
use hashi_types::guardian::bitcoin_utils;

const VERIFY_CONCURRENCY: usize = 64;
const BROADCAST_CONCURRENCY: usize = 8;

#[derive(Parser)]
pub struct Args {
    #[arg(long)]
    csv: PathBuf,

    #[arg(long)]
    private_key: String,

    #[arg(long)]
    destination: String,

    #[arg(long, default_value = "http://127.0.0.1:38332")]
    bitcoin_rpc: String,

    #[arg(long, default_value = "")]
    rpc_user: String,

    #[arg(long, default_value = "")]
    rpc_password: String,

    #[arg(long, default_value = "signet")]
    network: String,

    #[arg(long, default_value_t = 1.0)]
    fee_rate: f64,

    #[arg(long, default_value_t = 250)]
    batch_size: usize,

    #[arg(long, default_value_t = false)]
    verify: bool,

    #[arg(long, default_value_t = false)]
    broadcast: bool,
}

struct PreparedInput {
    outpoint: OutPoint,
    amount: Amount,
    secret_key: secp256k1::SecretKey,
    tapscript: ScriptBuf,
    control_block: bitcoin::taproot::ControlBlock,
    leaf_hash: TapLeafHash,
    address: Address,
}

struct BitcoinRpc {
    client: reqwest::Client,
    url: String,
    auth: Option<(String, String)>,
    next_id: AtomicUsize,
}

impl BitcoinRpc {
    fn new(url: &str, user: &str, password: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_string(),
            auth: if user.is_empty() {
                None
            } else {
                Some((user.to_string(), password.to_string()))
            },
            next_id: AtomicUsize::new(1),
        }
    }

    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let mut req = self.client.post(&self.url).json(&body);
        if let Some((user, pass)) = &self.auth {
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req.send().await.context("RPC request failed")?;
        let json: serde_json::Value = resp.json().await.context("RPC response parse failed")?;

        if let Some(error) = json.get("error").filter(|e| !e.is_null()) {
            bail!("RPC error: {error}");
        }

        Ok(json["result"].clone())
    }

    async fn get_tx_out(&self, txid: &str, vout: u32) -> anyhow::Result<Option<String>> {
        let result = self
            .call("gettxout", serde_json::json!([txid, vout]))
            .await?;
        if result.is_null() {
            return Ok(None);
        }
        let addr = result["scriptPubKey"]["address"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Ok(Some(addr))
    }

    async fn send_raw_transaction(&self, tx_hex: &str) -> anyhow::Result<String> {
        let result = self
            .call("sendrawtransaction", serde_json::json!([tx_hex]))
            .await?;
        Ok(result.as_str().unwrap_or("").to_string())
    }
}

/// Reimplemented from `fastcrypto_tbls::threshold_schnorr::key_derivation::compute_tweak`
/// (pub(crate), so not directly accessible).
fn compute_tweak(vk: &G, address: &[u8; 32]) -> S {
    let mut ikm: Vec<u8> = vk.x_as_be_bytes().expect("non-identity point").to_vec();
    ikm.extend_from_slice(address);

    let bytes = hkdf_sha3_256(&HkdfIkm::from_bytes(&ikm).expect("valid ikm"), &[], &[], 64)
        .expect("hkdf should not fail for 64 bytes");
    S::from_bytes_mod_order(&bytes)
}

fn derive_child_secret_key(parent_sk: &S, parent_pk: &G, derivation_path: &[u8; 32]) -> S {
    let tweak = compute_tweak(parent_pk, derivation_path);
    *parent_sk + tweak
}

fn parse_network(s: &str) -> anyhow::Result<Network> {
    match s {
        "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => bail!("unknown network: {s}"),
    }
}

fn estimate_tx_weight(n_inputs: usize) -> Weight {
    let fixed_wu: u64 = 44;
    let per_input_wu: u64 = 299;
    let per_output_wu: u64 = 172;
    Weight::from_wu(fixed_wu + (n_inputs as u64) * per_input_wu + per_output_wu)
}

fn estimate_fee(n_inputs: usize, fee_rate: FeeRate) -> Amount {
    fee_rate
        .fee_wu(estimate_tx_weight(n_inputs))
        .unwrap_or(Amount::from_sat(0))
}

fn prepare_inputs(
    utxos: &[Utxo],
    parent_sk: &S,
    parent_pk: &G,
    network: Network,
) -> anyhow::Result<Vec<PreparedInput>> {
    let secp = Secp256k1::new();
    let mut inputs = Vec::with_capacity(utxos.len());

    for (i, utxo) in utxos.iter().enumerate() {
        let child_sk_scalar = match &utxo.derivation_path {
            Some(path) => derive_child_secret_key(parent_sk, parent_pk, &path.into_inner()),
            None => *parent_sk,
        };

        let sk_bytes = child_sk_scalar.to_byte_array();
        let child_pk_point = G::generator() * child_sk_scalar;

        let xonly_bytes = child_pk_point
            .x_as_be_bytes()
            .map_err(|e| anyhow!("utxo {i}: x_as_be_bytes: {e}"))?;

        let xonly_pk = XOnlyPublicKey::from_slice(&xonly_bytes)
            .with_context(|| format!("utxo {i}: invalid x-only key"))?;

        let (tapscript, control_block, leaf_hash) =
            bitcoin_utils::single_key_taproot_script_path_spend_artifacts(&xonly_pk);
        let address = bitcoin_utils::single_key_taproot_script_path_address(&xonly_pk, network);

        let secret_key = secp256k1::SecretKey::from_slice(&sk_bytes)
            .with_context(|| format!("utxo {i}: invalid secret key"))?;

        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let (derived_xonly, _parity) = keypair.x_only_public_key();
        if derived_xonly != xonly_pk {
            bail!(
                "utxo {i}: derived pubkey mismatch: expected {}, got {}",
                xonly_pk,
                derived_xonly
            );
        }

        inputs.push(PreparedInput {
            outpoint: OutPoint {
                txid: Txid::from_byte_array(utxo.id.txid.into_inner()),
                vout: utxo.id.vout,
            },
            amount: Amount::from_sat(utxo.amount),
            secret_key,
            tapscript,
            control_block,
            leaf_hash,
            address,
        });
    }

    Ok(inputs)
}

fn build_and_sign_sweep_tx(
    inputs: &[PreparedInput],
    destination: &Address,
    fee_rate: FeeRate,
) -> anyhow::Result<(Transaction, Amount)> {
    let secp = Secp256k1::new();

    let total_input: Amount = inputs.iter().map(|inp| inp.amount).sum();
    let fee = estimate_fee(inputs.len(), fee_rate);
    if fee >= total_input {
        bail!(
            "fee ({} sat) exceeds total input ({} sat) for {} inputs",
            fee.to_sat(),
            total_input.to_sat(),
            inputs.len()
        );
    }
    let output_amount = total_input - fee;

    let tx_inputs: Vec<TxIn> = inputs
        .iter()
        .map(|inp| TxIn {
            previous_output: inp.outpoint,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        })
        .collect();

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: vec![TxOut {
            value: output_amount,
            script_pubkey: destination.script_pubkey(),
        }],
    };

    let prevouts: Vec<TxOut> = inputs
        .iter()
        .map(|inp| TxOut {
            value: inp.amount,
            script_pubkey: inp.address.script_pubkey(),
        })
        .collect();

    for (idx, inp) in inputs.iter().enumerate() {
        let mut sighasher = SighashCache::new(&tx);
        let sighash = sighasher
            .taproot_script_spend_signature_hash(
                idx,
                &Prevouts::All(&prevouts),
                inp.leaf_hash,
                TapSighashType::Default,
            )
            .with_context(|| format!("sighash computation failed for input {idx}"))?;

        let message = Message::from_digest(*sighash.as_byte_array());
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &inp.secret_key);
        let schnorr_sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);

        tx.input[idx].witness = Witness::from_slice(&[
            Signature {
                signature: schnorr_sig,
                sighash_type: TapSighashType::Default,
            }
            .to_vec(),
            inp.tapscript.to_bytes(),
            inp.control_block.serialize(),
        ]);
    }

    Ok((tx, fee))
}

async fn verify_utxos_against_node(
    inputs: Vec<PreparedInput>,
    rpc: &Arc<BitcoinRpc>,
) -> anyhow::Result<Vec<PreparedInput>> {
    let total = inputs.len();
    let checked = Arc::new(AtomicUsize::new(0));
    let skipped = Arc::new(AtomicUsize::new(0));

    println!("  Checking {total} UTXOs with {VERIFY_CONCURRENCY} concurrent requests...");

    let results: Vec<(usize, bool)> = stream::iter(inputs.iter().enumerate())
        .map(|(i, inp)| {
            let rpc = rpc.clone();
            let checked = checked.clone();
            let skipped = skipped.clone();
            let txid_str = inp.outpoint.txid.to_string();
            let vout = inp.outpoint.vout;
            let expected_addr = inp.address.to_string();

            async move {
                let cnt = checked.fetch_add(1, Ordering::Relaxed) + 1;
                if cnt.is_multiple_of(2000) {
                    eprintln!("  ... verified {cnt}/{total}");
                }

                match rpc.get_tx_out(&txid_str, vout).await {
                    Ok(Some(addr)) if addr == expected_addr => (i, true),
                    Ok(Some(_)) | Ok(None) => {
                        skipped.fetch_add(1, Ordering::Relaxed);
                        (i, false)
                    }
                    Err(_) => (i, true),
                }
            }
        })
        .buffer_unordered(VERIFY_CONCURRENCY)
        .collect()
        .await;

    let keep_set: std::collections::HashSet<usize> = results
        .into_iter()
        .filter(|(_, keep)| *keep)
        .map(|(i, _)| i)
        .collect();

    let filtered: Vec<PreparedInput> = inputs
        .into_iter()
        .enumerate()
        .filter(|(i, _)| keep_set.contains(i))
        .map(|(_, inp)| inp)
        .collect();

    let skipped_count = skipped.load(Ordering::Relaxed);
    println!(
        "Verified: {total} UTXOs checked, {skipped_count} skipped, {} remaining",
        filtered.len()
    );
    Ok(filtered)
}

async fn broadcast_transactions(
    signed_txs: &[(Transaction, Amount, Amount)],
    rpc: &Arc<BitcoinRpc>,
) -> (usize, usize) {
    let success = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));

    let results: Vec<(usize, Result<String, anyhow::Error>)> =
        stream::iter(signed_txs.iter().enumerate())
            .map(|(i, (tx, _fee, _out))| {
                let rpc = rpc.clone();
                let raw_hex = consensus::encode::serialize_hex(tx);
                let success = success.clone();
                let failed = failed.clone();

                async move {
                    match rpc.send_raw_transaction(&raw_hex).await {
                        Ok(txid) => {
                            success.fetch_add(1, Ordering::Relaxed);
                            (i, Ok(txid))
                        }
                        Err(e) => {
                            failed.fetch_add(1, Ordering::Relaxed);
                            (i, Err(e))
                        }
                    }
                }
            })
            .buffer_unordered(BROADCAST_CONCURRENCY)
            .collect()
            .await;

    let mut sorted_results = results;
    sorted_results.sort_by_key(|(i, _)| *i);
    for (i, result) in &sorted_results {
        match result {
            Ok(txid) => println!("  Tx {} broadcast OK: {txid}", i + 1),
            Err(e) => eprintln!("  Tx {} broadcast FAILED: {e}", i + 1),
        }
    }

    (
        success.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
    )
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    let network = parse_network(&args.network)?;

    let destination = Address::from_str(&args.destination)
        .with_context(|| format!("invalid destination address: {}", args.destination))?
        .require_network(network)
        .with_context(|| {
            format!(
                "destination address {} is not valid for network {:?}",
                args.destination, network
            )
        })?;

    let sk_bytes: [u8; 32] = hex::decode(&args.private_key)
        .context("invalid private key hex")?
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))?;
    let parent_sk = S::from_byte_array(&sk_bytes).map_err(|e| anyhow!("invalid scalar: {e}"))?;

    let parent_pk = G::generator() * parent_sk;
    let master_x = parent_pk
        .x_as_be_bytes()
        .map_err(|e| anyhow!("invalid master key: {e}"))?;
    println!("Master public key (x-only): {}", hex::encode(master_x));

    let master_xonly = XOnlyPublicKey::from_slice(&master_x).context("invalid master xonly key")?;
    let master_address =
        bitcoin_utils::single_key_taproot_script_path_address(&master_xonly, network);
    println!("Master deposit address: {}", master_address);

    println!("\nParsing CSV: {}", args.csv.display());
    let utxos = crate::utxo_csv::parse_csv(&args.csv)?;
    let total_amount: u64 = utxos.iter().map(|u| u.amount).sum();
    println!(
        "Parsed {} UTXOs, total: {} sat ({:.8} BTC)",
        utxos.len(),
        total_amount,
        total_amount as f64 / 1e8
    );

    println!("\nDeriving keys and computing addresses...");
    let mut inputs = prepare_inputs(&utxos, &parent_sk, &parent_pk, network)?;
    println!("Prepared {} inputs successfully", inputs.len());

    let rpc = Arc::new(BitcoinRpc::new(
        &args.bitcoin_rpc,
        &args.rpc_user,
        &args.rpc_password,
    ));

    if args.verify {
        println!(
            "\nVerifying UTXOs against Bitcoin node at {}...",
            args.bitcoin_rpc
        );
        inputs = verify_utxos_against_node(inputs, &rpc).await?;
    }

    if inputs.is_empty() {
        println!("\nNo spendable UTXOs found. Nothing to do.");
        return Ok(());
    }

    let fee_rate = FeeRate::from_sat_per_vb(args.fee_rate as u64)
        .ok_or_else(|| anyhow!("invalid fee rate"))?;
    println!("\nFee rate: {} sat/vB", args.fee_rate);
    println!("Destination: {destination}");
    println!("Batch size: {} inputs per tx", args.batch_size);

    let batches: Vec<&[PreparedInput]> = inputs.chunks(args.batch_size).collect();
    println!("\nBuilding {} transactions...", batches.len());

    let mut total_fees = Amount::from_sat(0);
    let mut total_output = Amount::from_sat(0);
    let mut signed_txs: Vec<(Transaction, Amount, Amount)> = Vec::new();

    for (batch_idx, batch) in batches.iter().enumerate() {
        let batch_input_total: Amount = batch.iter().map(|inp| inp.amount).sum();
        let (tx, fee) = build_and_sign_sweep_tx(batch, &destination, fee_rate)?;
        let output_amount = batch_input_total - fee;

        total_fees += fee;
        total_output += output_amount;

        println!(
            "  Tx {}: {} inputs, {} sat in, {} sat out, {} sat fee, txid: {}",
            batch_idx + 1,
            batch.len(),
            batch_input_total.to_sat(),
            output_amount.to_sat(),
            fee.to_sat(),
            tx.compute_txid(),
        );

        signed_txs.push((tx, fee, output_amount));
    }

    let spendable_amount: Amount = inputs.iter().map(|inp| inp.amount).sum();
    println!("\n=== Summary ===");
    println!("Total UTXOs: {}", inputs.len());
    println!(
        "Total input: {} sat ({:.8} BTC)",
        spendable_amount.to_sat(),
        spendable_amount.to_sat() as f64 / 1e8
    );
    println!(
        "Total output: {} sat ({:.8} BTC)",
        total_output.to_sat(),
        total_output.to_sat() as f64 / 1e8
    );
    println!(
        "Total fees: {} sat ({:.8} BTC)",
        total_fees.to_sat(),
        total_fees.to_sat() as f64 / 1e8
    );
    println!("Transactions: {}", signed_txs.len());
    println!("Destination: {destination}");

    if args.broadcast {
        println!("\n=== Broadcasting transactions ({BROADCAST_CONCURRENCY} concurrent) ===");
        let (ok, fail) = broadcast_transactions(&signed_txs, &rpc).await;
        println!("\nBroadcast complete: {ok} succeeded, {fail} failed");
    } else {
        println!("\n=== Signed transaction hex (dry run) ===");
        for (i, (tx, _fee, _out)) in signed_txs.iter().enumerate() {
            let raw_hex = consensus::encode::serialize_hex(tx);
            println!("\n--- Tx {} (txid: {}) ---", i + 1, tx.compute_txid());
            if i == 0 || i == signed_txs.len() - 1 || signed_txs.len() <= 5 {
                println!("{raw_hex}");
            } else if i == 1 {
                println!(
                    "  ... ({} more transactions omitted) ...",
                    signed_txs.len() - 2
                );
            }
        }
        println!("\nDry run complete. Use --broadcast to send transactions to the network.");
    }

    Ok(())
}
