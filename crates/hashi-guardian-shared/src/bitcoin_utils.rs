use crate::GuardianError::{InternalError, InvalidInputs};
use crate::GuardianResult;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::*;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::Signature;
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use bitcoin::*;
use serde::Deserialize;
use serde::Serialize;
use std::sync::LazyLock;

static BTC_LIB: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// Represents a UTXO that will be spent using taproot script-path spending.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaprootUTXO {
    txid: Txid,
    vout: u32,
    amount: Amount,
    script_pubkey: ScriptBuf, // P2TR script that locks the UTXO (what's on-chain)
    leaf_script: ScriptBuf,   // The specific tapscript leaf being executed
}

impl TaprootUTXO {
    pub fn new(
        txid: Txid,
        vout: u32,
        amount: Amount,
        script_pubkey: ScriptBuf,
        leaf_script: ScriptBuf,
    ) -> GuardianResult<Self> {
        if !script_pubkey.is_p2tr() {
            return Err(InvalidInputs("script is not P2TR".into()));
        }
        if leaf_script.is_empty() {
            return Err(InvalidInputs("leaf script must not be empty".into()));
        }
        Ok(Self {
            txid,
            vout,
            amount,
            script_pubkey,
            leaf_script,
        })
    }

    pub fn txout(&self) -> TxOut {
        TxOut {
            value: self.amount,
            script_pubkey: self.script_pubkey.clone(),
        }
    }

    pub fn txin(&self) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: self.txid,
                vout: self.vout,
            },
            // No script sig needed for taproot
            script_sig: ScriptBuf::default(),
            // Enables RBF, disables relative lock time, allows absolute lock time
            // TODO: Is that what we want?
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            // Witness will be set later
            witness: Witness::default(),
        }
    }
}

/// BTC tx signing w/ taproot and script spend path
pub fn sign_btc_tx(
    input_utxos: &[TaprootUTXO],
    output_utxos: &[TxOut],
    change_utxo: &TxOut,
    sk: &SecretKey,
) -> GuardianResult<Vec<Signature>> {
    let messages = construct_signing_messages(input_utxos, output_utxos, change_utxo)?;
    let keypair = Keypair::from_secret_key(&BTC_LIB, sk);
    Ok(messages
        .iter()
        // TODO: Discuss if we want to use auxiliary randomness in the signing process
        .map(|m| BTC_LIB.sign_schnorr(m, &keypair))
        .map(|s| Signature {
            signature: s,
            sighash_type: TapSighashType::Default,
        })
        .collect())
}

pub fn construct_signing_messages(
    input_utxos: &[TaprootUTXO],
    output_utxos: &[TxOut],
    change_utxo: &TxOut,
) -> GuardianResult<Vec<Message>> {
    // Input Validation
    if input_utxos.is_empty() {
        return Err(InvalidInputs("input utxos must not be empty".into()));
    }
    if output_utxos.is_empty() {
        return Err(InvalidInputs("output utxos must not be empty".into()));
    }
    let in_amount = input_utxos.iter().map(|utxo| utxo.amount).sum::<Amount>();
    let out_amount = output_utxos.iter().map(|utxo| utxo.value).sum::<Amount>();
    let change_amount = change_utxo.value;
    if in_amount < out_amount + change_amount {
        return Err(InvalidInputs("Amount mismatch".into()));
    }

    // Construct tx
    let mut all_outputs = output_utxos.to_vec();
    all_outputs.push(change_utxo.clone());
    let tx = construct_tx(
        input_utxos.iter().map(|utxo| utxo.txin()).collect(),
        all_outputs,
    );

    // Construct signing messages
    let sighash_type = TapSighashType::Default;
    let prevouts: Vec<TxOut> = input_utxos.iter().map(|utxo| utxo.txout()).collect();
    input_utxos
        .iter()
        .enumerate()
        .map(|(index, input_utxo)| {
            let mut sighasher = SighashCache::new(tx.clone());
            let leaf_hash =
                TapLeafHash::from_script(&input_utxo.leaf_script, LeafVersion::TapScript);
            let sighash = sighasher
                .taproot_script_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    leaf_hash,
                    sighash_type,
                )
                .map_err(|e| InternalError(format!("sighash error: {}", e)))?;
            Ok(Message::from_digest(*sighash.as_byte_array()))
        })
        .collect::<GuardianResult<Vec<Message>>>()
}

fn construct_tx(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        // The latest BTC tx version
        version: Version::TWO,
        // Disable absolute lock time (i.e., can be mined immediately)
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

#[cfg(test)]
mod bitcoin_tests {
    use super::*;
    use bitcoin::key::TapTweak;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::opcodes::all::*;
    use bitcoin::script::Builder;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};
    use bitcoin::KnownHrp::Regtest;

    pub const TEST_ENCLAVE_SK: [u8; 32] = [1u8; 32]; // Fingerprint: 9Azq+G5XdpIzMrjY/TvvhJytsZxplrwnKvH2SNlWakw=
    pub const TEST_HASHI_SK: [u8; 32] = [2u8; 32];

    fn gen_keypair_and_address(bytes: Option<[u8; 32]>, network: KnownHrp) -> (Keypair, Address) {
        let mut rng = rand::thread_rng();
        let bytes = bytes.unwrap_or({
            let mut bytes = [0u8; 32];
            rand::Rng::fill(&mut rng, &mut bytes);
            bytes
        });
        let secret_key = SecretKey::from_slice(&bytes).expect("valid secret key");
        let keypair = Keypair::from_secret_key(&BTC_LIB, &secret_key);
        let (internal_key, _) = UntweakedPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&BTC_LIB, internal_key, None, network);
        (keypair, address)
    }

    fn construct_witness(
        hashi_signature: &Signature,
        enclave_signature: &Signature,
        script: &ScriptBuf,
        spend_info: &TaprootSpendInfo,
    ) -> Witness {
        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("control block");

        // Witness stack order: [sig_for_pk2, sig_for_pk1, script, control_block]
        // Since our script is <pk1> OP_CHECKSIG <pk2> OP_CHECKSIGADD ...
        // And stack is LIFO, we need: [hashi_sig, enclave_sig, script, control]
        let hashi_sig_vec = hashi_signature.to_vec();
        let enclave_sig_vec = enclave_signature.to_vec();
        let control_block_vec = control_block.serialize();
        let witness_elements: Vec<Vec<u8>> = vec![
            hashi_sig_vec,     // sig for pk2 (hashi)
            enclave_sig_vec,   // sig for pk1 (enclave)
            script.to_bytes(), // script
            control_block_vec, // control block
        ];
        Witness::from_slice(&witness_elements)
    }

    fn create_2_of_2_taproot_address(
        enclave_pubkey: XOnlyPublicKey,
        hashi_pubkey: XOnlyPublicKey,
        network: KnownHrp,
    ) -> (Address, taproot::TaprootSpendInfo, ScriptBuf) {
        // Tapscript 2-of-2 with CHECKSIGADD pattern:
        // <enclave_pubkey> OP_CHECKSIG <hashi_pubkey> OP_CHECKSIGADD OP_PUSHNUM_2 OP_NUMEQUAL
        let tap_script = Builder::new()
            .push_x_only_key(&enclave_pubkey)
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&hashi_pubkey)
            .push_opcode(OP_CHECKSIGADD)
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_NUMEQUAL)
            .into_script();

        // Use a nothing-up-my-sleeve (NUMS) point as the internal key
        // Copied from BIP-341 doc.
        // TODO: Confirm ourselves that it is indeed secure
        let nums_key = UntweakedPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .expect("valid nums key");

        // Build taproot spend info
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, tap_script.clone())
            .expect("add leaf")
            .finalize(&BTC_LIB, nums_key)
            .expect("finalize taproot");

        let address = Address::p2tr(&BTC_LIB, nums_key, spend_info.merkle_root(), network);
        (address, spend_info, tap_script)
    }

    #[test]
    fn test_taproot_key_spend_path() {
        let (keypair, address) = gen_keypair_and_address(None, Regtest);
        let (internal_key, _) = UntweakedPublicKey::from_keypair(&keypair);

        let prev_utxo = TxOut {
            value: Amount::from_sat(1000000),
            script_pubkey: address.script_pubkey(),
        };

        let input = TxIn {
            previous_output: OutPoint::default(),
            // No script sig needed for taproot
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ZERO,
            witness: Witness::default(),
        };

        let spend = TxOut {
            value: Amount::from_sat(1000000),
            script_pubkey: address.script_pubkey(),
        };

        let change = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new_p2tr(&BTC_LIB, internal_key, None),
        };

        let mut tx = construct_tx(vec![input], vec![spend, change]);

        let input_index = 0;
        let prevouts = Prevouts::All(&[prev_utxo]);
        let sighash_type = TapSighashType::Default;

        let mut sighasher = SighashCache::new(&mut tx);
        let sighash = sighasher
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .unwrap();

        let tweaked = keypair.tap_tweak(&BTC_LIB, None);
        let msg = sighash.into();
        let sign = BTC_LIB.sign_schnorr_no_aux_rand(&msg, &tweaked.into());

        // Update the witness stack.
        let signature = Signature {
            signature: sign,
            sighash_type,
        };
        *sighasher.witness_mut(input_index).unwrap() = Witness::p2tr_key_spend(&signature);

        let signed_tx = sighasher.into_transaction();

        println!("Signed TX: {:#?}", signed_tx);
    }

    // Party 1: Enclave
    // Party 2: Hashi
    // Scenario:
    //  A) User picks destination address.
    //  B) Hashi selects the utxo.
    //  C) Enclave signs the transaction
    //  D) Hashi signs the transaction
    //  E) Relayer combines the signatures and pushes the transaction to the network.
    #[test]
    fn test_taproot_multi_party_tx_signing() {
        let (enclave_keypair, _) = gen_keypair_and_address(Some(TEST_ENCLAVE_SK), Regtest);
        let (hashi_keypair, _) = gen_keypair_and_address(Some(TEST_HASHI_SK), Regtest);

        let enclave_x = XOnlyPublicKey::from_keypair(&enclave_keypair).0;
        let hashi_x = XOnlyPublicKey::from_keypair(&hashi_keypair).0;

        let (address, spend_info, tap_script) =
            create_2_of_2_taproot_address(enclave_x, hashi_x, Regtest);
        println!("\n=== 2-of-2 Multisig Address ===");
        println!("Address: {}", address);
        println!("Enclave pubkey: {}", enclave_x);
        println!("Hashi pubkey: {}", hashi_x);

        // A) User picks destination address.
        const DEST_SK: [u8; 32] = [3u8; 32];
        let (_, dest_address) = gen_keypair_and_address(Some(DEST_SK), Regtest);

        // B) Hashi selects a UTXO
        // NOTE: Paste a real regtest UTXO to obtain a broadcastable tx.
        let out_point = OutPoint {
            txid: "f62f8d94074084555bd28187a4c79648c72571e53b5e2ba823bdf92b2cc1f88c"
                .parse()
                .unwrap(),
            vout: 1,
        };
        let input_utxo = TaprootUTXO::new(
            out_point.txid,
            out_point.vout,
            Amount::from_sat(100000000), // 1.0 BTC
            address.script_pubkey(),
            tap_script.clone(),
        )
        .unwrap();

        let spend_out = TxOut {
            value: Amount::from_sat(4990000), // ~0.05 BTC (leaving room for fees)
            script_pubkey: dest_address.script_pubkey(),
        };

        // Note: sending mostly to self for ease of testing..
        let change_out = TxOut {
            value: Amount::from_sat(95000000),      // 0.95 BTC
            script_pubkey: address.script_pubkey(), // back to self
        };

        // C) Enclave signs the transaction.
        let enclave_signatures = sign_btc_tx(
            std::slice::from_ref(&input_utxo),
            std::slice::from_ref(&spend_out),
            &change_out,
            &enclave_keypair.secret_key(),
        )
        .unwrap();

        // D) Hashi signs the transaction.
        let hashi_signatures = sign_btc_tx(
            std::slice::from_ref(&input_utxo),
            std::slice::from_ref(&spend_out),
            &change_out,
            &hashi_keypair.secret_key(),
        )
        .unwrap();

        // E) Relayer combines the signatures and finalizes the transaction.
        // Note: If there are multiple inputs, we need to construct the witness for each input.
        assert_eq!(enclave_signatures.len(), 1);
        assert_eq!(hashi_signatures.len(), 1);
        let witness = construct_witness(
            &hashi_signatures[0],
            &enclave_signatures[0],
            &tap_script,
            &spend_info,
        );

        let mut input_utxo = input_utxo.txin();
        input_utxo.witness = witness;

        let signed_tx = construct_tx(vec![input_utxo], vec![spend_out, change_out]);
        println!("Signed TX: {:#?}", signed_tx);
        println!("TXID: {}", signed_tx.compute_txid());
        println!(
            "Transaction hex: {}",
            consensus::encode::serialize_hex(&signed_tx)
        );
    }
}
