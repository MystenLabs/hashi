use crate::GuardianError::CryptoError;
use crate::GuardianResult;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::Signature;
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::Witness;
use serde::Deserialize;
use serde::Serialize;

// Represents a UTXO that will be spent using taproot script-path spending.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaprootUTXO {
    pub txid: Txid,
    pub vout: u32,
    pub amount: Amount,
    pub script_pubkey: ScriptBuf, // P2TR script that locks the UTXO (what's on-chain)
    pub leaf_script: ScriptBuf,   // The specific tapscript leaf being executed
}

impl TaprootUTXO {
    pub fn to_txout(&self) -> TxOut {
        TxOut {
            value: self.amount,
            script_pubkey: self.script_pubkey.clone(),
        }
    }

    pub fn to_txin(&self) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: self.txid,
                vout: self.vout,
            },
            // No script sig needed for taproot
            script_sig: ScriptBuf::default(),
            // TODO: Discuss what this needs to be set to
            sequence: Sequence::MAX,
            // Witness will be set later
            witness: Witness::default(),
        }
    }
}

/// BTC tx signing w/ taproot and script spend path
pub fn sign_btc_tx(
    secp: &Secp256k1<All>,
    input_utxos: &[TaprootUTXO],
    output_utxos: &[TxOut],
    change_utxo: TxOut,
    sk: &SecretKey,
) -> GuardianResult<Vec<Signature>> {
    let messages = construct_signing_messages(input_utxos, output_utxos, change_utxo)?;
    let keypair = Keypair::from_secret_key(secp, sk);
    Ok(messages
        .iter()
        // TODO: Discuss if we want to use auxiliary randomness in the signing process
        .map(|m| secp.sign_schnorr(m, &keypair))
        .map(|s| Signature {
            signature: s,
            sighash_type: TapSighashType::Default,
        })
        .collect())
}

pub fn construct_signing_messages(
    input_utxos: &[TaprootUTXO],
    output_utxos: &[TxOut],
    change_utxo: TxOut,
) -> GuardianResult<Vec<Message>> {
    let mut all_outputs = output_utxos.to_vec();
    all_outputs.push(change_utxo);
    let tx = construct_tx(
        input_utxos.iter().map(|utxo| utxo.to_txin()).collect(),
        all_outputs,
    );

    let sighash_type = TapSighashType::Default;
    let mut messages = Vec::new();
    let prevouts: Vec<TxOut> = input_utxos.iter().map(|utxo| utxo.to_txout()).collect();

    for (index, input_utxo) in input_utxos.iter().enumerate() {
        let mut sighasher = SighashCache::new(tx.clone());
        let leaf_hash = TapLeafHash::from_script(&input_utxo.leaf_script, LeafVersion::TapScript);

        let sighash = sighasher
            .taproot_script_spend_signature_hash(
                index,
                &Prevouts::All(&prevouts),
                leaf_hash,
                sighash_type,
            )
            .map_err(|e| CryptoError(format!("sighash error {}", e)))?;
        messages.push(Message::from_digest(*sighash.as_byte_array()));
    }
    Ok(messages)
}

fn construct_tx(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
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
    use bitcoin::opcodes::all::OP_CHECKSIG;
    use bitcoin::opcodes::all::OP_CHECKSIGADD;
    use bitcoin::opcodes::all::OP_NUMEQUAL;
    use bitcoin::opcodes::all::OP_PUSHNUM_2;
    use bitcoin::script::Builder;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::taproot::TaprootBuilder;
    use bitcoin::KnownHrp::Regtest;
    use bitcoin::XOnlyPublicKey;

    pub const TEST_ENCLAVE_SK: [u8; 32] = [1u8; 32]; // Fingerprint: 9Azq+G5XdpIzMrjY/TvvhJytsZxplrwnKvH2SNlWakw=
    pub const TEST_HASHI_SK: [u8; 32] = [2u8; 32];

    fn gen_keypair_and_address(
        secp: &Secp256k1<All>,
        bytes: Option<[u8; 32]>,
        network: bitcoin::KnownHrp,
    ) -> (Keypair, bitcoin::Address) {
        let mut rng = rand::thread_rng();
        let bytes = bytes.unwrap_or({
            let mut bytes = [0u8; 32];
            rand::Rng::fill(&mut rng, &mut bytes);
            bytes
        });
        let secret_key = SecretKey::from_slice(&bytes).expect("valid secret key");
        let keypair = Keypair::from_secret_key(secp, &secret_key);
        let (internal_key, _) = UntweakedPublicKey::from_keypair(&keypair);
        let address = bitcoin::Address::p2tr(secp, internal_key, None, network);
        (keypair, address)
    }

    fn construct_witness(
        hashi_signature: &bitcoin::taproot::Signature,
        enclave_signature: &bitcoin::taproot::Signature,
        script: &ScriptBuf,
        spend_info: &bitcoin::taproot::TaprootSpendInfo,
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
        secp: &Secp256k1<All>,
        enclave_pubkey: bitcoin::XOnlyPublicKey,
        hashi_pubkey: bitcoin::XOnlyPublicKey,
        network: bitcoin::KnownHrp,
    ) -> (
        bitcoin::Address,
        bitcoin::taproot::TaprootSpendInfo,
        ScriptBuf,
    ) {
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
            .finalize(secp, nums_key)
            .expect("finalize taproot");

        let address = bitcoin::Address::p2tr(secp, nums_key, spend_info.merkle_root(), network);
        (address, spend_info, tap_script)
    }

    #[test]
    fn test_taproot_key_spend_path() {
        let secp = Secp256k1::new();
        let (keypair, address) = gen_keypair_and_address(&secp, None, Regtest);
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
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
        };

        let mut tx = construct_tx(vec![input], vec![spend, change]);

        let input_index = 0;
        let prevouts = Prevouts::All(&[prev_utxo]);
        let sighash_type = TapSighashType::Default;

        let mut sighasher = SighashCache::new(&mut tx);
        let sighash = sighasher
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .unwrap();

        let tweaked = keypair.tap_tweak(&secp, None);
        let msg = sighash.into();
        let sign = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.into());

        // Update the witness stack.
        let signature = bitcoin::taproot::Signature {
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
        let secp = Secp256k1::new();
        let (enclave_keypair, _) = gen_keypair_and_address(&secp, Some(TEST_ENCLAVE_SK), Regtest);
        let (hashi_keypair, _) = gen_keypair_and_address(&secp, Some(TEST_HASHI_SK), Regtest);

        let enclave_x = XOnlyPublicKey::from_keypair(&enclave_keypair).0;
        let hashi_x = XOnlyPublicKey::from_keypair(&hashi_keypair).0;

        let (address, spend_info, tap_script) =
            create_2_of_2_taproot_address(&secp, enclave_x, hashi_x, Regtest);
        println!("\n=== 2-of-2 Multisig Address ===");
        println!("Address: {}", address);
        println!("Enclave pubkey: {}", enclave_x);
        println!("Hashi pubkey: {}", hashi_x);

        // A) User picks destination address.
        const DEST_SK: [u8; 32] = [3u8; 32];
        let (_, dest_address) = gen_keypair_and_address(&secp, Some(DEST_SK), Regtest);

        // B) Hashi selects a UTXO
        // NOTE: Paste a real regtest UTXO to obtain a broadcastable tx.
        let out_point = OutPoint {
            txid: "f62f8d94074084555bd28187a4c79648c72571e53b5e2ba823bdf92b2cc1f88c"
                .parse()
                .unwrap(),
            vout: 1,
        };
        let input_utxo = TaprootUTXO {
            txid: out_point.txid,
            vout: out_point.vout,
            amount: Amount::from_sat(100000000), // 1.0 BTC
            script_pubkey: address.script_pubkey(),
            leaf_script: tap_script.clone(),
        };

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
            &secp,
            std::slice::from_ref(&input_utxo),
            std::slice::from_ref(&spend_out),
            change_out.clone(),
            &enclave_keypair.secret_key(),
        )
        .unwrap();

        // D) Hashi signs the transaction.
        let hashi_signatures = sign_btc_tx(
            &secp,
            std::slice::from_ref(&input_utxo),
            std::slice::from_ref(&spend_out),
            change_out.clone(),
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

        let mut input_utxo = input_utxo.to_txin();
        input_utxo.witness = witness;

        let signed_tx = construct_tx(vec![input_utxo], vec![spend_out, change_out]);
        println!("Signed TX: {:#?}", signed_tx);
        println!("TXID: {}", signed_tx.compute_txid());
        println!(
            "Transaction hex: {}",
            bitcoin::consensus::encode::serialize_hex(&signed_tx)
        );
    }
}
