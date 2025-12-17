use crate::GuardianError::InvalidInputs;
use crate::GuardianResult;
use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::*;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::Signature;
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use bitcoin::Address as BitcoinAddress;
use bitcoin::*;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::threshold_schnorr;
use fastcrypto_tbls::threshold_schnorr::key_derivation::derive_verifying_key;
use fastcrypto_tbls::threshold_schnorr::Address as SuiAddress;
use miniscript::descriptor::Tr;
use miniscript::Descriptor;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;
use std::sync::LazyLock;

// ---------------------------------
//    Constants & Type Aliases
// ---------------------------------

pub static BTC_LIB: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);
pub type DerivationPath = SuiAddress;

// ---------------------------------
//    Core Data Structures
// ---------------------------------

/// (Hashi+Guardian)-owned input UTXO
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputUTXO {
    pub txid: Txid,
    pub vout: u32,
    pub amount: Amount,
    pub derivation_path: DerivationPath,
}

/// Withdrawal destination address and amount
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OutputUTXO {
    /// Bitcoin address to withdraw to
    pub address: BitcoinAddress<NetworkUnchecked>,
    /// Amount in satoshis
    pub amount: Amount,
}

/// All the Bitcoin-specific info of a withdrawal tx.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxInfo {
    /// The input UTXOs owned by hashi + guardian
    internal_inputs: Vec<InputUTXO>,
    /// External addresses and amounts
    external_outputs: Vec<OutputUTXO>,
    /// The derivation path for the sole internal output (change address)
    change_derivation_path: DerivationPath,
    /// Transaction fee in satoshis
    fee_sats: Amount,
}

// ---------------------------------
//    Helper Data Structures
// ---------------------------------

/// All data needed to sign a taproot script-path spend for a single input.
pub struct InputSigningData {
    pub txin: TxIn,
    pub prevout: TxOut,
    pub leaf_hash: TapLeafHash,
}

// ---------------------------------
//    Implementations
// ---------------------------------

impl InputUTXO {
    pub fn txin(&self) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: self.txid,
                vout: self.vout,
            },
            // No script sig needed for taproot
            script_sig: ScriptBuf::default(),
            // Enables RBF, disables relative lock time, allows absolute lock time
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            // Witness will be set later
            witness: Witness::default(),
        }
    }

    /// Prepares all data needed for signing this input in one go.
    pub fn prepare_for_signing(
        &self,
        enclave_pubkey: XOnlyPublicKey,
        hashi_pubkey: XOnlyPublicKey,
    ) -> InputSigningData {
        let artifacts =
            compute_taproot_artifacts(enclave_pubkey, hashi_pubkey, &self.derivation_path);
        InputSigningData {
            txin: self.txin(),
            prevout: TxOut {
                value: self.amount,
                script_pubkey: artifacts.0,
            },
            leaf_hash: artifacts.1,
        }
    }
}

impl OutputUTXO {
    /// Validates the address against the expected network and returns a checked TxOut
    pub fn to_txout(&self, network: Network) -> GuardianResult<TxOut> {
        let address = self
            .address
            .clone()
            .require_network(network)
            .map_err(|e| InvalidInputs(format!("Invalid address for the network: {:?}", e)))?;
        Ok(TxOut {
            value: self.amount,
            script_pubkey: address.script_pubkey(),
        })
    }
}

impl TxInfo {
    pub fn new(
        internal_inputs: Vec<InputUTXO>,
        external_outputs: Vec<OutputUTXO>,
        change_derivation_path: DerivationPath,
        fee_sats: Amount,
    ) -> GuardianResult<Self> {
        if internal_inputs.is_empty() {
            return Err(InvalidInputs("internal_inputs must not be empty".into()));
        }
        if external_outputs.is_empty() {
            return Err(InvalidInputs("external_outputs must not be empty".into()));
        }
        let tx_info = Self {
            internal_inputs,
            external_outputs,
            change_derivation_path,
            fee_sats,
        };

        // Validate amounts
        let _ = tx_info.change_amount()?;

        Ok(tx_info)
    }

    pub fn internal_inputs(&self) -> &[InputUTXO] {
        &self.internal_inputs
    }

    pub fn external_outputs(&self) -> &[OutputUTXO] {
        &self.external_outputs
    }

    pub fn change_derivation_path(&self) -> &DerivationPath {
        &self.change_derivation_path
    }

    pub fn fee_sats(&self) -> Amount {
        self.fee_sats
    }

    /// Validates that all withdrawal addresses match the expected network.
    /// Call this early (e.g., when receiving the request) to fail fast.
    pub fn validate_outputs(&self, network: Network) -> GuardianResult<()> {
        for output in &self.external_outputs {
            if !output.address.is_valid_for_network(network) {
                return Err(InvalidInputs("invalid output address".into()));
            }
        }
        Ok(())
    }

    pub fn compute_change_script(
        &self,
        enclave_pubkey: XOnlyPublicKey,
        hashi_pubkey: XOnlyPublicKey,
    ) -> ScriptBuf {
        let change_scripts =
            compute_taproot_artifacts(enclave_pubkey, hashi_pubkey, &self.change_derivation_path);
        change_scripts.0
    }

    /// All outputs including the internal change output.
    /// Assumes addresses have already been validated via `validate_outputs()`.
    /// Panics if addresses don't match network (should never happen after validation).
    pub fn compute_all_outputs(
        &self,
        enclave_pubkey: XOnlyPublicKey,
        hashi_pubkey: XOnlyPublicKey,
        network: Network,
    ) -> Vec<TxOut> {
        let mut all_outs: Vec<TxOut> = self
            .external_outputs
            .iter()
            .map(|utxo| TxOut {
                value: utxo.amount,
                script_pubkey: utxo
                    .address
                    .clone()
                    .require_network(network)
                    .expect("address should be validated before calling compute_all_outputs")
                    .script_pubkey(),
            })
            .collect();

        let change_script = self.compute_change_script(enclave_pubkey, hashi_pubkey);
        let change_out = TxOut {
            // expect because TxInfo::new validates change amounts
            value: self
                .change_amount()
                .expect("change amount should not be negative"),
            script_pubkey: change_script,
        };

        all_outs.push(change_out);

        all_outs
    }

    fn change_amount(&self) -> GuardianResult<Amount> {
        let input_sum = self
            .internal_inputs
            .iter()
            .map(|utxo| utxo.amount)
            .sum::<Amount>();
        let output_sum = self.external_outputs.iter().map(|utxo| utxo.amount).sum();
        if input_sum < output_sum + self.fee_sats {
            return Err(InvalidInputs(
                "Input sum is smaller than output sum + fee".into(),
            ));
        }
        Ok(input_sum - output_sum - self.fee_sats)
    }
}

// -------------------------------------------------
//      Transaction Construction & Signing
// -------------------------------------------------

/// BTC tx signing w/ taproot and script spend path
pub fn sign_btc_tx(messages: &[Message], kp: &Keypair) -> Vec<Signature> {
    messages
        .iter()
        // Not using aux randomness which only provides side-channel protection
        .map(|m| BTC_LIB.sign_schnorr_no_aux_rand(m, kp))
        .map(|s| Signature {
            signature: s,
            sighash_type: TapSighashType::Default,
        })
        .collect()
}

/// Returns the messages to be signed for each input.
/// Panics if tx_info has invalid output addresses. Call tx_info.validate_outputs(network) before.
pub fn construct_signing_messages(
    tx_info: &TxInfo,
    enclave_pubkey: XOnlyPublicKey,
    hashi_pubkey: XOnlyPublicKey,
    network: Network,
) -> GuardianResult<Vec<Message>> {
    // Prepare all input data
    let input_data: Vec<InputSigningData> = tx_info
        .internal_inputs()
        .iter()
        .map(|utxo| utxo.prepare_for_signing(enclave_pubkey, hashi_pubkey))
        .collect();

    // Construct tx
    let all_outputs = tx_info.compute_all_outputs(enclave_pubkey, hashi_pubkey, network);
    let tx = construct_tx(
        input_data.iter().map(|input| input.txin.clone()).collect(),
        all_outputs,
    );

    // Construct signing messages
    let sighash_type = TapSighashType::Default;
    let prevouts: Vec<&TxOut> = input_data.iter().map(|input| &input.prevout).collect();

    input_data
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let mut sighasher = SighashCache::new(tx.clone());
            let sighash = sighasher
                .taproot_script_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    input.leaf_hash,
                    sighash_type,
                )
                .expect("sighash failed unexpectedly");
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

// -------------------------------------------------
//      Taproot Descriptor & Address Computation
// -------------------------------------------------

/// Creates a taproot descriptor for the given enclave and hashi keys with a 2-of-2 multi_a script.
/// Taproot addresses are constructed as follows:
/// 1. Derive a child hashi pubkey from the derivation path
/// 2. Create a 2-of-2 tapscript with the enclave key and derived hashi key
/// 3. Place the tapscript as the sole leaf with a NUMS internal key
pub fn compute_taproot_descriptor(
    enclave_pubkey: XOnlyPublicKey,
    hashi_master_pubkey: XOnlyPublicKey,
    hashi_derivation_path: &DerivationPath,
) -> Tr<XOnlyPublicKey> {
    let derived_hashi_pubkey = get_derived_pubkey(hashi_master_pubkey, hashi_derivation_path);

    // Use a fixed nothing-up-my-sleeve (NUMS) point as the internal key. Copied from BIP-341.
    let internal = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .expect("valid nums key");

    // Taproot descriptor with one leaf: 2-of-2 checksigadd-style multisig
    // Descriptor docs: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
    let desc_str = format!(
        "tr({},multi_a(2,{},{}))",
        internal, enclave_pubkey, derived_hashi_pubkey
    );

    match Descriptor::<XOnlyPublicKey>::from_str(&desc_str).expect("valid descriptor") {
        Descriptor::Tr(tr) => tr,
        _ => panic!("unexpected descriptor"),
    }
}

/// Computes both the address and leaf script for a given derivation path and network.
fn compute_taproot_artifacts(
    enclave_pubkey: XOnlyPublicKey,
    hashi_master_pubkey: XOnlyPublicKey,
    hashi_derivation_path: &DerivationPath,
) -> (ScriptBuf, TapLeafHash) {
    let desc =
        compute_taproot_descriptor(enclave_pubkey, hashi_master_pubkey, hashi_derivation_path);

    let address_script = desc.script_pubkey();
    let item = desc
        .leaves()
        .next()
        .expect("tap tree should have at least one leaf");
    let leaf_hash = item.compute_tap_leaf_hash();

    (address_script, leaf_hash)
}

/// Derives a child public key using unhardened derivation.
/// TODO: Check correctness with Ben or Jonas
fn get_derived_pubkey(
    parent_pubkey: XOnlyPublicKey,
    derivation_path: &DerivationPath,
) -> XOnlyPublicKey {
    // Get x-only public key bytes (32 bytes)
    let x_bytes = parent_pubkey.serialize();

    // Create point with even y-coordinate
    let point =
        threshold_schnorr::G::with_even_y_from_x_be_bytes(&x_bytes).expect("valid x coordinate");

    // Derive the new key
    let derived_schnorr = derive_verifying_key(&point, derivation_path);

    // Get the x-coordinate of the derived key (schnorr keys are x-only with even y)
    let derived_x_bytes = derived_schnorr.to_byte_array();

    // Convert to Bitcoin XOnlyPublicKey
    XOnlyPublicKey::from_slice(&derived_x_bytes).expect("valid x-only key")
}

// ---------------------------------
//    Test Utilities & Tests
// ---------------------------------

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::*;

    pub const TEST_ENCLAVE_SK: [u8; 32] = [1u8; 32];
    pub const TEST_HASHI_SK: [u8; 32] = [2u8; 32];

    pub fn create_keypair(sk: &[u8; 32]) -> Keypair {
        let secret_key = SecretKey::from_slice(sk).expect("valid secret key");
        Keypair::from_secret_key(&BTC_LIB, &secret_key)
    }
}

#[cfg(test)]
mod bitcoin_tests {
    use super::*;
    use crate::bitcoin_utils::test_utils::*;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::taproot::ControlBlock;
    use bitcoin::KnownHrp::Regtest;
    use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;

    fn gen_keypair_and_address(
        bytes: Option<[u8; 32]>,
        network: KnownHrp,
    ) -> (Keypair, BitcoinAddress) {
        let mut rng = rand::thread_rng();
        let bytes = bytes.unwrap_or({
            let mut bytes = [0u8; 32];
            rand::Rng::fill(&mut rng, &mut bytes);
            bytes
        });
        let keypair = create_keypair(&bytes);
        let (internal_key, _) = UntweakedPublicKey::from_keypair(&keypair);
        let address = BitcoinAddress::p2tr(&BTC_LIB, internal_key, None, network);
        (keypair, address)
    }

    fn construct_witness(
        hashi_signature: &Signature,
        enclave_signature: &Signature,
        script: &ScriptBuf,
        control_block: &ControlBlock,
    ) -> Witness {
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

    fn create_taproot_artifacts_for_test(
        enclave_pubkey: XOnlyPublicKey,
        hashi_master_pubkey: XOnlyPublicKey,
        hashi_derivation_path: &DerivationPath,
        network: Network,
    ) -> (BitcoinAddress, ControlBlock, ScriptBuf) {
        let desc =
            compute_taproot_descriptor(enclave_pubkey, hashi_master_pubkey, hashi_derivation_path);
        let addr = desc.address(network);

        let tap_tree = desc.tap_tree().expect("descriptor should have tap tree");
        if tap_tree.leaves().len() != 1 {
            panic!("expected exactly one leaf in tap tree");
        }
        let tap_script = tap_tree.leaves().next().unwrap().compute_script();

        let spend_info = desc.spend_info();
        let control_block = spend_info
            .leaves()
            .next()
            .expect("spend info should have at least one leaf")
            .into_control_block();

        (addr, control_block, tap_script)
    }

    #[test]
    fn test_pubkey_round_trip() {
        let (hashi_keypair, _) = gen_keypair_and_address(None, Regtest);
        let hashi_pk = hashi_keypair.x_only_public_key().0;

        // Convert Bitcoin XOnlyPublicKey -> fastcrypto G -> Bitcoin XOnlyPublicKey
        let x_bytes = hashi_pk.serialize();
        let g_point = threshold_schnorr::G::with_even_y_from_x_be_bytes(&x_bytes)
            .expect("valid x coordinate");
        let schnorr_key = SchnorrPublicKey::try_from(&g_point).expect("valid schnorr key");
        let reconstructed_x_bytes = schnorr_key.to_byte_array();
        assert_eq!(
            x_bytes, reconstructed_x_bytes,
            "Round-trip conversion should preserve the key"
        );
        let reconstructed_pk =
            XOnlyPublicKey::from_slice(&reconstructed_x_bytes).expect("valid x-only key");
        assert_eq!(
            hashi_pk, reconstructed_pk,
            "Round-trip conversion should preserve the key"
        );
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

        let enclave_pk = enclave_keypair.x_only_public_key().0;
        let hashi_pk = hashi_keypair.x_only_public_key().0;

        let (address, control_block, tap_script) =
            create_taproot_artifacts_for_test(enclave_pk, hashi_pk, &[0u8; 32], Network::Regtest);
        println!("\n=== 2-of-2 Multisig Address ===");
        println!("Address: {}", address);
        println!("Enclave pubkey: {}", enclave_pk);
        println!("Hashi pubkey: {}", hashi_pk);

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
        let input_utxo = InputUTXO {
            txid: out_point.txid,
            vout: out_point.vout,
            amount: Amount::from_sat(100000000), // 1.0 BTC
            derivation_path: [0; 32],            // derivation_path = 0 (no derivation in this test)
        };

        // C) Enclave signs the transaction.
        let tx_info = TxInfo::new(
            vec![input_utxo.clone()],
            vec![OutputUTXO {
                address: dest_address.as_unchecked().clone(),
                amount: Amount::from_sat(4990000), // ~0.05 BTC
            }],
            [0; 32],                 // change_derivation_path
            Amount::from_sat(10000), // 0.0001 BTC fee
        )
        .unwrap();

        // Validate addresses early (fail fast)
        tx_info.validate_outputs(Network::Regtest).unwrap();

        let messages =
            construct_signing_messages(&tx_info, enclave_pk, hashi_pk, Network::Regtest).unwrap();
        let enclave_signatures = sign_btc_tx(&messages, &enclave_keypair);

        // D) Hashi signs the transaction.
        let hashi_signatures = sign_btc_tx(&messages, &hashi_keypair);

        // E) Relayer combines the signatures and finalizes the transaction.
        // Note: If there are multiple inputs, we need to construct the witness for each input.
        assert_eq!(enclave_signatures.len(), 1);
        assert_eq!(hashi_signatures.len(), 1);
        let witness = construct_witness(
            &hashi_signatures[0],
            &enclave_signatures[0],
            &tap_script,
            &control_block,
        );

        let mut input_txin = input_utxo.txin();
        input_txin.witness = witness;

        let all_outputs = tx_info.compute_all_outputs(enclave_pk, hashi_pk, Network::Regtest);
        let signed_tx = construct_tx(vec![input_txin], all_outputs);
        println!("Signed TX: {:#?}", signed_tx);
        println!("TXID: {}", signed_tx.compute_txid());
        println!(
            "Transaction hex: {}",
            consensus::encode::serialize_hex(&signed_tx)
        );
    }
}
