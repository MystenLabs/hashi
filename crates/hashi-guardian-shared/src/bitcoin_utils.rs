//! Bitcoin utilities shared between Hashi and Guardian.
//!
//! ## Validation model
//! Types in this module may be:
//! - **constructed locally** (e.g. by an SDK / external library), or
//! - **deserialized from untrusted input** (e.g. a request coming off the wire).
//!
//! To support both flows, types typically provide two layers of validation:
//! - `*_::validate_invariants()` checks network-independent structural invariants (e.g. non-empty vectors,
//!   no duplicate inputs). This is called by `new()` so library users fail fast, and also called by
//!   `validate(...)` to cover serde-based construction.
//! - `*_::validate(network)` should be called at request boundaries. It checks invariants and also enforces
//!   network-dependent constraints (e.g. that all provided addresses match `network`).

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
use std::collections::HashSet;
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
/// TODO: Should we take derivation path as input instead of address & leaf_hash? Investigate later.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputUTXO {
    outpoint: OutPoint,
    amount: Amount,
    address: BitcoinAddress<NetworkUnchecked>,
    leaf_hash: TapLeafHash,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExternalOutputUTXO {
    /// Bitcoin address to withdraw to
    pub address: BitcoinAddress<NetworkUnchecked>,
    /// Amount in satoshis
    pub amount: Amount,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InternalOutputUTXO {
    /// The derivation path
    pub derivation_path: DerivationPath,
    /// Amount in satoshis
    pub amount: Amount,
}

/// Withdrawal destination and amount.
/// External amounts count towards rate limits whereas internal amounts don't.
/// Internal address is derived inside the enclave to ensure that it is actually internal.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum OutputUTXO {
    External(ExternalOutputUTXO),
    Internal(InternalOutputUTXO),
}

/// All the UTXOs associated with a withdrawal transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxUTXOs {
    /// Inputs: internal
    inputs: Vec<InputUTXO>,
    /// Outputs: either external or internal
    outputs: Vec<OutputUTXO>,
}

// ---------------------------------
//    Implementations
// ---------------------------------

/// Validates that an unchecked address is appropriate for `network`.
pub fn validate_address_for_network(
    address: &BitcoinAddress<NetworkUnchecked>,
    network: Network,
) -> GuardianResult<()> {
    if !address.is_valid_for_network(network) {
        return Err(InvalidInputs(format!(
            "invalid output address {:?} for network {}",
            address, network
        )));
    }
    Ok(())
}

/// Represents an input to be spent.
///
/// All inputs are expected to be P2TR (Pay-to-Taproot) since spending is done via taproot script path.
impl InputUTXO {
    /// Constructs a new `InputUTXO` and validates structural invariants.
    ///
    /// To validate the address for a specific network, call `validate(network)`.
    pub fn new(
        outpoint: OutPoint,
        amount: Amount,
        address: BitcoinAddress<NetworkUnchecked>,
        leaf_hash: TapLeafHash,
    ) -> GuardianResult<Self> {
        let utxo = Self {
            outpoint,
            amount,
            address,
            leaf_hash,
        };
        utxo.validate_invariants()?;
        Ok(utxo)
    }

    /// Validates this value, including that the address is valid for `network`.
    pub fn validate(&self, network: Network) -> GuardianResult<()> {
        self.validate_invariants()?;
        validate_address_for_network(&self.address, network)
    }

    /// Validates network-independent structural invariants.
    fn validate_invariants(&self) -> GuardianResult<()> {
        // TODO: Validate amount > 0.
        if !self
            .address
            .clone()
            .assume_checked()
            .script_pubkey()
            .is_p2tr()
        {
            return Err(InvalidInputs("input address is not p2tr".to_string()));
        }
        Ok(())
    }

    /// Returns a `TxIn` for this UTXO with placeholder witness data.
    ///
    /// The witness will be populated later after signing.
    pub fn txin(&self) -> TxIn {
        TxIn {
            previous_output: self.outpoint,
            // No script sig needed for taproot
            script_sig: ScriptBuf::default(),
            // Enables RBF, disables relative lock time, allows absolute lock time
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            // Witness will be set later
            witness: Witness::default(),
        }
    }

    /// Returns the previous output as a `TxOut` (for sighash computation).
    pub fn prevout(&self, network: Network) -> TxOut {
        TxOut {
            value: self.amount,
            script_pubkey: self
                .address
                .clone()
                .require_network(network)
                .expect("address does not match network")
                .script_pubkey(),
        }
    }
}

impl ExternalOutputUTXO {
    pub fn validate(&self, network: Network) -> GuardianResult<()> {
        // TODO: Validate amount > 0
        validate_address_for_network(&self.address, network)
    }
}

/// Represents an output destination for a withdrawal.
///
/// Outputs can be **external** (to a user-provided address) or **internal** (change, derived inside enclave).
impl OutputUTXO {
    /// Validates this value, including external addresses against `network`.
    pub fn validate(&self, network: Network) -> GuardianResult<()> {
        // TODO: Validate amount > 0 (and optionally enforce dust rules for External outputs).
        if let OutputUTXO::External(x) = self {
            x.validate(network)?
        }
        Ok(())
    }

    /// Returns the output amount in satoshis.
    pub fn amount(&self) -> Amount {
        match self {
            OutputUTXO::External(ExternalOutputUTXO { amount, .. }) => *amount,
            OutputUTXO::Internal(InternalOutputUTXO { amount, .. }) => *amount,
        }
    }

    /// Constructs a `TxOut` for this output.
    ///
    /// Requires that `validate(network)` has been called; panics if address doesn't match `network`.
    pub fn to_txout(
        &self,
        enclave_pubkey: &XOnlyPublicKey,
        hashi_pubkey: &XOnlyPublicKey,
        network: Network,
    ) -> TxOut {
        match self {
            OutputUTXO::External(ExternalOutputUTXO { address, amount }) => TxOut {
                value: *amount,
                script_pubkey: address
                    .clone()
                    .require_network(network)
                    .expect("address should be validated before calling compute_all_outputs")
                    .script_pubkey(),
            },
            OutputUTXO::Internal(InternalOutputUTXO {
                derivation_path,
                amount,
            }) => {
                let scripts =
                    compute_taproot_artifacts(enclave_pubkey, hashi_pubkey, derivation_path);
                TxOut {
                    value: *amount,
                    script_pubkey: scripts.0,
                }
            }
        }
    }
}

impl TxUTXOs {
    /// Constructs a new `TxUTXOs` and validates structural invariants.
    ///
    /// To validate addresses for a specific network, call `validate(network)`.
    pub fn new(inputs: Vec<InputUTXO>, outputs: Vec<OutputUTXO>) -> GuardianResult<Self> {
        let tx_info = Self { inputs, outputs };
        tx_info.validate_invariants()?;
        Ok(tx_info)
    }

    /// Validates this value, including that all inputs and outputs are valid for `network`.
    pub fn validate(&self, network: Network) -> GuardianResult<()> {
        self.validate_invariants()?;
        self.inputs
            .iter()
            .try_for_each(|utxo| utxo.validate(network))?;
        self.outputs
            .iter()
            .try_for_each(|utxo| utxo.validate(network))
    }

    /// Validates network-independent structural invariants.
    fn validate_invariants(&self) -> GuardianResult<()> {
        if self.inputs.is_empty() {
            return Err(InvalidInputs("input utxos must not be empty".into()));
        }
        if self.outputs.is_empty() {
            return Err(InvalidInputs("output utxos must not be empty".into()));
        }

        // Disallow duplicate inputs (same txid,vout), which would result in an invalid transaction.
        let mut seen_inputs: HashSet<OutPoint> = HashSet::with_capacity(self.inputs.len());
        for utxo in &self.inputs {
            if !seen_inputs.insert(utxo.outpoint) {
                return Err(InvalidInputs(format!(
                    "duplicate input outpoint: {}",
                    utxo.outpoint
                )));
            }
        }

        // Enforce the intended invariant: fees > 0.
        let _ = self.fees()?;

        Ok(())
    }

    /// Returns a reference to the inputs.
    pub fn get_inputs(&self) -> &[InputUTXO] {
        &self.inputs
    }

    /// Returns a reference to the outputs.
    pub fn get_outputs(&self) -> &[OutputUTXO] {
        &self.outputs
    }

    /// Constructs all outputs (both external and internal).
    ///
    /// For `External` outputs, uses the user-provided address. For `Internal` outputs,
    /// derives a taproot address using the enclave and hashi keys.
    ///
    /// Requires that `validate(network)` has been called.
    pub fn compute_all_outputs(
        &self,
        enclave_pubkey: &XOnlyPublicKey,
        hashi_pubkey: &XOnlyPublicKey,
        network: Network,
    ) -> Vec<TxOut> {
        self.outputs
            .iter()
            .map(|utxo| utxo.to_txout(enclave_pubkey, hashi_pubkey, network))
            .collect()
    }

    pub fn external_outs(&self) -> Vec<&ExternalOutputUTXO> {
        self.outputs
            .iter()
            .filter_map(|utxo| match utxo {
                OutputUTXO::External(x) => Some(x),
                OutputUTXO::Internal(_) => None,
            })
            .collect::<Vec<_>>()
    }

    pub fn external_out_amount(&self) -> Amount {
        self.outputs
            .iter()
            .filter_map(|utxo| match utxo {
                OutputUTXO::External(x) => Some(x.amount),
                OutputUTXO::Internal(_) => None,
            })
            .sum()
    }

    fn fees(&self) -> GuardianResult<Amount> {
        let input_sum = self.inputs.iter().map(|utxo| utxo.amount).sum::<Amount>();
        let output_sum = self.outputs.iter().map(|utxo| utxo.amount()).sum();
        if input_sum <= output_sum {
            return Err(InvalidInputs(format!(
                "fees must be positive: input_sum={} output_sum={}",
                input_sum, output_sum
            )));
        }
        Ok(input_sum - output_sum)
    }
}

// -------------------------------------------------
//      Transaction Construction & Signing
// -------------------------------------------------

/// Signs messages using Schnorr signatures (suitable for taproot script-spend).
///
/// Each message is signed and wrapped in a `Signature` with `TapSighashType::Default`.
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

/// Constructs sighash messages for each input, ready for signing.
///
/// Uses `taproot_script_spend_signature_hash` for script-path spending.
///
/// Requires that `tx_info.validate(network)` has been called.
pub fn construct_signing_messages(
    tx_info: &TxUTXOs,
    enclave_pubkey: &XOnlyPublicKey,
    hashi_pubkey: &XOnlyPublicKey,
    network: Network,
) -> Vec<Message> {
    let inputs = tx_info.get_inputs();

    // Construct tx
    let all_outputs = tx_info.compute_all_outputs(enclave_pubkey, hashi_pubkey, network);
    let tx = construct_tx(
        inputs.iter().map(|input| input.txin()).collect(),
        all_outputs,
    );

    // Construct signing messages
    let prevouts: Vec<TxOut> = inputs.iter().map(|input| input.prevout(network)).collect();

    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let mut sighasher = SighashCache::new(tx.clone());
            let sighash = sighasher
                .taproot_script_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    input.leaf_hash,
                    TapSighashType::Default,
                )
                .expect("sighash failed unexpectedly");
            Message::from_digest(*sighash.as_byte_array())
        })
        .collect::<Vec<Message>>()
}

/// Constructs a Bitcoin transaction with the given inputs and outputs.
///
/// Uses BTC tx version 2 and disables lock time.
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
    enclave_pubkey: &XOnlyPublicKey,
    hashi_master_pubkey: &XOnlyPublicKey,
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
    enclave_pubkey: &XOnlyPublicKey,
    hashi_master_pubkey: &XOnlyPublicKey,
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

/// Derives a child public key using unhardened derivation from a parent public key.
///
/// Uses the provided derivation path to compute a new public key.
fn get_derived_pubkey(
    parent_pubkey: &XOnlyPublicKey,
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

#[cfg(test)]
mod bitcoin_tests {
    use super::*;
    use crate::test_utils::create_btc_keypair;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::taproot::ControlBlock;
    use bitcoin::Network::Regtest;
    use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;

    const TEST_ENCLAVE_BTC_SK: [u8; 32] = [1u8; 32];
    const TEST_HASHI_BTC_SK: [u8; 32] = [2u8; 32];

    fn gen_keypair_and_address(
        bytes: Option<[u8; 32]>,
        network: Network,
    ) -> (Keypair, BitcoinAddress) {
        let mut rng = rand::thread_rng();
        let bytes = bytes.unwrap_or({
            let mut bytes = [0u8; 32];
            rand::Rng::fill(&mut rng, &mut bytes);
            bytes
        });
        let keypair = create_btc_keypair(&bytes);
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
        enclave_pubkey: &XOnlyPublicKey,
        hashi_master_pubkey: &XOnlyPublicKey,
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
        let (enclave_keypair, _) = gen_keypair_and_address(Some(TEST_ENCLAVE_BTC_SK), Regtest);
        let (hashi_keypair, _) = gen_keypair_and_address(Some(TEST_HASHI_BTC_SK), Regtest);

        let enclave_pk = enclave_keypair.x_only_public_key().0;
        let hashi_pk = hashi_keypair.x_only_public_key().0;

        let (address, control_block, tap_script) =
            create_taproot_artifacts_for_test(&enclave_pk, &hashi_pk, &[0u8; 32], Regtest);
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
        let (_, leaf_hash) = compute_taproot_artifacts(&enclave_pk, &hashi_pk, &[0u8; 32]);

        let input_amount = Amount::from_sat(100000000); // 1.0 BTC
        let input_utxo = InputUTXO::new(
            out_point,
            input_amount,
            address.as_unchecked().clone(),
            leaf_hash,
        )
        .unwrap();

        // C) Enclave signs the transaction.
        let tx_info = TxUTXOs::new(
            vec![input_utxo.clone()],
            vec![
                OutputUTXO::External(ExternalOutputUTXO {
                    address: dest_address.as_unchecked().clone(),
                    amount: Amount::from_sat(100), // 100 sats is sent
                }),
                OutputUTXO::Internal(InternalOutputUTXO {
                    derivation_path: [0; 32],
                    amount: input_amount - Amount::from_sat(1000),
                }),
            ],
        )
        .unwrap();

        // Validate early (fail fast)
        tx_info.validate(Regtest).unwrap();

        let messages = construct_signing_messages(&tx_info, &enclave_pk, &hashi_pk, Regtest);
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

        let all_outputs = tx_info.compute_all_outputs(&enclave_pk, &hashi_pk, Regtest);
        let signed_tx = construct_tx(vec![input_txin], all_outputs);
        println!("Signed TX: {:#?}", signed_tx);
        println!("TXID: {}", signed_tx.compute_txid());
        println!(
            "Transaction hex: {}",
            consensus::encode::serialize_hex(&signed_tx)
        );
    }
}
