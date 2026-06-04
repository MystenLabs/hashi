// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Taproot descriptor, address, and child-key derivation for the 2-of-2
//! (enclave + Hashi) deposit/withdrawal scheme. The UTXO/transaction types that
//! consume these live in `super::utxo`.

use super::DerivationPath;
use crate::guardian::BitcoinAddress;
use crate::guardian::BitcoinPubkey;
use crate::guardian::HashiMasterG;
use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TapLeafHash;
use bitcoin::*;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::threshold_schnorr::key_derivation::derive_verifying_key;
use miniscript::Descriptor;
use miniscript::descriptor::Tr;
use std::str::FromStr;

/// Creates a taproot descriptor for the given enclave and hashi keys with a 2-of-2 multi_a script.
/// Taproot addresses are constructed as follows:
/// 1. Derive a child hashi pubkey from the derivation path
/// 2. Create a 2-of-2 tapscript with the enclave key and derived hashi key
/// 3. Place the tapscript as the sole leaf with a NUMS internal key
pub fn compute_taproot_descriptor(
    enclave_pubkey: &BitcoinPubkey,
    hashi_master_g: &HashiMasterG,
    hashi_derivation_path: &DerivationPath,
) -> Tr<BitcoinPubkey> {
    let derived_hashi_pubkey = derive_hashi_child_pubkey(hashi_master_g, hashi_derivation_path);

    let internal = nums_internal_key();

    // Taproot descriptor with one leaf: 2-of-2 checksigadd-style multisig
    // Descriptor docs: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
    let desc_str = format!(
        "tr({},multi_a(2,{},{}))",
        internal, enclave_pubkey, derived_hashi_pubkey
    );

    match Descriptor::<BitcoinPubkey>::from_str(&desc_str).expect("valid descriptor") {
        Descriptor::Tr(tr) => tr,
        _ => panic!("unexpected descriptor"),
    }
}

/// Derives the hashi child pubkey at `derivation_path` from `hashi_master_g`.
///
/// `hashi_master_g` must be the raw MPC verifying key with y-parity preserved:
/// `derive_verifying_key` consumes the full `G`, so the x-only/even-y projection
/// would derive a different child for ~half of all vks and break the 2-of-2 leaf
/// script. The returned x-only key is exactly what the MPC protocol signs
/// against. This is the module's canonical statement of the raw-`G` requirement;
/// other sites point here rather than restating it.
pub fn derive_hashi_child_pubkey(
    hashi_master_g: &HashiMasterG,
    hashi_derivation_path: &DerivationPath,
) -> BitcoinPubkey {
    let derived = derive_verifying_key(hashi_master_g, &hashi_derivation_path.into_inner());
    BitcoinPubkey::from_slice(&derived.to_byte_array()).expect("derived schnorr key is x-only")
}

// Use a fixed nothing-up-my-sleeve (NUMS) point as the internal key. Copied from BIP-341.
pub fn nums_internal_key() -> BitcoinPubkey {
    BitcoinPubkey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("valid nums key")
}

/// Computes both the address and leaf script for a given derivation path and network.
pub(super) fn compute_taproot_artifacts(
    enclave_pubkey: &BitcoinPubkey,
    hashi_master_g: &HashiMasterG,
    hashi_derivation_path: &DerivationPath,
) -> (ScriptBuf, TapLeafHash) {
    let desc = compute_taproot_descriptor(enclave_pubkey, hashi_master_g, hashi_derivation_path);

    let address_script = desc.script_pubkey();
    let item = desc
        .leaves()
        .next()
        .expect("tap tree should have at least one leaf");
    let leaf_hash = item.compute_tap_leaf_hash();

    (address_script, leaf_hash)
}

/// Deposit address for `tr(NUMS, multi_a(2, enclave, derived_hashi))`.
pub fn two_of_two_taproot_script_path_address(
    enclave_pubkey: &BitcoinPubkey,
    hashi_master_g: &HashiMasterG,
    hashi_derivation_path: &DerivationPath,
    network: Network,
) -> BitcoinAddress {
    compute_taproot_descriptor(enclave_pubkey, hashi_master_g, hashi_derivation_path)
        .address(network)
}

/// Spend artifacts for `tr(NUMS, multi_a(2, enclave, derived_hashi))`.
pub fn two_of_two_taproot_script_path_spend_artifacts(
    enclave_pubkey: &BitcoinPubkey,
    hashi_master_g: &HashiMasterG,
    hashi_derivation_path: &DerivationPath,
) -> (ScriptBuf, ControlBlock, TapLeafHash) {
    let desc = compute_taproot_descriptor(enclave_pubkey, hashi_master_g, hashi_derivation_path);

    let tap_tree = desc.tap_tree().expect("descriptor should have a tap tree");
    let leaf = tap_tree
        .leaves()
        .next()
        .expect("tap tree should have at least one leaf");
    let tap_script = leaf.compute_script();

    let control_block = desc
        .spend_info()
        .leaves()
        .next()
        .expect("spend info should have at least one leaf")
        .into_control_block();

    let leaf_hash = TapLeafHash::from_script(&tap_script, LeafVersion::TapScript);

    (tap_script, control_block, leaf_hash)
}

#[cfg(test)]
mod bitcoin_tests {
    use super::*;
    use crate::guardian::BitcoinKeypair;
    use crate::guardian::bitcoin_utils::BTC_LIB;
    use crate::guardian::bitcoin_utils::InputUTXO;
    use crate::guardian::bitcoin_utils::OutputUTXOWire;
    use crate::guardian::bitcoin_utils::TxUTXOs;
    use crate::guardian::bitcoin_utils::construct_tx;
    use crate::guardian::bitcoin_utils::sign_btc_tx;
    use crate::guardian::test_utils::create_btc_keypair;
    use bitcoin::Network::Regtest;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::taproot::ControlBlock;
    use bitcoin::taproot::Signature;
    use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;

    const TEST_ENCLAVE_BTC_SK: [u8; 32] = [1u8; 32];
    const TEST_HASHI_BTC_SK: [u8; 32] = [2u8; 32];

    fn gen_keypair_and_address(
        bytes: Option<[u8; 32]>,
        network: Network,
    ) -> (BitcoinKeypair, BitcoinAddress) {
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

    /// Convert a bitcoin-lib x-only key into the even-y `G` point. The
    /// bitcoin-lib `Keypair` always signs against the even-y projection of
    /// its master pubkey, so the descriptor derivation must use the same
    /// parent to agree.
    fn hashi_master_g_from_xonly(pubkey: &BitcoinPubkey) -> HashiMasterG {
        HashiMasterG::with_even_y_from_x_be_bytes(&pubkey.serialize()).expect("valid x coordinate")
    }

    fn create_taproot_artifacts_for_test(
        enclave_pubkey: &BitcoinPubkey,
        hashi_master_pubkey: &BitcoinPubkey,
        hashi_derivation_path: &DerivationPath,
        network: Network,
    ) -> (BitcoinAddress, ControlBlock, ScriptBuf) {
        let hashi_master_g = hashi_master_g_from_xonly(hashi_master_pubkey);
        let addr = two_of_two_taproot_script_path_address(
            enclave_pubkey,
            &hashi_master_g,
            hashi_derivation_path,
            network,
        );
        let (tap_script, control_block, _) = two_of_two_taproot_script_path_spend_artifacts(
            enclave_pubkey,
            &hashi_master_g,
            hashi_derivation_path,
        );
        (addr, control_block, tap_script)
    }

    #[test]
    fn test_pubkey_round_trip() {
        let (hashi_keypair, _) = gen_keypair_and_address(None, Regtest);
        let hashi_pk = hashi_keypair.x_only_public_key().0;

        // Convert Bitcoin BitcoinPubkey -> fastcrypto G -> Bitcoin BitcoinPubkey
        let x_bytes = hashi_pk.serialize();
        let g_point =
            HashiMasterG::with_even_y_from_x_be_bytes(&x_bytes).expect("valid x coordinate");
        let schnorr_key = SchnorrPublicKey::try_from(&g_point).expect("valid schnorr key");
        let reconstructed_x_bytes = schnorr_key.to_byte_array();
        assert_eq!(
            x_bytes, reconstructed_x_bytes,
            "Round-trip conversion should preserve the key"
        );
        let reconstructed_pk =
            BitcoinPubkey::from_slice(&reconstructed_x_bytes).expect("valid x-only key");
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

        let (address, control_block, tap_script) = create_taproot_artifacts_for_test(
            &enclave_pk,
            &hashi_pk,
            &DerivationPath::ZERO,
            Regtest,
        );
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
        let hashi_master_g = hashi_master_g_from_xonly(&hashi_pk);

        let input_amount = Amount::from_sat(100000000); // 1.0 BTC
        let input_utxo = InputUTXO::new(out_point, input_amount, DerivationPath::ZERO);

        // C) Enclave signs the transaction.
        let tx_info = TxUTXOs::new(
            vec![input_utxo.clone()],
            vec![
                // 100 sats sent externally; the rest (minus fee) returns as change.
                OutputUTXOWire::external(
                    dest_address.as_unchecked().clone(),
                    Amount::from_sat(100),
                ),
                OutputUTXOWire::internal(
                    DerivationPath::ZERO,
                    input_amount - Amount::from_sat(1000),
                ),
            ],
            Regtest,
        )
        .unwrap();

        let (messages, _) = tx_info.signing_messages_and_txid(&enclave_pk, &hashi_master_g);
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

        let all_outputs = tx_info.compute_all_outputs(&enclave_pk, &hashi_master_g);
        let signed_tx = construct_tx(vec![input_txin], all_outputs);
        println!("Signed TX: {:#?}", signed_tx);
        println!("TXID: {}", signed_tx.compute_txid());
        println!(
            "Transaction hex: {}",
            consensus::encode::serialize_hex(&signed_tx)
        );
    }

    // Regression: an odd-y MPC master key used to silently disagree between
    // the 2-of-2 leaf script (which reconstructed an even-y parent from the
    // x-only bytes) and the MPC signature (which signs against
    // `derive_verifying_key(raw_g, path)`), giving "Invalid Schnorr signature"
    // at Bitcoin. This builds the real leaf for an odd-y master and asserts it
    // embeds the MPC-signed child key, not the even-y-forced one.
    #[test]
    fn two_of_two_leaf_embeds_mpc_signed_child_for_odd_y_master() {
        use fastcrypto::groups::GroupElement;
        use fastcrypto_tbls::threshold_schnorr::S;

        // Find a master G with ODD y so we exercise the formerly-broken branch.
        let raw_g = loop {
            let mut bytes = [0u8; 32];
            rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
            let g = HashiMasterG::generator() * S::from_bytes_mod_order(&bytes);
            if !g.has_even_y().unwrap() {
                break g;
            }
        };

        let enclave_pubkey = create_btc_keypair(&[7u8; 32]).x_only_public_key().0;
        let path = [42u8; 32];

        // The child key the MPC actually produces signatures against.
        let mpc_child = derive_verifying_key(&raw_g, &path).to_byte_array();
        // The child the old even-y-forcing code would have embedded instead.
        let raw_g_xonly = SchnorrPublicKey::try_from(&raw_g)
            .expect("valid schnorr key")
            .to_byte_array();
        let forced_even =
            HashiMasterG::with_even_y_from_x_be_bytes(&raw_g_xonly).expect("valid x coordinate");
        let buggy_child = derive_verifying_key(&forced_even, &path).to_byte_array();
        assert_ne!(
            buggy_child, mpc_child,
            "odd-y parent must change the child, else this test can't catch the regression"
        );

        // The production 2-of-2 leaf must embed the MPC-signed child.
        let (leaf_script, _, _) = two_of_two_taproot_script_path_spend_artifacts(
            &enclave_pubkey,
            &raw_g,
            &DerivationPath::from(path),
        );
        let script = leaf_script.as_bytes();
        assert!(
            script.windows(32).any(|w| w == mpc_child.as_slice()),
            "2-of-2 leaf must embed the MPC-signed child key"
        );
        assert!(
            !script.windows(32).any(|w| w == buggy_child.as_slice()),
            "2-of-2 leaf must not embed the even-y-forced child key"
        );
    }

    // Cross-language vectors shared with the hashi-ts-sdk (bitcoin.test.ts):
    // both sides must derive the same (child, address, leaf script, tap-leaf
    // hash) or deposit addresses silently diverge. Even-y master forced via
    // `hashi_master_g_from_xonly`; odd-y is the companion test below.
    #[test]
    fn cross_lang_2of2_test_vectors() {
        use bitcoin::hex::DisplayHex;

        let (enclave_keypair, _) = gen_keypair_and_address(Some(TEST_ENCLAVE_BTC_SK), Regtest);
        let (hashi_keypair, _) = gen_keypair_and_address(Some(TEST_HASHI_BTC_SK), Regtest);
        let enclave_pk = enclave_keypair.x_only_public_key().0;
        let hashi_master_pk = hashi_keypair.x_only_public_key().0;
        let master_g = hashi_master_g_from_xonly(&hashi_master_pk);

        // Sanity check that the well-known SKs map to the x-only pubkeys
        // the TS test hardcodes.
        assert_eq!(
            enclave_pk.serialize().as_hex().to_string(),
            "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        );
        assert_eq!(
            hashi_master_pk.serialize().as_hex().to_string(),
            "4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
        );

        struct Case {
            label: &'static str,
            path: DerivationPath,
            expected_derived: &'static str,
            expected_addr_regtest: &'static str,
            expected_addr_signet: &'static str,
            expected_leaf_script: &'static str,
            expected_tap_leaf_hash: &'static str,
        }

        let mut path_ab_cd = [0u8; 32];
        path_ab_cd[0] = 0xab;
        path_ab_cd[31] = 0xcd;

        let cases = [
            Case {
                label: "zero path",
                path: DerivationPath::ZERO,
                expected_derived: "80583e4abd7e73b0868a44e24dd05379375f1c3a85c4c1329bb0572df8577985",
                expected_addr_regtest: "bcrt1p0y0fqatuhy4rwt5ac99z7wse6u8zqzu73jmk0rls57uulnl7q4mq0pk06r",
                expected_addr_signet: "tb1p0y0fqatuhy4rwt5ac99z7wse6u8zqzu73jmk0rls57uulnl7q4mqzcuf0e",
                expected_leaf_script: concat!(
                    "20",
                    "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
                    "ac",
                    "20",
                    "80583e4abd7e73b0868a44e24dd05379375f1c3a85c4c1329bb0572df8577985",
                    "ba529c",
                ),
                expected_tap_leaf_hash: "011aae27d79836b512747c1dff9027feb3e6cfec89e1f94c1f04133e44c58af4",
            },
            Case {
                label: "path = [1u8; 32]",
                path: DerivationPath::from([1u8; 32]),
                expected_derived: "1b79f716fb1f7beba697f012edcf7b81a96ceac2920b181bd217c9cc017ac7fb",
                expected_addr_regtest: "bcrt1pftf88nkuljl4rlsd4xqyq7sy0fzjedws5egf7nuyq4lkkj3hdz2sdfq4a0",
                expected_addr_signet: "tb1pftf88nkuljl4rlsd4xqyq7sy0fzjedws5egf7nuyq4lkkj3hdz2sqs2ng4",
                expected_leaf_script: concat!(
                    "20",
                    "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
                    "ac",
                    "20",
                    "1b79f716fb1f7beba697f012edcf7b81a96ceac2920b181bd217c9cc017ac7fb",
                    "ba529c",
                ),
                expected_tap_leaf_hash: "8db999b8b0372687316ccc75a7d1e940e521009f87b4a580db22a7e221f32ac4",
            },
            Case {
                label: "path = 0xab..00..cd",
                path: DerivationPath::from(path_ab_cd),
                expected_derived: "1403322badfd7823bebf81e9c5ff74f32f856348ac0f5abe33130cc4b6a14c84",
                expected_addr_regtest: "bcrt1pe82wsztzxt97jwkx6wcls257xaycfxw7up4k0ju7r6rsf07zxdlsyg9dfv",
                expected_addr_signet: "tb1pe82wsztzxt97jwkx6wcls257xaycfxw7up4k0ju7r6rsf07zxdlsf30tuk",
                expected_leaf_script: concat!(
                    "20",
                    "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
                    "ac",
                    "20",
                    "1403322badfd7823bebf81e9c5ff74f32f856348ac0f5abe33130cc4b6a14c84",
                    "ba529c",
                ),
                expected_tap_leaf_hash: "733642c74741262b118e37d0fa2071a7b0159a27bea1d5675712ac3f56dea098",
            },
        ];

        for c in &cases {
            let derived = derive_hashi_child_pubkey(&master_g, &c.path);
            assert_eq!(
                derived.serialize().as_hex().to_string(),
                c.expected_derived,
                "derived child mismatch ({})",
                c.label,
            );

            let addr_regtest =
                two_of_two_taproot_script_path_address(&enclave_pk, &master_g, &c.path, Regtest);
            assert_eq!(
                addr_regtest.to_string(),
                c.expected_addr_regtest,
                "regtest address mismatch ({})",
                c.label,
            );

            let addr_signet = two_of_two_taproot_script_path_address(
                &enclave_pk,
                &master_g,
                &c.path,
                Network::Signet,
            );
            assert_eq!(
                addr_signet.to_string(),
                c.expected_addr_signet,
                "signet address mismatch ({})",
                c.label,
            );

            let (script, _control_block, leaf_hash) =
                two_of_two_taproot_script_path_spend_artifacts(&enclave_pk, &master_g, &c.path);
            assert_eq!(script.as_bytes().len(), 70, "leaf script must be 70 bytes");
            assert_eq!(
                script.as_bytes().as_hex().to_string(),
                c.expected_leaf_script,
                "leaf script mismatch ({})",
                c.label,
            );
            assert_eq!(
                leaf_hash.to_string(),
                c.expected_tap_leaf_hash,
                "tap leaf hash mismatch ({})",
                c.label,
            );
        }
    }

    // Odd-y companion to `cross_lang_2of2_test_vectors`: exercises the path
    // #609 fixed, where `derive_hashi_child_pubkey` diverges from the legacy
    // even-y-forcing flow. Seed [4u8;32] is the first scalar in 3..=255 whose
    // `s·G` has odd y; Rust and the SDK both derive against the raw G.
    #[test]
    fn cross_lang_2of2_test_vectors_odd_y() {
        use bitcoin::hex::DisplayHex;
        use fastcrypto::groups::GroupElement;
        use fastcrypto_tbls::threshold_schnorr::S;

        const TEST_HASHI_BTC_SK_ODD_Y: [u8; 32] = [4u8; 32];

        let sk = S::from_bytes_mod_order(&TEST_HASHI_BTC_SK_ODD_Y);
        let master_g = HashiMasterG::generator() * sk;
        assert!(
            !master_g.has_even_y().unwrap(),
            "seed [4u8;32] must land on odd y — if this fires, the upstream curve impl changed",
        );

        let (enclave_keypair, _) = gen_keypair_and_address(Some(TEST_ENCLAVE_BTC_SK), Regtest);
        let enclave_pk = enclave_keypair.x_only_public_key().0;

        let path = DerivationPath::from([1u8; 32]);
        const EXPECTED_DERIVED: &str =
            "d6305db510d6cb87554c942aaaffa3ff277366c2a04b8e64f633cceebd05f937";
        const EXPECTED_ADDR_REGTEST: &str =
            "bcrt1pcpxn30jztmndchw204yr2hjzpy6eqq3k8lauehq2nf2wduu3yzcs2uprtq";
        const EXPECTED_ADDR_SIGNET: &str =
            "tb1pcpxn30jztmndchw204yr2hjzpy6eqq3k8lauehq2nf2wduu3yzcs89t976";
        const EXPECTED_LEAF_SCRIPT: &str = concat!(
            "20",
            "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
            "ac",
            "20",
            "d6305db510d6cb87554c942aaaffa3ff277366c2a04b8e64f633cceebd05f937",
            "ba529c",
        );
        const EXPECTED_TAP_LEAF_HASH: &str =
            "f53aeb1a6730788e60fd358254423f4f1d4b960cc9eefad6055e537c1c89ca52";

        let derived = derive_hashi_child_pubkey(&master_g, &path);
        assert_eq!(derived.serialize().as_hex().to_string(), EXPECTED_DERIVED);

        let addr_regtest =
            two_of_two_taproot_script_path_address(&enclave_pk, &master_g, &path, Regtest);
        assert_eq!(addr_regtest.to_string(), EXPECTED_ADDR_REGTEST);

        let addr_signet =
            two_of_two_taproot_script_path_address(&enclave_pk, &master_g, &path, Network::Signet);
        assert_eq!(addr_signet.to_string(), EXPECTED_ADDR_SIGNET);

        let (script, _control_block, leaf_hash) =
            two_of_two_taproot_script_path_spend_artifacts(&enclave_pk, &master_g, &path);
        assert_eq!(script.as_bytes().len(), 70);
        assert_eq!(script.as_bytes().as_hex().to_string(), EXPECTED_LEAF_SCRIPT);
        assert_eq!(leaf_hash.to_string(), EXPECTED_TAP_LEAF_HASH);
    }
}
