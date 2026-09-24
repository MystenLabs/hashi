// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Spend data stored with each UTXO when it is created, and the checks that
//! let signing read it instead of re-deriving it from node code.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::anyhow;
use bitcoin::Amount;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::threshold_schnorr::G;
use hashi_types::bitcoin as hashi_bitcoin;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::bitcoin::CheckedSpend;
use hashi_types::bitcoin::SpendRecordError;
use hashi_types::bitcoin_txid::BitcoinTxid;
use sui_sdk_types::Address;

use crate::Hashi;
use crate::onchain::types::OutputUtxo;
use crate::onchain::types::SpendData;
use crate::onchain::types::Utxo;
use crate::onchain::types::UtxoId;

#[derive(Clone, Copy, Debug)]
pub(crate) enum SpendCheckSite {
    Deposit,
    Commit,
    LeaderBuild,
    Signing,
    ChunkCheck,
    Finalize,
    LeaderCollection,
    Broadcast,
}

impl SpendCheckSite {
    fn label(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Commit => "commit",
            Self::LeaderBuild => "leader_build",
            Self::Signing => "signing",
            Self::ChunkCheck => "chunk_check",
            Self::Finalize => "finalize",
            Self::LeaderCollection => "leader_collection",
            Self::Broadcast => "broadcast",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SpendAt {
    Input(usize),
    Utxo,
}

impl std::fmt::Display for SpendAt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(index) => write!(f, "input {index}"),
            Self::Utxo => f.write_str("UTXO"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpendCheckError {
    #[error("input {index} ({utxo_id:?}) has no UTXO record")]
    MissingRecord { index: usize, utxo_id: UtxoId },
    #[error("{at}: spend record refused: {source}")]
    Record {
        at: SpendAt,
        #[source]
        source: SpendRecordError,
    },
    #[error("{at}: the leaf key is not the key the MPC signs under for key path {key_path}")]
    Key { at: SpendAt, key_path: Address },
    #[error("txid mismatch: expected {expected:?}, rebuilt {rebuilt:?}")]
    Txid {
        expected: BitcoinTxid,
        rebuilt: BitcoinTxid,
    },
    #[error("sighash digest mismatch: certified {certified}, computed {computed}")]
    Digest {
        certified: Address,
        computed: Address,
    },
    #[error("signing request pairing refused: {0}")]
    Pairing(String),
    #[error("{0}")]
    Unavailable(anyhow::Error),
}

impl SpendCheckError {
    fn check_label(&self) -> Option<&'static str> {
        match self {
            Self::MissingRecord { .. } => Some("missing_record"),
            Self::Record { .. } => Some("record"),
            Self::Key { .. } => Some("key"),
            Self::Txid { .. } => Some("txid"),
            Self::Digest { .. } => Some("digest"),
            Self::Pairing(_) => Some("pairing"),
            Self::Unavailable(_) => None,
        }
    }
}

pub(crate) struct WithdrawalSpends {
    pub tx: bitcoin::Transaction,
    pub sighashes: Vec<[u8; 32]>,
    pub records: Vec<SpendData>,
    pub checked: Vec<CheckedSpend>,
    pub digest: Address,
}

impl WithdrawalSpends {
    pub(crate) fn check_leaf_keys(&self, mpc_key: &G) -> Result<(), SpendCheckError> {
        self.checked
            .iter()
            .zip(&self.records)
            .enumerate()
            .try_for_each(|(index, (checked, record))| {
                check_leaf_key(SpendAt::Input(index), checked, mpc_key, &record.key_path)
            })
    }
}

#[derive(Default)]
pub(crate) struct SpendVerdictCache {
    verdicts: Mutex<HashMap<SpendVerdictKey, Option<&'static str>>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SpendVerdictKey {
    spend: SpendData,
    guardian: [u8; 32],
    mpc_key: Vec<u8>,
}

impl Hashi {
    pub(crate) fn record_spend_refusal(&self, site: SpendCheckSite, error: &SpendCheckError) {
        if let Some(check) = error.check_label() {
            self.metrics
                .spend_check_refusals_total
                .with_label_values(&[site.label(), check])
                .inc();
        }
    }

    pub(crate) fn onchain_guardian_btc_pubkey(&self) -> Result<BitcoinPubkey, SpendCheckError> {
        let bytes = self
            .onchain_state()
            .guardian_btc_public_key()
            .ok_or_else(|| SpendCheckError::Unavailable(anyhow!("guardian key not on chain")))?;
        BitcoinPubkey::from_slice(&bytes).map_err(|e| {
            SpendCheckError::Unavailable(anyhow!("on-chain guardian key is invalid: {e}"))
        })
    }

    pub(crate) fn new_spend_data(&self, key_path: &Address) -> Result<SpendData, SpendCheckError> {
        let mpc_key = self.mpc_master_g().map_err(SpendCheckError::Unavailable)?;
        let guardian = self
            .guardian_btc_pubkey()
            .copied()
            .ok_or_else(|| SpendCheckError::Unavailable(anyhow!("guardian key not yet pinned")))?;
        let spend = hashi_bitcoin::taproot_2of2_spend_data(&guardian, &mpc_key, key_path);
        check_record_and_key(
            SpendAt::Utxo,
            &spend,
            &self.onchain_guardian_btc_pubkey()?,
            &mpc_key,
        )?;
        Ok(spend)
    }

    pub(crate) fn spend_verdict(
        &self,
        spend: &SpendData,
        mpc_key: &G,
        guardian: &BitcoinPubkey,
    ) -> Option<&'static str> {
        let key = SpendVerdictKey {
            spend: spend.clone(),
            guardian: guardian.serialize(),
            mpc_key: mpc_key.to_byte_array().to_vec(),
        };
        if let Some(verdict) = self.spend_verdicts.verdicts.lock().unwrap().get(&key) {
            return *verdict;
        }
        let verdict = match check_record_and_key(SpendAt::Utxo, spend, guardian, mpc_key) {
            Ok(_) => None,
            Err(SpendCheckError::Record { .. }) => Some("record"),
            Err(_) => Some("key"),
        };
        self.spend_verdicts
            .verdicts
            .lock()
            .unwrap()
            .insert(key, verdict);
        verdict
    }

    pub(crate) fn retain_spend_verdicts<'a>(&self, live: impl IntoIterator<Item = &'a SpendData>) {
        let live: std::collections::HashSet<&SpendData> = live.into_iter().collect();
        self.spend_verdicts
            .verdicts
            .lock()
            .unwrap()
            .retain(|key, _| live.contains(&key.spend));
    }

    pub(crate) fn withdrawal_spends(
        &self,
        inputs: &[Utxo],
        outputs: &[OutputUtxo],
        txid: &BitcoinTxid,
        certified_digest: Option<&Address>,
    ) -> Result<WithdrawalSpends, SpendCheckError> {
        let records = self
            .onchain_state()
            .utxo_spends(inputs.iter().map(|utxo| &utxo.id))
            .into_iter()
            .zip(inputs)
            .enumerate()
            .map(|(index, (record, utxo))| {
                record.ok_or(SpendCheckError::MissingRecord {
                    index,
                    utxo_id: utxo.id,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.withdrawal_spends_from(inputs, records, outputs, txid, certified_digest)
    }

    pub(crate) fn withdrawal_spends_from(
        &self,
        inputs: &[Utxo],
        records: Vec<SpendData>,
        outputs: &[OutputUtxo],
        txid: &BitcoinTxid,
        certified_digest: Option<&Address>,
    ) -> Result<WithdrawalSpends, SpendCheckError> {
        let guardian = self.onchain_guardian_btc_pubkey()?;
        compute_withdrawal_spends(inputs, records, outputs, txid, &guardian, certified_digest)
    }
}

pub(crate) fn compute_withdrawal_spends(
    inputs: &[Utxo],
    records: Vec<SpendData>,
    outputs: &[OutputUtxo],
    txid: &BitcoinTxid,
    guardian: &BitcoinPubkey,
    certified_digest: Option<&Address>,
) -> Result<WithdrawalSpends, SpendCheckError> {
    if records.len() != inputs.len() {
        return Err(SpendCheckError::Unavailable(anyhow!(
            "{} spend records for {} inputs",
            records.len(),
            inputs.len()
        )));
    }
    let tx = crate::withdrawals::unsigned_withdrawal_tx(inputs, outputs)
        .map_err(SpendCheckError::Unavailable)?;
    let rebuilt = BitcoinTxid::from(tx.compute_txid());
    if rebuilt != *txid {
        return Err(SpendCheckError::Txid {
            expected: *txid,
            rebuilt,
        });
    }
    let checked = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            hashi_bitcoin::check_spend_record(record, guardian).map_err(|source| {
                SpendCheckError::Record {
                    at: SpendAt::Input(index),
                    source,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let amounts: Vec<Amount> = inputs
        .iter()
        .map(|utxo| Amount::from_sat(utxo.amount))
        .collect();
    let sighashes = hashi_bitcoin::checked_spend_sighashes(&tx, &amounts, &checked);
    let digest = Address::new(hashi_bitcoin::sighash_digest(&sighashes));
    if let Some(certified) = certified_digest
        && *certified != digest
    {
        return Err(SpendCheckError::Digest {
            certified: *certified,
            computed: digest,
        });
    }
    Ok(WithdrawalSpends {
        tx,
        sighashes,
        records,
        checked,
        digest,
    })
}

pub(crate) fn spend_data_digest(spend: &SpendData) -> String {
    use fastcrypto::hash::HashFunction;
    let bytes = bcs::to_bytes(spend).expect("serialization should succeed");
    hex::encode(&fastcrypto::hash::Blake2b256::digest(&bytes).digest[..8])
}

fn check_record_and_key(
    at: SpendAt,
    spend: &SpendData,
    guardian: &BitcoinPubkey,
    mpc_key: &G,
) -> Result<CheckedSpend, SpendCheckError> {
    let checked = hashi_bitcoin::check_spend_record(spend, guardian)
        .map_err(|source| SpendCheckError::Record { at, source })?;
    check_leaf_key(at, &checked, mpc_key, &spend.key_path)?;
    Ok(checked)
}

fn check_leaf_key(
    at: SpendAt,
    checked: &CheckedSpend,
    mpc_key: &G,
    key_path: &Address,
) -> Result<(), SpendCheckError> {
    hashi_bitcoin::signs_under_leaf_key(mpc_key, Some(&key_path.into_inner()), &checked.leaf_key)
        .then_some(())
        .ok_or(SpendCheckError::Key {
            at,
            key_path: *key_path,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawals::check_signing_pairing;
    use crate::withdrawals::unsigned_withdrawal_tx;
    use crate::withdrawals::withdrawal_signing_requests;
    use bitcoin::opcodes::all::OP_CHECKSIG;
    use bitcoin::opcodes::all::OP_CHECKSIGADD;
    use bitcoin::opcodes::all::OP_CSV;
    use bitcoin::opcodes::all::OP_NUMEQUAL;
    use bitcoin::opcodes::all::OP_VERIFY;
    use bitcoin::script::Builder;
    use bitcoin::taproot::LeafVersion;
    use bitcoin::taproot::TaprootBuilder;
    use fastcrypto::groups::GroupElement;
    use fastcrypto_tbls::threshold_schnorr::S;
    use hashi_types::bitcoin::BTC_LIB;
    use hashi_types::bitcoin::InputUTXO;
    use hashi_types::bitcoin::OutputUTXOWire;
    use hashi_types::bitcoin::TxUTXOs;
    use hashi_types::bitcoin::create_btc_keypair_for_test;
    use hashi_types::move_types::MpcSig;
    use hashi_types::move_types::SigningBatch;
    use std::str::FromStr;

    const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

    const GOLDEN_MESSAGES: [&str; 4] = [
        "b112272ef5d9dbe0d616ef82c204648172a170f633a2fae4cee0f25a816b6aae",
        "9a994f386a878607cae37a939006ee9946cddaadc29cb3783997d712741e861d",
        "c4746f9cb5a576a54b7717f3f6a54c335b4d9ed2d4ff4e0b254b4197c85598fc",
        "a4a3c683c58561f481f541031fe9c5edf479d8c1372ae04192bb6336df01b6f6",
    ];
    const GOLDEN_LEAF_KEYS: [&str; 4] = [
        "6d4eb255927a80aaa3d7924af9d6753251d0ccffd51f01d88f84cb2735ba9a0b",
        "9bd93300d52f19b957339bc3a2c2f33b0a90186c8873e4e28f0e48d4b28e75ee",
        "e8d79575ef36b4c8241f727eebf0879a71e283cde38b03f52c007540188f7017",
        "295eab9b3c050c474d6d3069e44d3146ee68e9cb5685875d246a9241a6e8f27d",
    ];
    const GOLDEN_DIGEST: &str = "38b6f6c8cb29da961b9546804a43553a998c1077a7530337c2106c3d65f9fe04";

    fn guardian() -> BitcoinPubkey {
        create_btc_keypair_for_test(&[1u8; 32])
            .x_only_public_key()
            .0
    }

    fn mpc_key() -> G {
        G::generator() * S::from(7u128)
    }

    fn path(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    fn two_of_two_leaf(guardian: &BitcoinPubkey, leaf_key: &BitcoinPubkey) -> bitcoin::ScriptBuf {
        Builder::new()
            .push_x_only_key(guardian)
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(leaf_key)
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_NUMEQUAL)
            .into_script()
    }

    fn off_template_record(key_path: Address) -> SpendData {
        let leaf_key = BitcoinPubkey::from_slice(
            &hashi_bitcoin::signing_key_x(&mpc_key(), Some(&key_path.into_inner())).unwrap(),
        )
        .unwrap();
        let leaf = two_of_two_leaf(&guardian(), &leaf_key);
        let recovery = Builder::new()
            .push_int(12_345)
            .push_opcode(OP_CSV)
            .push_opcode(OP_VERIFY)
            .push_x_only_key(&leaf_key)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let info = TaprootBuilder::new()
            .add_leaf(1, leaf.clone())
            .unwrap()
            .add_leaf(1, recovery)
            .unwrap()
            .finalize(&BTC_LIB, BitcoinPubkey::from_str(NUMS).unwrap())
            .unwrap();
        let control_block = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        SpendData {
            script_pubkey: bitcoin::ScriptBuf::new_p2tr_tweaked(info.output_key()).into_bytes(),
            leaf_script: leaf.into_bytes(),
            control_block: control_block.serialize(),
            key_path,
            sighash_type: 0,
        }
    }

    fn utxo(txid_byte: u8, amount: u64, derivation_path: Option<Address>) -> Utxo {
        Utxo {
            id: UtxoId {
                txid: BitcoinTxid::new([txid_byte; 32]),
                vout: txid_byte.into(),
            },
            amount,
            derivation_path,
        }
    }

    fn production_shape() -> (Vec<Utxo>, Vec<SpendData>, Vec<OutputUtxo>) {
        let inputs = vec![
            utxo(0xa1, 100_000, Some(path(0x0a))),
            utxo(0xa2, 200_000, Some(path(0x0b))),
            utxo(0xa3, 50_000, None),
            utxo(0xa4, 75_000, Some(path(0x0d))),
        ];
        let records = vec![
            off_template_record(path(0x0a)),
            off_template_record(path(0x0c)),
            off_template_record(Address::ZERO),
            off_template_record(path(0x0d)),
        ];
        let outputs = vec![
            OutputUtxo {
                amount: 120_000,
                bitcoin_address: vec![0x11; 20],
            },
            OutputUtxo {
                amount: 150_000,
                bitcoin_address: vec![0x22; 32],
            },
            OutputUtxo {
                amount: 150_000,
                bitcoin_address: vec![0x33; 32],
            },
        ];
        (inputs, records, outputs)
    }

    fn signing_batch(signed: &[usize]) -> SigningBatch {
        SigningBatch {
            signatures: (0..4)
                .map(|i| {
                    if signed.contains(&i) {
                        MpcSig::Signed(vec![0; 64])
                    } else {
                        MpcSig::Pending(1_000 + i as u64)
                    }
                })
                .collect(),
            epoch: 9,
        }
    }

    fn hex32(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    #[test]
    fn signing_requests_come_from_stored_spend_data() {
        let (inputs, records, outputs) = production_shape();
        let txid = BitcoinTxid::from(
            unsigned_withdrawal_tx(&inputs, &outputs)
                .unwrap()
                .compute_txid(),
        );
        let spends =
            compute_withdrawal_spends(&inputs, records.clone(), &outputs, &txid, &guardian(), None)
                .unwrap();
        let messages: Vec<String> = spends.sighashes.iter().map(|m| hex32(m)).collect();
        let leaf_keys: Vec<String> = spends.checked.iter().map(|c| hex32(&c.leaf_key)).collect();
        assert_eq!(messages, GOLDEN_MESSAGES);
        assert_eq!(leaf_keys, GOLDEN_LEAF_KEYS);
        assert_eq!(hex32(spends.digest.as_bytes()), GOLDEN_DIGEST);
        let golden_messages: Vec<[u8; 32]> = GOLDEN_MESSAGES
            .iter()
            .map(|m| hex::decode(m).unwrap().try_into().unwrap())
            .collect();
        assert_eq!(
            hex32(&hashi_bitcoin::sighash_digest(&golden_messages)),
            GOLDEN_DIGEST
        );

        let certified = Address::new(hex::decode(GOLDEN_DIGEST).unwrap().try_into().unwrap());
        let stored = compute_withdrawal_spends(
            &inputs,
            records.clone(),
            &outputs,
            &txid,
            &guardian(),
            Some(&certified),
        )
        .unwrap();
        assert_eq!(stored.sighashes, spends.sighashes);

        let txn_id = Address::new([0x77; 32]);
        for (signed, expected_owners) in [(vec![], vec![0, 1, 2, 3]), (vec![0, 2], vec![1, 3])] {
            let batch = signing_batch(&signed);
            let (requests, index_by_id) =
                withdrawal_signing_requests(&txn_id, &batch, &stored, &[]).unwrap();
            check_signing_pairing(&txn_id, &batch, &stored, &requests, 9).unwrap();
            let owners: Vec<usize> = requests
                .iter()
                .map(|r| index_by_id[&r.signing_id])
                .collect();
            assert_eq!(owners, expected_owners);
            for (request, owner) in requests.iter().zip(owners) {
                assert_eq!(hex32(&request.message), GOLDEN_MESSAGES[owner]);
                assert_eq!(request.global_presig_index, 1_000 + owner as u64);
                assert_eq!(
                    request.leaf_key.map(|k| hex32(&k)).as_deref(),
                    Some(GOLDEN_LEAF_KEYS[owner])
                );
                assert_eq!(
                    request.derivation_address,
                    Some(records[owner].key_path.into_inner())
                );
            }
        }
    }

    #[test]
    fn template_records_match_the_enclave_sighashes() {
        let (inputs, _, mut outputs) = production_shape();
        let records: Vec<SpendData> = inputs
            .iter()
            .map(|utxo| {
                hashi_bitcoin::taproot_2of2_spend_data(
                    &guardian(),
                    &mpc_key(),
                    &utxo.derivation_path.unwrap_or(Address::ZERO),
                )
            })
            .collect();
        let change =
            hashi_bitcoin::taproot_2of2_spend_data(&guardian(), &mpc_key(), &Address::ZERO);
        outputs[2].bitcoin_address = change.script_pubkey[2..].to_vec();
        let txid = BitcoinTxid::from(
            unsigned_withdrawal_tx(&inputs, &outputs)
                .unwrap()
                .compute_txid(),
        );
        let spends =
            compute_withdrawal_spends(&inputs, records, &outputs, &txid, &guardian(), None)
                .unwrap();

        let network = bitcoin::Network::Regtest;
        let external = |output: &OutputUtxo| {
            let script =
                hashi_bitcoin::script_pubkey_from_witness_program(&output.bitcoin_address).unwrap();
            OutputUTXOWire::external(
                hashi_bitcoin::BitcoinAddress::from_script(&script, network)
                    .unwrap()
                    .into_unchecked(),
                bitcoin::Amount::from_sat(output.amount),
            )
        };
        let tx_utxos = TxUTXOs::new(
            inputs.iter().map(InputUTXO::from).collect(),
            vec![
                external(&outputs[0]),
                external(&outputs[1]),
                OutputUTXOWire::internal(
                    Address::ZERO,
                    bitcoin::Amount::from_sat(outputs[2].amount),
                ),
            ],
            network,
        )
        .unwrap();
        let (enclave_messages, enclave_txid) =
            tx_utxos.signing_messages_and_txid(&guardian(), &mpc_key());
        assert_eq!(BitcoinTxid::from(enclave_txid), txid);
        let enclave_messages: Vec<[u8; 32]> =
            enclave_messages.iter().map(|m| *m.as_ref()).collect();
        assert_eq!(enclave_messages, spends.sighashes);
    }

    fn tree_record(
        guardian: &BitcoinPubkey,
        leaf_key: &BitcoinPubkey,
        key_path: Address,
    ) -> SpendData {
        let leaf = two_of_two_leaf(guardian, leaf_key);
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&BTC_LIB, BitcoinPubkey::from_str(NUMS).unwrap())
            .unwrap();
        let control_block = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        SpendData {
            script_pubkey: bitcoin::ScriptBuf::new_p2tr_tweaked(info.output_key()).into_bytes(),
            leaf_script: leaf.into_bytes(),
            control_block: control_block.serialize(),
            key_path,
            sighash_type: 0,
        }
    }

    #[test]
    fn creation_checks_refuse_a_leaf_key_the_mpc_does_not_sign_under() {
        let odd_y_key = [7u128, 8, 9, 10, 11]
            .into_iter()
            .map(|k| G::generator() * S::from(k))
            .find(|key| !key.has_even_y().unwrap())
            .unwrap();
        let key_path = path(0x0e);
        let even_y_projection = -odd_y_key;
        let embedded = BitcoinPubkey::from_slice(
            &hashi_bitcoin::signing_key_x(&even_y_projection, Some(&key_path.into_inner()))
                .unwrap(),
        )
        .unwrap();
        let record = tree_record(&guardian(), &embedded, key_path);
        let checked = hashi_bitcoin::check_spend_record(&record, &guardian()).unwrap();
        assert!(matches!(
            check_leaf_key(SpendAt::Utxo, &checked, &odd_y_key, &key_path),
            Err(SpendCheckError::Key {
                at: SpendAt::Utxo,
                ..
            })
        ));
        assert!(check_leaf_key(SpendAt::Utxo, &checked, &even_y_projection, &key_path).is_ok());
    }

    #[test]
    fn record_check_refuses_a_leaf_for_another_guardian() {
        let other_guardian = create_btc_keypair_for_test(&[3u8; 32])
            .x_only_public_key()
            .0;
        let leaf_key = BitcoinPubkey::from_slice(
            &hashi_bitcoin::signing_key_x(&mpc_key(), Some(&[0u8; 32])).unwrap(),
        )
        .unwrap();
        let record = tree_record(&other_guardian, &leaf_key, Address::ZERO);
        assert!(hashi_bitcoin::check_spend_record(&record, &other_guardian).is_ok());
        assert_eq!(
            hashi_bitcoin::check_spend_record(&record, &guardian()),
            Err(SpendRecordError::NotGuardianTwoOfTwo)
        );
    }

    fn production_spends() -> (WithdrawalSpends, Address) {
        let (inputs, records, outputs) = production_shape();
        let txid = BitcoinTxid::from(
            unsigned_withdrawal_tx(&inputs, &outputs)
                .unwrap()
                .compute_txid(),
        );
        let spends =
            compute_withdrawal_spends(&inputs, records, &outputs, &txid, &guardian(), None)
                .unwrap();
        (spends, Address::new([0x77; 32]))
    }

    #[test]
    fn pairing_check_refuses_a_request_sent_to_another_inputs_slot() {
        let (spends, txn_id) = production_spends();
        let batch = signing_batch(&[]);
        let (mut requests, _) = withdrawal_signing_requests(&txn_id, &batch, &spends, &[]).unwrap();
        requests.swap(0, 1);
        let (first, second) = requests.split_at_mut(1);
        std::mem::swap(
            &mut first[0].global_presig_index,
            &mut second[0].global_presig_index,
        );
        assert!(matches!(
            check_signing_pairing(&txn_id, &batch, &spends, &requests, 9),
            Err(SpendCheckError::Pairing(_))
        ));
    }

    #[test]
    fn pairing_check_refuses_a_slot_no_pending_input_holds() {
        let (spends, txn_id) = production_spends();
        let batch = signing_batch(&[]);
        let (mut requests, _) = withdrawal_signing_requests(&txn_id, &batch, &spends, &[]).unwrap();
        requests[2].global_presig_index = 5_000;
        assert!(matches!(
            check_signing_pairing(&txn_id, &batch, &spends, &requests, 9),
            Err(SpendCheckError::Pairing(_))
        ));
        assert!(matches!(
            check_signing_pairing(&txn_id, &batch, &spends, &requests[..2], 8),
            Err(SpendCheckError::Pairing(_))
        ));
    }

    #[test]
    fn signing_refuses_a_withdrawal_whose_stored_digest_differs() {
        let (inputs, records, outputs) = production_shape();
        let txid = BitcoinTxid::from(
            unsigned_withdrawal_tx(&inputs, &outputs)
                .unwrap()
                .compute_txid(),
        );
        let certified = Address::new([0x99; 32]);
        assert!(matches!(
            compute_withdrawal_spends(&inputs, records, &outputs, &txid, &guardian(), Some(&certified)),
            Err(SpendCheckError::Digest { certified: c, .. }) if c == certified
        ));
    }
}
