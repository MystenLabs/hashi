// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fixtures shared by the test modules: the test bridge keys, Bitcoin ids
//! and scripts, a confirmed transaction, a withdrawal transaction, and a
//! deposit request.

use bitcoin::Amount;
use bitcoin::ScriptBuf;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::WPubkeyHash;
use bitcoin::hashes::Hash as _;
use hashi_types::bitcoin::BTC_LIB;
use hashi_types::bitcoin::BitcoinKeypair;
use hashi_types::bitcoin::DerivationPath;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::move_types::OutputUtxo;
use hashi_types::move_types::Utxo;
use hashi_types::move_types::UtxoId;

use sui_sdk_types::Address;

use crate::domain::BtcConfirmation;
use crate::domain::DepositId;
use crate::domain::SuiDepositRequestedEvent;
use crate::domain::WithdrawalTx;
use crate::keys::HashiBTCKeys;

/// Bridge keys from fixed test guardian and MPC keys, on Signet.
pub fn test_hashi_btc_keys() -> HashiBTCKeys {
    let guardian = BitcoinKeypair::from_seckey_slice(&BTC_LIB, &[6u8; 32])
        .unwrap()
        .x_only_public_key()
        .0;
    let mpc = HashiMasterG::with_even_y_from_x_be_bytes(
        &BitcoinKeypair::from_seckey_slice(&BTC_LIB, &[7u8; 32])
            .unwrap()
            .x_only_public_key()
            .0
            .serialize(),
    )
    .unwrap();
    HashiBTCKeys::new(guardian, mpc, bitcoin::Network::Signet)
}

/// A txid of 32 `fill` bytes.
pub fn txid(fill: u8) -> Txid {
    Txid::from_slice(&[fill; 32]).expect("valid txid")
}

/// A P2WPKH script whose key hash is 20 `fill` bytes.
pub fn p2wpkh(fill: u8) -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([fill; 20]))
}

/// A request at time 100 for `txid(9):1`, claiming 50,000 sats to
/// `p2wpkh(0x54)`. `confirmation(50_000, p2wpkh(0x54))` pays it.
pub fn deposit_request() -> SuiDepositRequestedEvent {
    SuiDepositRequestedEvent {
        request_id: Address::new([0x61; 32]),
        timestamp_secs: 100,
        deposit_id: DepositId::new(txid(9), 1),
        amount: 50_000,
        script_pubkey: p2wpkh(0x54),
    }
}

/// A confirmed transaction that pays `paid` sats to `script_pubkey` at vout 1.
pub fn confirmation(paid: u64, script_pubkey: ScriptBuf) -> BtcConfirmation {
    BtcConfirmation {
        block_time: 30,
        confirmed_time: 90,
        inputs: vec![],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: p2wpkh(0x53),
            },
            TxOut {
                value: Amount::from_sat(paid),
                script_pubkey,
            },
        ],
    }
}

/// One input, one user payout, and change to `change_address`.
pub fn withdrawal_tx(change_address: Vec<u8>) -> WithdrawalTx {
    WithdrawalTx::new(
        vec![Utxo {
            id: UtxoId {
                txid: txid(0x51).into(),
                vout: 1,
            },
            amount: 120_000,
            derivation_path: Some(DerivationPath::new([0x52; 32])),
        }],
        vec![OutputUtxo {
            amount: 100_000,
            bitcoin_address: vec![0x53; 20],
        }],
        vec![OutputUtxo {
            amount: 19_000,
            bitcoin_address: change_address,
        }],
    )
}
