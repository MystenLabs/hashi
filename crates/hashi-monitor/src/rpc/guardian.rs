// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;
use crate::domain::HashiBTCKeys;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use crate::domain::WithdrawalTx;
use crate::domain::utc_timestamp;
use crate::findings::MonitorFinding;
use anyhow::Context;
use bitcoin::Network;
use hashi_guardian::MAX_EXPECTED_LOG_CLOCK_SKEW;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_guardian::s3_reader::VerifiedLogEntry;
use hashi_types::bitcoin::OutputUTXOWire;
use hashi_types::bitcoin::TxUTXOsWire;
use hashi_types::bitcoin::witness_program_from_address;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::OutputUtxo;
use hashi_types::move_types::Utxo;
use hashi_types::move_types::UtxoId;
use tracing::debug;

// Note: current design does not check if multiple concurrent sessions are running.
//       one way to impl this: store the first & last observed session timestamp & ensure no overlap between time ranges.
pub struct GuardianWithdrawalsPoller {
    /// Owns the S3 client + the trusted-key cache, so a session's attestation is
    /// verified once for the poller's lifetime.
    reader: GuardianReader,
    cursor: S3HourDirectory,
    /// Set by `read_hashi_btc_keys`. The guardian's internal outputs state a
    /// derivation path, and the keys turn it into the address they pay.
    hashi_btc_keys: Option<HashiBTCKeys>,
}

impl GuardianWithdrawalsPoller {
    // Note: Throws an error if there is a S3 connectivity issue
    pub async fn new(config: &Config, start: UnixSeconds) -> anyhow::Result<Self> {
        let s3_credentials =
            hashi_guardian::resolve_s3_credentials(config.s3_credentials.as_ref()).await?;
        Ok(Self {
            reader: GuardianReader::new(config.deployment.clone(), s3_credentials).await?,
            cursor: S3HourDirectory::withdraw(start)?,
            hashi_btc_keys: None,
        })
    }

    /// The E2 event of a verified guardian withdrawal log.
    fn withdrawal_event(&self, log: VerifiedLogEntry) -> anyhow::Result<MonitorWithdrawalEvent> {
        let keys = self
            .hashi_btc_keys
            .as_ref()
            .context("the bridge keys must be read before polling guardian logs")?;
        let entry = log.into_entry();
        let timestamp_ms = entry.timestamp_ms();
        let withdrawal = entry
            .into_message()
            .into_withdrawal()
            .ok_or_else(|| anyhow::anyhow!("non-withdrawal logs found"))?;

        debug!(
            wid = %withdrawal.request_data.wid,
            txid = %withdrawal.txid,
            "guardian withdrawal log"
        );
        Ok(MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E2GuardianApproved,
            wid: withdrawal.request_data.wid,
            timestamp_secs: unix_millis_to_seconds(timestamp_ms),
            btc_txid: withdrawal.txid,
            tx: withdrawal_tx(keys, &withdrawal.request_data.utxos)?,
        })
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor.to_unix_seconds()
    }

    /// The two keys every bridge address derives from. They never change. The
    /// MPC master key comes from the KP-authorized genesis record and the
    /// guardian's Bitcoin key from the latest ceremony record, both verified
    /// against the allowlist.
    pub async fn read_hashi_btc_keys(&mut self, network: Network) -> anyhow::Result<HashiBTCKeys> {
        let genesis = self
            .reader
            .read_genesis()
            .await
            .context("failed to read the guardian genesis record")?
            .context("the guardian genesis record does not exist")?;
        let ceremony = self
            .reader
            .read_latest_ceremony_state()
            .await
            .context("failed to read the guardian ceremony record")?;
        let keys = HashiBTCKeys::new(ceremony.btc_master_pubkey, genesis.mpc_master_g, network);
        tracing::info!(
            change_script = %keys.script_pubkey(None),
            "read the bridge keys from the guardian records"
        );
        self.hashi_btc_keys = Some(keys.clone());
        Ok(keys)
    }

    /// Time after which the next unread hourly partition is considered complete.
    pub fn next_partition_ready_at(&self) -> UnixSeconds {
        self.cursor.write_completion_time()
    }

    /// Poll one hourly Guardian S3 directory and advance to the next directory.
    pub async fn poll_one_hour(&mut self) -> anyhow::Result<PollOutcome> {
        if now_timestamp_secs() < self.cursor.write_completion_time() {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let start = self.cursor.to_unix_seconds();
        let next_cursor = self.cursor.next_dir()?;
        let end = next_cursor.to_unix_seconds();
        let verified_logs = self.reader.read_logs_in_dir(&self.cursor).await?;
        // Withdrawal polling may replay historical buckets during an upgrade, so
        // this caller accepts any record whose session build verifies against the
        // configured allowlist. Add a cursor/cutoff policy here if tailing must
        // require the current build after the upgrade window.
        let mut findings = Vec::new();
        let mut withdrawal_events = Vec::with_capacity(verified_logs.len());
        for log in verified_logs {
            // Each record is one sample of the guardian's clock against AWS
            // time, plus the write latency.
            if log.exceeds_clock_skew(MAX_EXPECTED_LOG_CLOCK_SKEW) {
                findings.push(MonitorFinding::GuardianClockSkew {
                    session_id: log.session_id().clone(),
                    object_key: log.entry().object_key().to_owned(),
                    logged_at_ms: log.entry().timestamp_ms(),
                    stored_at_ms: log.stored_at_ms(),
                });
            }
            withdrawal_events.push(MonitorEvent::Withdrawal(self.withdrawal_event(log)?));
        }

        self.cursor = next_cursor;
        tracing::info!(
            start = %utc_timestamp(start),
            end = %utc_timestamp(end),
            cursor = %utc_timestamp(self.cursor.to_unix_seconds()),
            events = withdrawal_events.len(),
            "completed Guardian event range"
        );
        Ok(PollOutcome::CursorAdvanced {
            events: withdrawal_events,
            findings,
        })
    }
}

/// The UTXOs the guardian signed, in Move's shape. The guardian labels each
/// output external, to a user address, or internal, to the bridge address of
/// a derivation path. The external outputs are Move's user payouts and the
/// internal ones its change, each with the address as a witness program.
fn withdrawal_tx(keys: &HashiBTCKeys, utxos: &TxUTXOsWire) -> anyhow::Result<WithdrawalTx> {
    let inputs = utxos
        .inputs
        .iter()
        .map(|input| Utxo {
            id: UtxoId {
                txid: input.outpoint.txid.into(),
                vout: input.outpoint.vout,
            },
            amount: input.amount.to_sat(),
            derivation_path: Some(input.derivation_path),
        })
        .collect();
    let mut withdrawal_outputs = Vec::new();
    let mut change_outputs = Vec::new();
    for output in &utxos.outputs {
        match output {
            OutputUTXOWire::External(external) => {
                let address = external
                    .address
                    .clone()
                    .require_network(keys.network())
                    .context("guardian external output address is for another network")?;
                withdrawal_outputs.push(OutputUtxo {
                    amount: external.amount.to_sat(),
                    bitcoin_address: witness_program_from_address(&address)?,
                });
            }
            OutputUTXOWire::Internal(internal) => change_outputs.push(OutputUtxo {
                amount: internal.amount.to_sat(),
                bitcoin_address: witness_program_from_address(
                    &keys.address(Some(&internal.derivation_path)),
                )?,
            }),
        }
    }
    Ok(WithdrawalTx::new(
        inputs,
        withdrawal_outputs,
        change_outputs,
    ))
}

#[cfg(test)]
impl GuardianWithdrawalsPoller {
    /// A poller over a mock S3 client, for tests that never poll it.
    pub(crate) fn for_tests(config: &Config, start: UnixSeconds) -> Self {
        Self {
            reader: hashi_guardian::test_utils::mock_reader(config.deployment.clone()),
            cursor: S3HourDirectory::withdraw(start).expect("valid test timestamp"),
            hashi_btc_keys: Some(crate::rpc::sui::approval::tests::test_hashi_btc_keys()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::sui::approval::tests::test_hashi_btc_keys;
    use bitcoin::Amount;
    use bitcoin::OutPoint;
    use bitcoin::ScriptBuf;
    use bitcoin::WPubkeyHash;
    use bitcoin::hashes::Hash as _;
    use hashi_types::bitcoin::BitcoinAddress;
    use hashi_types::bitcoin::DerivationPath;
    use hashi_types::bitcoin::InputUTXO;

    #[test]
    fn the_guardians_utxos_convert_to_moves_shape() {
        let keys = test_hashi_btc_keys();
        let input_path = DerivationPath::new([0x52; 32]);
        let change_path = DerivationPath::new([0x42; 32]);
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_slice(&[0x51; 32]).unwrap(),
            vout: 1,
        };
        let user_script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x53; 20]));
        let user_address = BitcoinAddress::from_script(&user_script, keys.network()).unwrap();
        let utxos = TxUTXOsWire {
            inputs: vec![InputUTXO::new(
                outpoint,
                Amount::from_sat(120_000),
                input_path,
            )],
            outputs: vec![
                OutputUTXOWire::external(user_address.into_unchecked(), Amount::from_sat(100_000)),
                OutputUTXOWire::internal(change_path, Amount::from_sat(19_000)),
            ],
        };

        assert_eq!(
            withdrawal_tx(&keys, &utxos).unwrap(),
            WithdrawalTx {
                inputs: vec![Utxo {
                    id: UtxoId {
                        txid: outpoint.txid.into(),
                        vout: 1,
                    },
                    amount: 120_000,
                    derivation_path: Some(input_path),
                }],
                withdrawal_outputs: vec![OutputUtxo {
                    amount: 100_000,
                    bitcoin_address: vec![0x53; 20],
                }],
                change_outputs: vec![OutputUtxo {
                    amount: 19_000,
                    bitcoin_address: witness_program_from_address(
                        &keys.address(Some(&change_path))
                    )
                    .unwrap(),
                }],
            }
        );
    }

    #[test]
    fn an_external_address_for_another_network_is_an_error() {
        let keys = test_hashi_btc_keys();
        let mainnet = BitcoinAddress::from_script(
            &ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x53; 20])),
            Network::Bitcoin,
        )
        .unwrap();
        let utxos = TxUTXOsWire {
            inputs: vec![InputUTXO::new(
                OutPoint::null(),
                Amount::from_sat(1),
                DerivationPath::ZERO,
            )],
            outputs: vec![OutputUTXOWire::external(
                mainnet.into_unchecked(),
                Amount::from_sat(1),
            )],
        };

        assert!(withdrawal_tx(&keys, &utxos).is_err());
    }
}
