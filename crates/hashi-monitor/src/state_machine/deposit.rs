// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Deposit state machine: Hashi's claim checked against Bitcoin.

use crate::config::Config;
use crate::domain::DepositEventType;
use crate::domain::DepositId;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorEventId;
use crate::domain::MonitorEventType;
use crate::domain::TxConfirmation;
use crate::findings::EventRelation;
use crate::findings::MonitorFinding;
use crate::rpc::btc::BtcRpcClient;
use crate::state_machine::BtcFetchOutcome;
use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

/// Deposit State Machine. Unlike withdrawal state machine, here we only listen for a sui event,
/// which in turn triggers a lookup for a specific btc event. So we simplify the struct & its impl's.
pub struct DepositStateMachine {
    /// The hashi deposit event
    hashi_deposit_event: MonitorDepositEvent,
    /// True once Bitcoin confirmed the transaction, with or without the
    /// deposit output. The flow is then complete.
    btc_resolved: bool,
    btc_event_expected_at: UnixSeconds,
    btc_checked_at: Option<UnixSeconds>,
}

impl DepositStateMachine {
    pub fn new(event: MonitorDepositEvent, cfg: &Config) -> Self {
        if event.event_type != DepositEventType::E2HashiDeposited {
            panic!("unexpected event type");
        }
        // btc confirmation is a predecessor event => we set the deadline to now (+skew).
        let t_btc_expected = event.timestamp_secs + cfg.timing.deposit_confirmation_skew;
        Self {
            hashi_deposit_event: event,
            btc_resolved: false,
            btc_event_expected_at: t_btc_expected,
            btc_checked_at: None,
        }
    }

    pub fn btc_txid(&self) -> Txid {
        self.hashi_deposit_event.deposit_id.txid()
    }

    pub fn deposit_id(&self) -> DepositId {
        self.hashi_deposit_event.deposit_id
    }

    pub fn hashi_deposit_event(&self) -> &MonitorDepositEvent {
        &self.hashi_deposit_event
    }

    pub fn is_expecting_events(&self) -> bool {
        !self.btc_resolved
    }

    /// Look up the deposit on Bitcoin. A confirmed transaction without the
    /// deposit output is a `DepositOutputMissing`, and a confirmed deposit that
    /// differs from the Sui claim is a `DepositMismatch`. Both are reported
    /// once: the flow then completes and is not looked up again.
    pub fn try_fetch_btc_tx(
        &mut self,
        btc_rpc_client: &BtcRpcClient,
    ) -> anyhow::Result<BtcFetchOutcome> {
        if !self.is_expecting_events() {
            return Ok(BtcFetchOutcome::NotExpected);
        }

        let confirmation = btc_rpc_client.lookup_confirmation(self.btc_txid())?;
        self.btc_checked_at = Some(now_timestamp_secs());
        Ok(match confirmation {
            Some(confirmation) => BtcFetchOutcome::Confirmed(self.resolve(&confirmation)),
            None => BtcFetchOutcome::Unconfirmed,
        })
    }

    /// Complete the flow with the confirmed transaction and return its findings.
    fn resolve(&mut self, confirmation: &TxConfirmation) -> Vec<MonitorFinding> {
        self.btc_resolved = true;
        let deposit_id = self.deposit_id();
        let Some(e_btc) = MonitorDepositEvent::from_btc(confirmation, deposit_id) else {
            return vec![MonitorFinding::DepositOutputMissing {
                deposit_id,
                output_count: confirmation.outputs.len(),
            }];
        };

        let deadline = self.btc_event_expected_at;
        let mut findings = Vec::new();
        if deadline < e_btc.timestamp_secs {
            findings.push(MonitorFinding::EventOccurredAfterDeadline {
                event: MonitorEvent::Deposit(e_btc.clone()),
                relation: EventRelation::Predecessor,
                deadline,
                occurred_at: e_btc.timestamp_secs,
            });
        }
        findings.extend(deposit_mismatch(&self.hashi_deposit_event, &e_btc));
        findings
    }

    pub fn violations(&self) -> Vec<MonitorFinding> {
        if self.btc_resolved {
            // Bitcoin resolved the deposit, so nothing is missing.
            return Vec::new();
        };

        // Bitcoin has not resolved the deposit yet.
        let Some(cursor) = self.btc_checked_at else {
            // Bitcoin and state checks have independent schedules. Wait for
            // the first lookup before evaluating absence.
            return Vec::new();
        };

        let deadline = self.btc_event_expected_at;
        if deadline > cursor {
            return Vec::new();
        }

        vec![MonitorFinding::ExpectedEventMissing {
            event_id: MonitorEventId::Deposit(self.hashi_deposit_event.deposit_id),
            event_type: MonitorEventType::Deposit(DepositEventType::E1BtcConfirmed),
            relation: EventRelation::Predecessor,
            deadline,
            cursor,
        }]
    }
}

/// The finding if the deposit Bitcoin confirms differs from the one Sui
/// claims. Move only sees the committee's signature over the claim, so this
/// is the check that the bridge received every satoshi it mints.
pub fn deposit_mismatch(
    sui: &MonitorDepositEvent,
    btc: &MonitorDepositEvent,
) -> Option<MonitorFinding> {
    (sui.amount != btc.amount || sui.script_pubkey != btc.script_pubkey).then(|| {
        MonitorFinding::DepositMismatch {
            sui: sui.clone(),
            btc: btc.clone(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::FindingCategory;
    use crate::rpc::sui::approval::tests::test_hashi_btc_keys;
    use bitcoin::Amount;
    use bitcoin::ScriptBuf;
    use bitcoin::TxOut;
    use bitcoin::WPubkeyHash;
    use bitcoin::hashes::Hash as _;
    use hashi_types::bitcoin::DerivationPath;

    fn cfg() -> Config {
        Config::for_tests()
    }

    fn txid(fill: u8) -> Txid {
        Txid::from_slice(&[fill; 32]).expect("valid txid")
    }

    fn deposit_event(timestamp: UnixSeconds, fill: u8) -> MonitorDepositEvent {
        MonitorDepositEvent {
            event_type: DepositEventType::E2HashiDeposited,
            timestamp_secs: timestamp,
            deposit_id: DepositId::new(txid(fill), 0),
            amount: 50_000,
            script_pubkey: test_hashi_btc_keys().script_pubkey(None),
        }
    }

    fn p2wpkh(fill: u8) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([fill; 20]))
    }

    fn sui_deposit(amount: u64, script_pubkey: ScriptBuf) -> MonitorDepositEvent {
        MonitorDepositEvent {
            event_type: DepositEventType::E2HashiDeposited,
            timestamp_secs: 100,
            deposit_id: DepositId::new(txid(9), 1),
            amount,
            script_pubkey,
        }
    }

    /// A confirmed transaction that pays `paid` sats to `script_pubkey` at vout 1.
    fn confirmation(paid: u64, script_pubkey: ScriptBuf) -> TxConfirmation {
        TxConfirmation {
            block_time: 30,
            confirmed_time: 90,
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

    #[test]
    fn a_deposit_paid_as_claimed_has_no_mismatch() {
        let keys = test_hashi_btc_keys();
        let path = DerivationPath::new([0x42; 32]);
        let sui = sui_deposit(50_000, keys.script_pubkey(Some(&path)));
        let btc = MonitorDepositEvent::from_btc(
            &confirmation(50_000, keys.script_pubkey(Some(&path))),
            sui.deposit_id,
        )
        .unwrap();

        assert_eq!(deposit_mismatch(&sui, &btc), None);
    }

    #[test]
    fn a_claimed_amount_above_the_paid_amount_is_a_mismatch() {
        let sui = sui_deposit(50_000, p2wpkh(0x54));
        let btc =
            MonitorDepositEvent::from_btc(&confirmation(40_000, p2wpkh(0x54)), sui.deposit_id)
                .unwrap();

        let finding = deposit_mismatch(&sui, &btc).unwrap();
        assert_eq!(
            finding,
            MonitorFinding::DepositMismatch {
                sui: sui.clone(),
                btc,
            }
        );
        assert_eq!(finding.category(), FindingCategory::Safety);
    }

    #[test]
    fn a_payment_to_another_address_is_a_mismatch() {
        let sui = sui_deposit(50_000, p2wpkh(0x54));
        let btc =
            MonitorDepositEvent::from_btc(&confirmation(50_000, p2wpkh(0x55)), sui.deposit_id)
                .unwrap();

        assert!(deposit_mismatch(&sui, &btc).is_some());
    }

    #[test]
    fn a_confirmed_transaction_without_the_deposit_output_is_output_missing() {
        let deposit_id = DepositId::new(txid(9), 2);
        let sui = MonitorDepositEvent {
            deposit_id,
            ..sui_deposit(50_000, p2wpkh(0x54))
        };
        let mut sm = DepositStateMachine::new(sui, &cfg());

        let findings = sm.resolve(&confirmation(50_000, p2wpkh(0x54)));

        assert_eq!(
            findings,
            vec![MonitorFinding::DepositOutputMissing {
                deposit_id,
                output_count: 2,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
        assert!(!sm.is_expecting_events());
    }

    #[test]
    fn a_claimed_recipient_other_than_the_paid_one_is_a_mismatch() {
        let keys = test_hashi_btc_keys();
        let paid_path = DerivationPath::new([0x42; 32]);
        let claimed_path = DerivationPath::new([0x43; 32]);
        let sui = sui_deposit(50_000, keys.script_pubkey(Some(&claimed_path)));
        let btc = MonitorDepositEvent::from_btc(
            &confirmation(50_000, keys.script_pubkey(Some(&paid_path))),
            sui.deposit_id,
        )
        .unwrap();

        assert!(deposit_mismatch(&sui, &btc).is_some());
    }

    #[test]
    fn deposit_violations_wait_for_btc_check() {
        let cfg = cfg();
        let mut sm = DepositStateMachine::new(deposit_event(100, 8), &cfg);

        assert!(sm.violations().is_empty());

        sm.btc_checked_at = Some(109);
        assert!(sm.violations().is_empty());

        sm.btc_checked_at = Some(110);
        let violations = sm.violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0],
            MonitorFinding::ExpectedEventMissing {
                event_id: MonitorEventId::Deposit(DepositId::new(txid(8), 0)),
                event_type: MonitorEventType::Deposit(DepositEventType::E1BtcConfirmed),
                relation: EventRelation::Predecessor,
                deadline: 110,
                cursor: 110,
            }
        );
    }
}
