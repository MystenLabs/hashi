// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Withdrawal state machine for tracking event flow.

use crate::audit::AuditWindow;
use crate::config::Config;
use crate::domain::BridgeKeys;
use crate::domain::Cursors;
use crate::domain::DepositEventType;
use crate::domain::DepositId;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorEventId;
use crate::domain::MonitorEventType;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::findings::EventRelation;
use crate::findings::MonitorFinding;
use crate::rpc::btc::BtcRpcClient;
use bitcoin::TxOut;
use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

/// A record of all the events tracking a single withdrawal.
///
/// `add_event` validates and stores an event. A structurally valid late event
/// is retained even though the method returns its timing finding.
///
/// `violations(cursors)` checks if there are any violations given current cursors
///
/// Invariant: `expected_events` should not contain an event type that exists in `seen_events`.
///
/// Four current scope/progress combinations are possible:
/// - Window: Out, In
/// - Progress: Expecting events, Complete
///
/// `is_expecting_events()` distinguishes the two progress states. Findings are
/// emitted to the caller and are not retained in the WSM, so `Complete` does not
/// mean that no earlier finding was reported.
pub struct WithdrawalStateMachine {
    /// the set of non-zero events we have seen until now related to this withdrawal.
    seen_events: Vec<MonitorWithdrawalEvent>,
    /// Each `(event, deadline, relation)` entry means `event` is expected by
    /// `deadline`; `relation` records whether it precedes or follows an event
    /// already observed for this withdrawal.
    expected_events: Vec<(WithdrawalEventType, UnixSeconds, EventRelation)>,
    /// last time at which we checked for a btc withdrawal tx
    btc_checked_at: Option<UnixSeconds>,
    /// immutable wid
    wid: WithdrawalID,
    /// immutable txid
    btc_txid: Txid,
}

pub enum BtcFetchOutcome {
    NotExpected,
    Unconfirmed,
    Confirmed(Vec<MonitorFinding>),
}

impl WithdrawalStateMachine {
    /// Note: Initialization ensures that the state machine has at least one event.
    pub fn new(event: MonitorWithdrawalEvent, cfg: &Config) -> Self {
        let mut sm = Self {
            seen_events: Vec::new(),
            expected_events: Vec::new(),
            btc_checked_at: None,
            wid: event.wid,
            btc_txid: event.btc_txid,
        };
        assert!(
            sm.add_event(event, cfg).is_empty(),
            "first event cannot produce a finding"
        );
        sm
    }

    pub fn get(&self, event_type: WithdrawalEventType) -> Option<&MonitorWithdrawalEvent> {
        self.seen_events
            .iter()
            .find(|event| event.event_type == event_type)
    }

    pub fn btc_txid(&self) -> Txid {
        self.btc_txid
    }

    pub fn wid(&self) -> WithdrawalID {
        self.wid
    }

    pub fn expects(&self, event_type: WithdrawalEventType) -> bool {
        self.expected_events
            .iter()
            .any(|(event, _, _)| *event == event_type)
    }

    /// Is the Hashi approval still missing after the Sui cursor passed its deadline?
    pub fn is_missing_hashi_approval(&self, cursors: &Cursors) -> bool {
        self.expected_events
            .iter()
            .any(|(event_type, deadline, _)| {
                *event_type == WithdrawalEventType::E1HashiApproved && *deadline <= cursors.sui
            })
    }

    /// Are any expected neighboring events still outstanding?
    ///
    /// This does not mean that no timing finding was emitted during ingestion.
    /// Callers must ensure `is_in_audit_window()` is true before using this for
    /// garbage collection. Out-of-window withdrawals with pending expectations
    /// may remain in memory, but they arise only from the bounded lookback or
    /// lookahead ranges.
    pub fn is_expecting_events(&self) -> bool {
        !self.expected_events.is_empty()
    }

    pub fn expected_event_types(&self) -> Vec<WithdrawalEventType> {
        self.expected_events
            .iter()
            .map(|(event_type, _, _)| *event_type)
            .collect()
    }

    // TODO: If we fully move to strict guardian-led audits, this can be relaxed to only include
    // withdrawals with guardian E2 in the user window.
    pub fn is_in_audit_window(&self, window: &impl AuditWindow) -> bool {
        self.seen_events
            .iter()
            .any(|e| window.in_window(e.timestamp_secs))
    }

    /// Add an event and update expectations for its immediate neighbors.
    ///
    /// A missing predecessor is expected by the event timestamp plus the
    /// predecessor's clock skew; a missing successor is expected by the
    /// configured next-event deadline. A neighbor already seen is checked
    /// against the pair's deadlines, so findings do not depend on ingestion order.
    ///
    /// Event retention is based on structural validity, not finding category.
    /// `MonitorFinding::InvalidEventAdded` denotes a contradictory, definite
    /// safety issue, so it is returned immediately without storing the event.
    /// A structurally valid event is stored and updates subsequent expectations
    /// even when its timing produces a safety or liveness finding.
    ///
    /// The return value contains every resulting finding. An empty vector means
    /// the event was accepted without one.
    pub fn add_event(
        &mut self,
        new_event: MonitorWithdrawalEvent,
        cfg: &Config,
    ) -> Vec<MonitorFinding> {
        if let Some(existing_event) = self.get(new_event.event_type) {
            return if *existing_event == new_event {
                Vec::new()
            } else {
                vec![MonitorFinding::InvalidEventAdded(
                    "duplicate event for same wid with different contents".to_string(),
                )]
            };
        }

        if self.wid != new_event.wid {
            return vec![MonitorFinding::InvalidEventAdded("invalid wid".to_string())];
        }

        if self.btc_txid != new_event.btc_txid {
            return vec![MonitorFinding::InvalidEventAdded(
                "invalid btc_txid".to_string(),
            )];
        }

        let mut timing_findings = Vec::new();
        if let Some(predecessor_event_type) = new_event.event_type.predecessor() {
            match self.get(predecessor_event_type) {
                Some(predecessor) => {
                    timing_findings.extend(neighbor_timing_findings(predecessor, &new_event, cfg))
                }
                None => self.expected_events.push((
                    predecessor_event_type,
                    cfg.predecessor_deadline(&new_event),
                    EventRelation::Predecessor,
                )),
            }
        }
        if let Some(successor_event_type) = new_event.event_type.successor() {
            match self.get(successor_event_type) {
                Some(successor) => {
                    timing_findings.extend(neighbor_timing_findings(&new_event, successor, cfg))
                }
                None => self.expected_events.push((
                    successor_event_type,
                    cfg.successor_deadline(&new_event),
                    EventRelation::Successor,
                )),
            }
        }

        // remove any previously stored expected events
        self.expected_events
            .retain(|(src, _, _)| *src != new_event.event_type);
        // add to seen events
        self.seen_events.push(new_event);
        timing_findings
    }

    /// If expecting BTC confirmation, query BTC RPC and add the event if confirmed.
    ///     - Returns `Ok(BtcFetchOutcome::NotExpected)` if a BTC event is not expected.
    ///     - Returns `Ok(BtcFetchOutcome::Unconfirmed)` if checked but block not yet mined.
    ///     - Returns `Ok(BtcFetchOutcome::Confirmed(findings))` if confirmed; `findings` may be empty.
    ///     - Returns `Err` for BTC RPC/infrastructure failures.
    pub fn try_fetch_btc_tx(
        &mut self,
        cfg: &Config,
        btc_rpc_client: &BtcRpcClient,
    ) -> anyhow::Result<BtcFetchOutcome> {
        if !self.expects(WithdrawalEventType::E3BtcConfirmed) {
            return Ok(BtcFetchOutcome::NotExpected);
        }
        let btc_txid = self.btc_txid;
        let wid = self.wid;
        let cur_time = now_timestamp_secs();

        match btc_rpc_client.lookup_confirmation(btc_txid) {
            Ok(Some(confirmation)) => {
                self.btc_checked_at = Some(cur_time);
                let e_btc = MonitorWithdrawalEvent {
                    event_type: WithdrawalEventType::E3BtcConfirmed,
                    wid,
                    btc_txid,
                    timestamp_secs: confirmation.block_time,
                };
                Ok(BtcFetchOutcome::Confirmed(self.add_event(e_btc, cfg)))
            }
            Ok(None) => {
                self.btc_checked_at = Some(cur_time);
                Ok(BtcFetchOutcome::Unconfirmed)
            }
            Err(e) => Err(e),
        }
    }

    /// Check for violations given per-source cursors.
    /// Only reports a missing event if its deadline has passed relative to the relevant cursor.
    /// Callers must ensure is_in_audit_window() is true before calling this function.
    pub fn violations(&self, cursors: &Cursors) -> Vec<MonitorFinding> {
        let mut out = Vec::new();
        for (event_type, deadline, relation) in &self.expected_events {
            let cursor = match event_type {
                WithdrawalEventType::E3BtcConfirmed => match self.btc_checked_at {
                    Some(checked_at) => checked_at,
                    None => {
                        // Bitcoin and state checks have independent schedules.
                        // Wait for the first lookup before evaluating absence.
                        continue;
                    }
                },
                _ => cursors.for_event_type(*event_type),
            };
            if *deadline <= cursor {
                out.push(MonitorFinding::ExpectedEventMissing {
                    event_id: MonitorEventId::Withdrawal(self.wid),
                    event_type: MonitorEventType::Withdrawal(*event_type),
                    relation: *relation,
                    deadline: *deadline,
                    cursor,
                });
            }
        }
        out
    }
}

/// Both timing bounds between consecutive events.
fn neighbor_timing_findings(
    predecessor: &MonitorWithdrawalEvent,
    successor: &MonitorWithdrawalEvent,
    cfg: &Config,
) -> Vec<MonitorFinding> {
    let mut findings = Vec::new();
    let deadline = cfg.successor_deadline(predecessor);
    if deadline < successor.timestamp_secs {
        findings.push(MonitorFinding::EventOccurredAfterDeadline {
            event: MonitorEvent::Withdrawal(successor.clone()),
            relation: EventRelation::Successor,
            deadline,
            occurred_at: successor.timestamp_secs,
        });
    }
    let deadline = cfg.predecessor_deadline(successor);
    if deadline < predecessor.timestamp_secs {
        findings.push(MonitorFinding::EventOccurredAfterDeadline {
            event: MonitorEvent::Withdrawal(predecessor.clone()),
            relation: EventRelation::Predecessor,
            deadline,
            occurred_at: predecessor.timestamp_secs,
        });
    }
    findings
}

/// Deposit State Machine. Unlike withdrawal state machine, here we only listen for a sui event,
/// which in turn triggers a lookup for a specific btc event. So we simplify the struct & its impl's.
pub struct DepositStateMachine {
    /// The hashi deposit event
    hashi_deposit_event: MonitorDepositEvent,
    /// None initially and Some post BTC event find
    btc_event: Option<MonitorDepositEvent>,
    btc_event_expected_at: UnixSeconds,
    btc_checked_at: Option<UnixSeconds>,
}

impl DepositStateMachine {
    pub fn new(event: MonitorDepositEvent, cfg: &Config) -> Self {
        if event.event_type != DepositEventType::E2HashiDeposited {
            panic!("unexpected event type");
        }
        // btc confirmation is a predecessor event => we set the deadline to now (+skew).
        let t_btc_expected = event.timestamp_secs + cfg.deposit_clock_skew;
        Self {
            hashi_deposit_event: event,
            btc_event: None,
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
        self.btc_event.is_none()
    }

    /// Look up the deposit on Bitcoin. A confirmed deposit also gets the
    /// `validate_deposit` checks. Its findings are reported once: the
    /// Bitcoin event is kept, so the flow completes and is not looked up again.
    pub fn try_fetch_btc_tx(
        &mut self,
        btc_rpc_client: &BtcRpcClient,
        bridge_keys: &BridgeKeys,
    ) -> anyhow::Result<BtcFetchOutcome> {
        if !self.is_expecting_events() {
            return Ok(BtcFetchOutcome::NotExpected);
        }

        let deadline = self.btc_event_expected_at;
        let deposit_id = self.hashi_deposit_event.deposit_id;
        let btc_txid = deposit_id.txid();
        let cur_time = now_timestamp_secs();

        match btc_rpc_client.lookup_confirmation(btc_txid) {
            Ok(Some(confirmation)) => {
                self.btc_checked_at = Some(cur_time);
                let block_time = confirmation.block_time;
                let e_btc = MonitorDepositEvent {
                    event_type: DepositEventType::E1BtcConfirmed,
                    timestamp_secs: block_time,
                    ..self.hashi_deposit_event.clone()
                };

                let mut findings = Vec::new();
                if deadline < block_time {
                    findings.push(MonitorFinding::EventOccurredAfterDeadline {
                        event: MonitorEvent::Deposit(e_btc.clone()),
                        relation: EventRelation::Predecessor,
                        deadline,
                        occurred_at: block_time,
                    });
                }
                findings.extend(validate_deposit(
                    &self.hashi_deposit_event,
                    &confirmation.outputs,
                    bridge_keys,
                ));
                self.btc_event = Some(e_btc);
                Ok(BtcFetchOutcome::Confirmed(findings))
            }
            Ok(None) => {
                self.btc_checked_at = Some(cur_time);
                Ok(BtcFetchOutcome::Unconfirmed)
            }
            Err(e) => Err(e),
        }
    }

    pub fn violations(&self) -> Vec<MonitorFinding> {
        if self.btc_event.is_some() {
            // btc event found => no violations!
            return Vec::new();
        };

        // btc event not yet found
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

/// Check what Move does not on a confirmed deposit: the claimed output exists,
/// holds the claimed amount, and pays the bridge address of the claimed
/// derivation path. Move only sees the committee's signature over the claim.
pub fn validate_deposit(
    claim: &MonitorDepositEvent,
    outputs: &[TxOut],
    bridge_keys: &BridgeKeys,
) -> Vec<MonitorFinding> {
    let deposit_id = claim.deposit_id;
    let Some(output) = outputs.get(deposit_id.vout() as usize) else {
        return vec![MonitorFinding::DepositOutputMissing {
            deposit_id,
            output_count: outputs.len(),
        }];
    };
    let mut findings = Vec::new();
    if output.value.to_sat() != claim.amount {
        findings.push(MonitorFinding::DepositAmountMismatch {
            deposit_id,
            claimed: claim.amount,
            onchain: output.value.to_sat(),
        });
    }
    if output.script_pubkey != bridge_keys.script_pubkey(claim.derivation_path.as_ref()) {
        findings.push(MonitorFinding::DepositOutputNotToBridge {
            deposit_id,
            derivation_path: claim.derivation_path,
            script_pubkey: output.script_pubkey.clone(),
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::BtcConfig;
    use crate::config::ClockSkews;
    use crate::config::NextEventDelays;
    use crate::config::SuiConfig;
    use crate::findings::FindingCategory;
    use crate::rpc::sui::approval::tests::test_bridge_keys;
    use bitcoin::Amount;
    use bitcoin::ScriptBuf;
    use bitcoin::WPubkeyHash;
    use bitcoin::hashes::Hash as _;
    use hashi_types::bitcoin::DerivationPath;
    use hashi_types::guardian::DeploymentConfig;
    use hashi_types::guardian::S3Credentials;

    struct TestWindow {
        start: UnixSeconds,
        end: UnixSeconds,
    }

    impl AuditWindow for TestWindow {
        fn in_window(&self, timestamp_secs: UnixSeconds) -> bool {
            timestamp_secs >= self.start && timestamp_secs <= self.end
        }
    }

    fn cfg() -> Config {
        Config {
            next_event_delays: NextEventDelays::new(vec![
                (WithdrawalEventType::E1HashiApproved, 100),
                (WithdrawalEventType::E2GuardianApproved, 200),
            ])
            .expect("valid intra-event delays"),
            clock_skews: ClockSkews::new(vec![
                (WithdrawalEventType::E1HashiApproved, 10),
                (WithdrawalEventType::E2GuardianApproved, 30),
            ])
            .expect("valid clock skews"),
            deposit_clock_skew: 10,
            withdrawal_predecessor_lookback: 60 * 60,
            deployment: DeploymentConfig {
                bucket_info: hashi_types::guardian::S3BucketInfo {
                    name: "bucket".to_string(),
                    region: "us-east-1".to_string(),
                },
                retention_environment: hashi_types::guardian::S3RetentionEnvironment::Testnet,
                bitcoin_network: bitcoin::Network::Regtest,
                pcr_allowlist: hashi_types::guardian::PcrAllowlist::new(
                    hashi_types::guardian::BuildPcrs::mock_for_testing("", 1),
                    vec![],
                )
                .expect("valid PCR allowlist"),
            },
            s3_credentials: Some(S3Credentials {
                access_key: "access-key".to_string(),
                secret_key: "secret-key".to_string(),
                session_token: None,
            }),
            sui: SuiConfig {
                rpc_url: "http://sui".to_string(),
                package_id: format!("0x{}", "11".repeat(32)),
            },
            btc: BtcConfig {
                rpc_url: "http://btc".to_string(),
                http_headers: BTreeMap::new(),
            },
        }
    }

    fn txid(fill: u8) -> Txid {
        Txid::from_slice(&[fill; 32]).expect("valid txid")
    }

    fn event(
        source: WithdrawalEventType,
        wid_seed: u8,
        timestamp: UnixSeconds,
        fill: u8,
    ) -> MonitorWithdrawalEvent {
        MonitorWithdrawalEvent {
            event_type: source,
            wid: WithdrawalID::new([wid_seed; 32]),
            timestamp_secs: timestamp,
            btc_txid: txid(fill),
        }
    }

    fn deposit_event(timestamp: UnixSeconds, fill: u8) -> MonitorDepositEvent {
        MonitorDepositEvent {
            event_type: DepositEventType::E2HashiDeposited,
            timestamp_secs: timestamp,
            deposit_id: DepositId::new(txid(fill), 0),
            amount: 50_000,
            derivation_path: None,
        }
    }

    #[test]
    fn add_event_rejects_duplicate_source() {
        let cfg = cfg();

        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 1, 100, 1),
            &cfg,
        );

        let findings = sm.add_event(event(WithdrawalEventType::E1HashiApproved, 1, 110, 1), &cfg);
        assert_eq!(
            findings,
            vec![MonitorFinding::InvalidEventAdded(
                "duplicate event for same wid with different contents".to_string()
            )]
        );

        let wid_findings = sm.add_event(
            event(WithdrawalEventType::E2GuardianApproved, 2, 120, 1),
            &cfg,
        );
        assert_eq!(
            wid_findings,
            vec![MonitorFinding::InvalidEventAdded("invalid wid".to_string())]
        );

        let txid_findings = sm.add_event(
            event(WithdrawalEventType::E2GuardianApproved, 1, 120, 2),
            &cfg,
        );
        assert_eq!(
            txid_findings,
            vec![MonitorFinding::InvalidEventAdded(
                "invalid btc_txid".to_string()
            )]
        );
    }

    #[test]
    fn in_order_flow_completes() {
        let cfg = cfg();

        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 9, 100, 7),
            &cfg,
        );
        assert!(sm.expects(WithdrawalEventType::E2GuardianApproved));

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E2GuardianApproved, 9, 150, 7),
                &cfg,
            )
            .is_empty()
        );
        assert!(sm.expects(WithdrawalEventType::E3BtcConfirmed));

        assert!(
            sm.add_event(event(WithdrawalEventType::E3BtcConfirmed, 9, 300, 7), &cfg)
                .is_empty()
        );

        assert!(!sm.is_expecting_events());
    }

    #[test]
    fn add_event_records_event_past_deadline() {
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 4, 100, 4),
            &cfg,
        );
        let event = event(WithdrawalEventType::E2GuardianApproved, 4, 201, 4);

        let findings = sm.add_event(event.clone(), &cfg);
        assert_eq!(
            findings,
            vec![MonitorFinding::EventOccurredAfterDeadline {
                event: MonitorEvent::Withdrawal(event),
                relation: EventRelation::Successor,
                deadline: 200,
                occurred_at: 201,
            }]
        );
        assert!(sm.get(WithdrawalEventType::E2GuardianApproved).is_some());
        assert!(!sm.expects(WithdrawalEventType::E2GuardianApproved));
        assert!(sm.expects(WithdrawalEventType::E3BtcConfirmed));
    }

    #[test]
    fn add_event_records_all_timing_findings() {
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 4, 100, 4),
            &cfg,
        );
        let btc_confirmed = event(WithdrawalEventType::E3BtcConfirmed, 4, 600, 4);
        assert!(sm.add_event(btc_confirmed.clone(), &cfg).is_empty());

        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 4, 311, 4);
        let findings = sm.add_event(guardian_approval.clone(), &cfg);

        assert_eq!(
            findings,
            vec![
                MonitorFinding::EventOccurredAfterDeadline {
                    event: MonitorEvent::Withdrawal(guardian_approval),
                    relation: EventRelation::Successor,
                    deadline: 200,
                    occurred_at: 311,
                },
                MonitorFinding::EventOccurredAfterDeadline {
                    event: MonitorEvent::Withdrawal(btc_confirmed),
                    relation: EventRelation::Successor,
                    deadline: 511,
                    occurred_at: 600,
                },
            ]
        );
        assert!(!sm.is_expecting_events());
    }

    #[test]
    fn timing_findings_do_not_depend_on_ingestion_order() {
        let cfg = cfg();
        let late = |event: &MonitorWithdrawalEvent, relation, deadline| {
            MonitorFinding::EventOccurredAfterDeadline {
                event: MonitorEvent::Withdrawal(event.clone()),
                relation,
                deadline,
                occurred_at: event.timestamp_secs,
            }
        };

        // The last two cases have a block time before the guardian signature,
        // within and past E2's clock skew.
        for (approved_at, signed_at, confirmed_at) in [
            (100, 150, 300),
            (100, 200, 400),
            (100, 201, 300),
            (100, 400_000, 400_100),
            (110, 100, 300),
            (111, 100, 301),
            (100, 150, 120),
            (100, 150, 119),
        ] {
            let events = [
                event(WithdrawalEventType::E1HashiApproved, 5, approved_at, 5),
                event(WithdrawalEventType::E2GuardianApproved, 5, signed_at, 5),
                event(WithdrawalEventType::E3BtcConfirmed, 5, confirmed_at, 5),
            ];
            let [approval, signature, confirmation] = &events;
            let mut expected = Vec::new();
            if signed_at > approved_at + 100 {
                expected.push(late(signature, EventRelation::Successor, approved_at + 100));
            }
            if approved_at > signed_at + 10 {
                expected.push(late(approval, EventRelation::Predecessor, signed_at + 10));
            }
            if confirmed_at > signed_at + 200 {
                expected.push(late(
                    confirmation,
                    EventRelation::Successor,
                    signed_at + 200,
                ));
            }
            if signed_at > confirmed_at + 30 {
                expected.push(late(
                    signature,
                    EventRelation::Predecessor,
                    confirmed_at + 30,
                ));
            }

            for order in [
                [0, 1, 2],
                [0, 2, 1],
                [1, 0, 2],
                [1, 2, 0],
                [2, 0, 1],
                [2, 1, 0],
            ] {
                let mut sm = WithdrawalStateMachine::new(events[order[0]].clone(), &cfg);
                let findings: Vec<_> = order[1..]
                    .iter()
                    .flat_map(|&i| sm.add_event(events[i].clone(), &cfg))
                    .collect();
                assert_eq!(findings.len(), expected.len(), "{order:?}: {findings:?}");
                assert!(
                    expected.iter().all(|finding| findings.contains(finding)),
                    "{order:?}: {findings:?}"
                );
                assert!(!sm.is_expecting_events(), "{order:?}");
            }
        }
    }

    #[test]
    fn violations_only_after_cursor_passes_deadline() {
        let cfg = cfg();
        let sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 1, 100, 5),
            &cfg,
        );

        let no_violation = sm.violations(&Cursors {
            sui: 0,
            guardian: 199,
        });
        assert!(no_violation.is_empty());

        let violations = sm.violations(&Cursors {
            sui: 0,
            guardian: 200,
        });
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0],
            MonitorFinding::ExpectedEventMissing {
                event_id: MonitorEventId::Withdrawal(WithdrawalID::new([1; 32])),
                event_type: MonitorEventType::Withdrawal(WithdrawalEventType::E2GuardianApproved),
                relation: EventRelation::Successor,
                deadline: 200,
                cursor: 200,
            }
        );
    }

    #[test]
    fn hashi_approval_is_missing_once_the_sui_cursor_passes_its_deadline() {
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E2GuardianApproved, 7, 100, 7),
            &cfg,
        );
        let cursors = |sui| Cursors {
            sui,
            guardian: 1_000,
        };

        assert!(!sm.is_missing_hashi_approval(&cursors(109)));
        assert!(sm.is_missing_hashi_approval(&cursors(110)));

        assert!(
            sm.add_event(event(WithdrawalEventType::E1HashiApproved, 7, 10, 7), &cfg)
                .is_empty()
        );
        assert!(!sm.is_missing_hashi_approval(&cursors(1_000)));
        assert!(sm.violations(&cursors(1_000)).is_empty());
    }

    #[test]
    fn a_late_or_mismatched_hashi_approval_is_a_safety_finding() {
        let cfg = cfg();
        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 8, 100, 8);

        let mut late = WithdrawalStateMachine::new(guardian_approval.clone(), &cfg);
        let approval = event(WithdrawalEventType::E1HashiApproved, 8, 111, 8);
        let findings = late.add_event(approval.clone(), &cfg);
        assert_eq!(
            findings,
            vec![MonitorFinding::EventOccurredAfterDeadline {
                event: MonitorEvent::Withdrawal(approval),
                relation: EventRelation::Predecessor,
                deadline: 110,
                occurred_at: 111,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);

        let mut mismatched = WithdrawalStateMachine::new(guardian_approval, &cfg);
        let findings =
            mismatched.add_event(event(WithdrawalEventType::E1HashiApproved, 8, 50, 9), &cfg);
        assert_eq!(
            findings,
            vec![MonitorFinding::InvalidEventAdded(
                "invalid btc_txid".to_string()
            )]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
        assert!(mismatched.is_missing_hashi_approval(&Cursors {
            sui: 110,
            guardian: 1_000,
        }));
    }

    #[test]
    fn a_guardian_approval_past_its_skew_after_the_block_time_is_a_safety_finding() {
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 6, 100, 6),
            &cfg,
        );
        let guardian_approval = event(WithdrawalEventType::E2GuardianApproved, 6, 150, 6);
        assert!(sm.add_event(guardian_approval.clone(), &cfg).is_empty());

        let findings = sm.add_event(event(WithdrawalEventType::E3BtcConfirmed, 6, 119, 6), &cfg);

        assert_eq!(
            findings,
            vec![MonitorFinding::EventOccurredAfterDeadline {
                event: MonitorEvent::Withdrawal(guardian_approval),
                relation: EventRelation::Predecessor,
                deadline: 149,
                occurred_at: 150,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
    }

    #[test]
    fn backfill_e1_outside_window_e2_inside_is_still_valid() {
        let cfg = cfg();
        let mut sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 31, 90, 1),
            &cfg,
        );
        let window = TestWindow {
            start: 100,
            end: 200,
        };

        assert!(
            sm.add_event(
                event(WithdrawalEventType::E2GuardianApproved, 31, 100, 1),
                &cfg,
            )
            .is_empty()
        );
        assert!(sm.is_in_audit_window(&window));

        let findings = sm.violations(&Cursors {
            sui: 1_000,
            guardian: 1_000,
        });

        assert!(findings.is_empty());
    }

    #[test]
    fn e1_inside_window_without_e2_is_in_scope() {
        let cfg = cfg();
        let sm = WithdrawalStateMachine::new(
            event(WithdrawalEventType::E1HashiApproved, 88, 120, 2),
            &cfg,
        );
        let window = TestWindow {
            start: 100,
            end: 200,
        };

        assert!(sm.is_in_audit_window(&window));
    }

    /// A claim of `amount` sats at vout 1 for `derivation_path`, and the
    /// outputs of a transaction that pays `paid` sats to `script` at vout 1.
    fn deposit_claim_and_outputs(
        amount: u64,
        derivation_path: Option<DerivationPath>,
        paid: u64,
        script: ScriptBuf,
    ) -> (MonitorDepositEvent, Vec<TxOut>) {
        let claim = MonitorDepositEvent {
            event_type: DepositEventType::E2HashiDeposited,
            timestamp_secs: 100,
            deposit_id: DepositId::new(txid(9), 1),
            amount,
            derivation_path,
        };
        let outputs = vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x53; 20])),
            },
            TxOut {
                value: Amount::from_sat(paid),
                script_pubkey: script,
            },
        ];
        (claim, outputs)
    }

    #[test]
    fn a_deposit_to_the_bridge_with_the_claimed_amount_is_valid() {
        let keys = test_bridge_keys();
        let path = DerivationPath::new([0x42; 32]);
        let (claim, outputs) =
            deposit_claim_and_outputs(50_000, Some(path), 50_000, keys.script_pubkey(Some(&path)));

        assert!(validate_deposit(&claim, &outputs, &keys).is_empty());

        let (claim, outputs) =
            deposit_claim_and_outputs(50_000, None, 50_000, keys.change_script());
        assert!(validate_deposit(&claim, &outputs, &keys).is_empty());
    }

    #[test]
    fn a_missing_output_is_a_finding() {
        let keys = test_bridge_keys();
        let (claim, outputs) =
            deposit_claim_and_outputs(50_000, None, 50_000, keys.change_script());

        assert_eq!(
            validate_deposit(&claim, &outputs[..1], &keys),
            vec![MonitorFinding::DepositOutputMissing {
                deposit_id: claim.deposit_id,
                output_count: 1,
            }]
        );
    }

    #[test]
    fn a_claimed_amount_above_the_paid_amount_is_a_finding() {
        let keys = test_bridge_keys();
        let (claim, outputs) =
            deposit_claim_and_outputs(50_000, None, 40_000, keys.change_script());

        assert_eq!(
            validate_deposit(&claim, &outputs, &keys),
            vec![MonitorFinding::DepositAmountMismatch {
                deposit_id: claim.deposit_id,
                claimed: 50_000,
                onchain: 40_000,
            }]
        );
    }

    #[test]
    fn an_output_to_another_address_is_a_finding() {
        let keys = test_bridge_keys();
        let other = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x54; 20]));
        let (claim, outputs) = deposit_claim_and_outputs(50_000, None, 50_000, other.clone());

        assert_eq!(
            validate_deposit(&claim, &outputs, &keys),
            vec![MonitorFinding::DepositOutputNotToBridge {
                deposit_id: claim.deposit_id,
                derivation_path: None,
                script_pubkey: other,
            }]
        );
    }

    #[test]
    fn a_claimed_recipient_other_than_the_paid_one_is_a_finding() {
        let keys = test_bridge_keys();
        let paid_path = DerivationPath::new([0x42; 32]);
        let claimed_path = DerivationPath::new([0x43; 32]);
        let (claim, outputs) = deposit_claim_and_outputs(
            50_000,
            Some(claimed_path),
            50_000,
            keys.script_pubkey(Some(&paid_path)),
        );

        let findings = validate_deposit(&claim, &outputs, &keys);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(matches!(
            findings[0],
            MonitorFinding::DepositOutputNotToBridge { .. }
        ));
        assert_eq!(findings[0].category(), FindingCategory::Safety);
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
