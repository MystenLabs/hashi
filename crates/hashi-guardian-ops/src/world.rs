// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A stand-in for a two-slot guardian deployment, for the rotation steps' tests: the enclave and proxy stacks, ECS,
//! the hosts and their guardian sessions, the relay, `/info`, the Sui epoch and the log bucket's init records. It
//! answers the exact commands the steps run, and applies what they change.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use base64ct::Base64;
use base64ct::Encoding;
use serde_json::Value;
use serde_json::json;

use crate::exec::fake::Fake;
use crate::stack::Slot;

pub const COMMIT: &str = crate::stack::tests::COMMIT;
pub const BTC: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
const URN_PREFIX: &str = "urn:pulumi:testnet::hashi-guardian-enclave::aws:ec2/instance:Instance::hashi-guardian-enclave-";
const TASK: &str =
    "urn:pulumi:testnet::hashi-guardian-proxy::aws:ecs/taskDefinition:TaskDefinition::t";
const SERVICE: &str = "urn:pulumi:testnet::hashi-guardian-proxy::aws:ecs/service:Service::s";

pub struct Session {
    pub key: String,
    pub btc: Option<String>,
    pub config_hash: Option<String>,
    pub lifecycle: String,
    pub epoch: Option<u64>,
}

pub struct Host {
    pub ip: String,
    pub running: bool,
    pub session: Session,
}

pub struct State {
    /// The enclave stack's configuration, without its project prefix.
    pub config: BTreeMap<String, String>,
    pub deployed: BTreeMap<String, String>,
    pub outputs_active: Slot,
    pub hosts: BTreeMap<String, Host>,
    /// The proxy task's deployed guardian URLs.
    pub backend: String,
    pub standby: Option<String>,
    pub running_tag: String,
    pub configured_tag: String,
    pub service_counts: (u64, u64, u64),
    /// Init records by session, holding each session's configuration hash.
    pub init_records: BTreeMap<String, String>,
    pub sui_epoch: u64,
    /// When the epoch began and when the one before it began, as seconds before now.
    pub epoch_age: (i64, i64),
    pub activate_false_failure: bool,
    pub counter: u32,
    /// What each SSM command printed, by command ID.
    pub commands: BTreeMap<String, String>,
}

impl State {
    fn slot_enabled(&self, slot: Slot) -> bool {
        match self.config.get(&format!("slot-{slot}-enabled")) {
            Some(value) => value == "true",
            None => slot == Slot::A,
        }
    }

    fn configured_active(&self) -> Slot {
        if self.config.get("active-slot").map(String::as_str) == Some("b") {
            Slot::B
        } else {
            Slot::A
        }
    }

    fn outputs(&self) -> Value {
        let mut outputs = json!({
            "s3_bucket_name": "guardian-bucket",
            "s3_bucket_region": "us-west-2",
            "s3_access_key_id": "test-access-key",
            "s3_secret_access_key": "[secret]",
        });
        let active = self.outputs_active;
        if let Some(id) = self.deployed.get(&active.to_string()) {
            outputs["active_slot"] = active.to_string().into();
            outputs["enclave_instance_id"] = id.clone().into();
            outputs["guardian_private_ip"] = self.hosts[id].ip.clone().into();
            let standby = self.deployed.get(&active.other().to_string());
            outputs["standby_instance_id"] = standby.cloned().unwrap_or_default().into();
            outputs["standby_private_ip"] = standby
                .map(|id| self.hosts[id].ip.clone())
                .unwrap_or_default()
                .into();
        }
        outputs
    }

    fn proxy_desired(&self) -> (String, Option<String>) {
        let outputs = self.outputs();
        let ip = |key: &str| {
            outputs[key]
                .as_str()
                .filter(|ip| !ip.is_empty())
                .map(|ip| format!("http://{ip}:3000"))
        };
        (
            ip("guardian_private_ip").unwrap_or_default(),
            ip("standby_private_ip"),
        )
    }

    fn host_at(&self, url: &str) -> Option<&Host> {
        let ip = url.strip_prefix("http://")?.split(':').next()?;
        self.hosts
            .values()
            .find(|host| host.ip == ip && host.running)
    }

    fn new_session(&mut self) -> Session {
        self.counter += 1;
        Session {
            key: format!("{:064x}", 0xabc0 + self.counter),
            btc: None,
            config_hash: None,
            lifecycle: "none".to_owned(),
            epoch: None,
        }
    }

    fn enclave_plan(&self, target: &str) -> Vec<(String, String)> {
        let mut steps = Vec::new();
        for slot in Slot::ALL {
            let urn = format!("{URN_PREFIX}{slot}");
            if urn != target {
                continue;
            }
            let deployed = self.deployed.contains_key(&slot.to_string());
            let op = match (self.slot_enabled(slot), deployed) {
                (true, false) => "create",
                (false, true) => "delete",
                _ => "same",
            };
            steps.push((op.to_owned(), urn));
        }
        steps
    }

    fn apply_enclave(&mut self, target: &str) {
        for (op, urn) in self.enclave_plan(target) {
            let slot = urn.rsplit('-').next().unwrap().to_owned();
            match op.as_str() {
                "create" => {
                    self.counter += 1;
                    let id = format!("i-0{slot}{:03}", self.counter);
                    let session = self.new_session();
                    let ip = format!("192.0.2.{}", self.counter);
                    self.hosts.insert(
                        id.clone(),
                        Host {
                            ip,
                            running: true,
                            session,
                        },
                    );
                    self.deployed.insert(slot, id);
                }
                "delete" => {
                    self.deployed.remove(&slot);
                }
                _ => {}
            }
        }
        let active = self.configured_active();
        if self.slot_enabled(active) && self.deployed.contains_key(&active.to_string()) {
            self.outputs_active = active;
        }
    }

    fn info_data(&self, host: &Host) -> Value {
        let b64 = |hex_text: &str| Base64::encode_string(&hex::decode(hex_text).unwrap());
        let session = &host.session;
        let mut data = json!({ "signingPubKey": b64(&session.key) });
        if let Some(btc) = &session.btc {
            data["enclaveBtcPubkey"] = b64(btc).into();
        }
        // Activation drops the configuration hash from a guardian's own report.
        if let Some(hash) = session
            .config_hash
            .as_ref()
            .filter(|_| session.lifecycle != "withdraw/ACTIVATED")
        {
            data["configHash"] = b64(hash).into();
        }
        match session.lifecycle.split_once('/') {
            Some(("withdraw", stage)) => {
                data["withdraw"] = format!("WITHDRAW_STAGE_{stage}").into()
            }
            Some(("ceremony", stage)) => {
                data["ceremony"] = format!("CEREMONY_STAGE_{stage}").into()
            }
            _ => {}
        }
        data
    }

    fn proxy_plan(&self) -> Value {
        let (backend, standby) = self.proxy_desired();
        let definitions = |backend: &str, standby: &Option<String>, tag: &str| {
            crate::proxy::tests::definitions(backend, standby.as_deref(), &format!("repo:{tag}"))
        };
        let old = definitions(&self.backend, &self.standby, &self.running_tag);
        let new = definitions(&backend, &standby, &self.configured_tag);
        let mut steps = Vec::new();
        if old != new {
            steps.push(json!({ "op": "replace", "urn": TASK,
                "oldState": { "inputs": { "containerDefinitions": old } },
                "newState": { "inputs": { "containerDefinitions": new } } }));
            steps.push(json!({ "op": "update", "urn": SERVICE, "detailedDiff": { "taskDefinition": { "kind": "update" } } }));
        }
        steps.push(json!({ "op": "read", "urn": "urn:pulumi:testnet::hashi-guardian-proxy::pulumi:pulumi:StackReference::mysten/hashi-guardian-enclave/testnet" }));
        json!({ "steps": steps, "changeSummary": {} })
    }
}

/// A testnet-like stack: slot a serves `BTC` at committee epoch 1253, and slot b is enabled with the same build but
/// not yet deployed.
pub fn serving_world() -> Rc<RefCell<State>> {
    let config: BTreeMap<String, String> = [
        ("hashi-commit", COMMIT),
        ("hashi-commit-b", COMMIT),
        ("eif-pcr0", &"0c".repeat(48)),
        ("eif-pcr0-b", &"0c".repeat(48)),
        ("slot-b-enabled", "true"),
        ("refill-rate-sats-per-sec", "11574"),
        ("max-bucket-capacity-sats", "1000000000"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect();
    let serving = Session {
        key: "aa".repeat(32),
        btc: Some(BTC.to_owned()),
        config_hash: Some("cf".repeat(32)),
        lifecycle: "withdraw/ACTIVATED".to_owned(),
        epoch: Some(1253),
    };
    let mut init_records = BTreeMap::new();
    init_records.insert("aa".repeat(8), "cf".repeat(32));
    Rc::new(RefCell::new(State {
        config,
        deployed: [("a".to_owned(), "i-0aaa".to_owned())]
            .into_iter()
            .collect(),
        outputs_active: Slot::A,
        hosts: [(
            "i-0aaa".to_owned(),
            Host {
                ip: "192.0.2.10".to_owned(),
                running: true,
                session: serving,
            },
        )]
        .into_iter()
        .collect(),
        backend: "http://192.0.2.10:3000".to_owned(),
        standby: None,
        running_tag: "v1".to_owned(),
        configured_tag: "v1".to_owned(),
        service_counts: (1, 1, 1),
        init_records,
        sui_epoch: 1253,
        epoch_age: (3 * 3600, 27 * 3600),
        activate_false_failure: false,
        counter: 0,
        commands: BTreeMap::new(),
    }))
}

/// The commands the steps run, answered from and applied to `state`.
pub fn exec(state: &Rc<RefCell<State>>) -> Fake {
    let state = state.clone();
    Fake::new(move |words| {
        let w: Vec<&str> = words.iter().map(String::as_str).collect();
        let mut s = state.borrow_mut();
        let ok = |stdout: String| Some((true, stdout));
        let fail = || Some((false, String::new()));
        match w.as_slice() {
            ["pulumi", "version"] => ok("v3.148.0\n".to_owned()),
            ["pulumi", "-C", dir, rest @ ..] => {
                let proxy = dir.ends_with("hashi-guardian-proxy");
                match rest {
                    ["config", "--stack", _, "--json"] => ok(Value::Object(
                        s.config
                            .iter()
                            .map(|(key, value)| (format!("hashi-guardian-enclave:{key}"), json!({ "value": value })))
                            .collect(),
                    )
                    .to_string()),
                    ["config", "get", "hashi-guardian-proxy:proxy-image-tag", ..] => ok(format!("{}\n", s.configured_tag)),
                    ["config", "get", "hashi-guardian-proxy:aws-region", ..] => ok("us-west-2\n".to_owned()),
                    ["stack", "output", "--json", ..] => ok(s.outputs().to_string()),
                    ["stack", "output", "s3_access_key_id", ..] => ok("test-access-key\n".to_owned()),
                    ["stack", "output", "s3_secret_access_key", "--show-secrets", ..] => ok("test-secret-key\n".to_owned()),
                    ["stack", "tag", "ls", ..] => ok("{}".to_owned()),
                    ["stack", "export", ..] => {
                        let resources: Vec<Value> = if proxy {
                            vec![json!({ "type": "aws:ecs/service:Service", "urn": SERVICE,
                                "outputs": { "cluster": "proxy-cluster", "name": "proxy-service" } })]
                        } else {
                            s.deployed
                                .iter()
                                .map(|(slot, id)| json!({ "type": "aws:ec2/instance:Instance", "urn": format!("{URN_PREFIX}{slot}"), "id": id }))
                                .collect()
                        };
                        ok(json!({ "deployment": { "manifest": { "version": "v3.148.0" }, "resources": resources } }).to_string())
                    }
                    ["preview", "--stack", _, "--json"] if proxy => ok(s.proxy_plan().to_string()),
                    ["preview", "--stack", _, "--target", target, "--target-dependents", "--json"] => {
                        let steps: Vec<Value> = s
                            .enclave_plan(target)
                            .into_iter()
                            .map(|(op, urn)| json!({ "op": op, "urn": urn }))
                            .collect();
                        ok(json!({ "steps": steps, "changeSummary": {} }).to_string())
                    }
                    ["up", "--stack", _, "--yes"] if proxy => {
                        let (backend, standby) = s.proxy_desired();
                        s.backend = backend;
                        s.standby = standby;
                        s.running_tag = s.configured_tag.clone();
                        ok(String::new())
                    }
                    ["up", "--stack", _, "--target", target, "--target-dependents", "--yes"] => {
                        s.apply_enclave(target);
                        ok(String::new())
                    }
                    _ => None,
                }
            }
            ["grpcurl", .., address, "sui.hashi.v1alpha.GuardianService/GetGuardianInfo"] => {
                let slot = if address.ends_with(":3000") { "a" } else { "b" };
                let host = s.deployed.get(slot).and_then(|id| s.hosts.get(id)).filter(|host| host.running);
                match host {
                    Some(host) => ok(json!({ "info": s.info_data(host) }).to_string()),
                    None => fail(),
                }
            }
            ["grpcurl", .., "sui.hashi.v1alpha.GuardianRelayService/GetProvisioningTargetInfo"] => {
                let target = s.standby.clone().unwrap_or_else(|| s.backend.clone());
                match s.host_at(&target) {
                    Some(host) => ok(json!({ "signedInfo": { "data": s.info_data(host) } }).to_string()),
                    None => fail(),
                }
            }
            ["curl", .., url] if url.ends_with("/health") => ok(String::new()),
            ["curl", .., url] if url.ends_with("/info") => match s.host_at(&s.backend) {
                Some(host) => {
                    let session = &host.session;
                    ok(json!({
                        "signingPubKey": session.key,
                        "btcPubkey": session.btc,
                        "gitRevision": COMMIT,
                        "committeeEpoch": session.epoch.map(|epoch| epoch.to_string()),
                    })
                    .to_string())
                }
                None => fail(),
            },
            ["curl", .., "-d", body, _graphql] => {
                let now = crate::sui::now();
                let at = |age: i64| jiff::Timestamp::from_second(now - age).unwrap().to_string();
                if body.contains("epochId:") {
                    ok(json!({ "data": { "epoch": { "startTimestamp": at(s.epoch_age.1) } } }).to_string())
                } else {
                    ok(json!({ "data": { "epoch": { "epochId": s.sui_epoch, "startTimestamp": at(s.epoch_age.0) } } }).to_string())
                }
            }
            ["aws", "ecs", "describe-services", ..] => {
                let (desired, running, deployments) = s.service_counts;
                ok(format!("{desired}\t{running}\t{deployments}\ttaskdef-1\n"))
            }
            ["aws", "ecs", "describe-task-definition", ..] => ok(format!("repo:{}\n", s.running_tag)),
            ["aws", "s3", "cp", .., source, "-"] => {
                let session = source.split("/init/").nth(1)?.split('/').next()?.to_owned();
                match s.init_records.get(&session) {
                    Some(hash) => ok(json!({ "message": { "Init": { "OIGuardianInfo": { "mode": { "Withdraw": { "config_hash": hash } } } } } }).to_string()),
                    None => fail(),
                }
            }
            ["aws", "ssm", "send-command", .., "--parameters", parameters] => {
                let instance = w[w.iter().position(|word| *word == "--instance-ids")? + 1];
                let script = parameters.to_owned();
                let host = s.hosts.get_mut(instance)?;
                let out = if script.contains("GUARDIAN_RUNNING") {
                    if host.running { "GUARDIAN_RUNNING" } else { "GUARDIAN_STOPPED" }.to_owned()
                } else if script.contains("disable --now") {
                    host.running = false;
                    String::new()
                } else {
                    String::new()
                };
                s.counter += 1;
                let id = format!("cmd-{}", s.counter);
                s.commands.insert(id.clone(), out);
                ok(format!("{id}\n"))
            }
            ["aws", "ssm", "wait", ..] => ok(String::new()),
            ["aws", "ssm", "get-command-invocation", _, _, "--command-id", id, ..] => {
                ok(format!("{}\t\n", s.commands.get(*id).cloned().unwrap_or_default()))
            }
            ["gh", "run", "list", ..] => ok("0\n".to_owned()),
            ["cargo", "build", ..] => ok(r#"{"reason":"compiler-artifact","target":{"name":"hashi-guardian-init"},"executable":"/x/hashi-guardian-init"}"#.to_owned()),
            ["/x/hashi-guardian-init", "operator", "activate", ..] => {
                let others_quiet = s.hosts.values().all(|host| {
                    !host.running || !host.session.lifecycle.starts_with("withdraw/ACTIVATED")
                });
                let active = s.outputs_active.to_string();
                let epoch = s.sui_epoch;
                let false_failure = s.activate_false_failure;
                let id = s.deployed.get(&active)?.clone();
                if !others_quiet {
                    return fail();
                }
                let host = s.hosts.get_mut(&id)?;
                host.session.lifecycle = "withdraw/ACTIVATED".to_owned();
                host.session.epoch = Some(epoch);
                Some((!false_failure, String::new()))
            }
            _ => None,
        }
    })
}

/// Has the key provisioners provision `slot`'s guardian with the serving guardian's key and configuration.
pub fn provision(state: &Rc<RefCell<State>>, slot: Slot) {
    let mut s = state.borrow_mut();
    let id = s.deployed[&slot.to_string()].clone();
    let host = s.hosts.get_mut(&id).unwrap();
    host.session.btc = Some(BTC.to_owned());
    host.session.config_hash = Some("cf".repeat(32));
    host.session.lifecycle = "withdraw/PROVISIONER_INITIALIZED".to_owned();
    let session = host.session.key[..16].to_owned();
    s.init_records.insert(session, "cf".repeat(32));
}

/// The env file a rotation runs with, with its roster and the two stacks' Pulumi programs under `repo`.
pub fn env(repo: &std::path::Path) -> Vec<(String, String)> {
    let roster = crate::render::tests::roster_dir(&repo.join("roster"), &["alice", "bob"], "v1");
    let services = repo.join("pulumi/services");
    std::fs::create_dir_all(services.join("hashi-guardian-proxy")).unwrap();
    let enclave = services
        .join("hashi-guardian-enclave")
        .display()
        .to_string();
    [
        ("GUARDIAN_PULUMI_DIR", enclave.as_str()),
        ("GUARDIAN_STACK", "mysten/testnet"),
        (
            "GUARDIAN_PROXY_URL",
            "https://guardian.testnet.hashi.sui.io",
        ),
        ("KP_NAME", "testnet"),
        ("KP_ROSTER_DIR", roster.as_str()),
        ("KP_THRESHOLD", "2"),
        ("SUI_RPC", "https://fullnode.testnet.sui.io:443"),
        ("HASHI_PACKAGE_ID", "0x1"),
        ("HASHI_OBJECT_ID", "0x2"),
        ("BITCOIN_NETWORK", "signet"),
        ("RETENTION_ENVIRONMENT", "testnet"),
        ("SUI_GRAPHQL_URL", "https://graphql.testnet.sui.io/graphql"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect()
}
