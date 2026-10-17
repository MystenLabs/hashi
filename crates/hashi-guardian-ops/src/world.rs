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

use crate::Ctx;
use crate::ask::scripted::Scripted;
use crate::exec::fake::Fake;
use crate::render::SlotRender;
use crate::stack::Slot;
use crate::stack::Stack;

pub const COMMIT: &str = crate::stack::tests::COMMIT;
/// A later build, for a rotation onto another commit.
pub const NEXT: &str = "c47991e310000000000000000000000000000000";
pub const BTC: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
pub const URN_PREFIX: &str = "urn:pulumi:testnet::enclave::aws:ec2/instance:Instance::guardian-";
const STACK_URN: &str = "urn:pulumi:testnet::enclave::pulumi:pulumi:Stack::enclave-testnet";
const SERVICE: &str = "urn:pulumi:testnet::proxy::aws:ecs/service:Service::s";
const TASK: &str = "urn:pulumi:testnet::proxy::aws:ecs/taskDefinition:TaskDefinition::t";
const ACCOUNT: &str = "111111111111";

pub struct Session {
    pub key: String,
    pub btc: Option<String>,
    pub config_hash: Option<String>,
    pub lifecycle: String,
    pub epoch: Option<u64>,
}

pub struct Host {
    pub ip: String,
    /// The commit its guardian is built from.
    pub commit: String,
    /// Whether the guardian's unit is enabled or active.
    pub running: bool,
    /// Whether an enclave runs, which a failed terminate leaves after the unit stops.
    pub enclave: bool,
    pub session: Session,
}

pub struct State {
    /// The enclave stack's configuration, without its project prefix.
    pub config: BTreeMap<String, String>,
    pub deployed: BTreeMap<String, String>,
    pub outputs_active: Slot,
    pub hosts: BTreeMap<String, Host>,
    /// The proxy task's guardian URLs and image tag in the proxy stack's state, as its live task definition `revision`.
    pub backend: String,
    pub standby: Option<String>,
    pub running_tag: String,
    pub revision: u32,
    pub configured_tag: String,
    pub service_counts: (u64, u64, u64),
    /// Whether ECS rolls the next proxy deployment back, and the revision and URLs it then runs instead of the state's.
    pub rolls_back: bool,
    pub rolled_back: Option<(u32, String, Option<String>)>,
    /// Resources besides the slots' instances that an untargeted enclave plan creates.
    pub other_creates: Vec<String>,
    /// An instance the enclave stack's outputs name as the standby in place of the standby slot's.
    pub standby_output: Option<String>,
    /// EC2's state of a host, where it isn't `running`.
    pub ec2_states: BTreeMap<String, String>,
    /// Workflow runs that haven't completed: their repository, status and workflow path.
    pub workflow_runs: Vec<(String, String, String)>,
    /// Each session's operator-init record, by session.
    pub init_records: BTreeMap<String, Value>,
    /// The builds hashi-monitor's audit configuration allowlists, its current build first, if it has one.
    pub monitor_builds: Option<Vec<(String, String)>>,
    /// The commits this checkout has.
    pub local_commits: Vec<String>,
    /// What `git diff` lists between any two commits under the guardian's protos and log types.
    pub format_changes: Vec<String>,
    pub sui_epoch: u64,
    /// When the epoch began and when the one before it began, as seconds before now.
    pub epoch_age: (i64, i64),
    pub activate_false_failure: bool,
    /// Whether stopping a guardian's unit leaves its enclave running.
    pub terminate_fails: bool,
    /// A change every enclave plan also holds, such as drift elsewhere in the stack.
    pub extra_change: Option<(String, String)>,
    /// The enclave stack's `rotation:*` tags.
    pub rotation_tags: Vec<String>,
    pub counter: u32,
    /// What each SSM command printed, and whether it succeeded, by command ID.
    pub commands: BTreeMap<String, (String, bool)>,
}

impl State {
    fn slot_enabled(&self, slot: Slot) -> bool {
        match self.config.get(&format!("slot-{slot}-enabled")) {
            Some(value) => value == "true",
            None => slot == Slot::A,
        }
    }

    /// The commit and PCR0 the stack configures for a slot.
    fn build(&self, slot: Slot) -> (String, String) {
        let key = |name: &str| {
            self.config
                .get(&format!("{name}{}", slot.suffix()))
                .cloned()
                .unwrap_or_default()
        };
        (key("hashi-commit"), key("eif-pcr0"))
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
            outputs["standby_instance_id"] = standby
                .map(|id| self.standby_output.clone().unwrap_or_else(|| id.clone()))
                .unwrap_or_default()
                .into();
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
            // The first 16 digits name the session in the log.
            key: format!("{:016x}", 0xabc0 + self.counter).repeat(4),
            btc: None,
            config_hash: None,
            lifecycle: "none".to_owned(),
            epoch: None,
        }
    }

    /// The enclave stack's plan, of `target` and what depends on it, or of the whole stack.
    fn enclave_plan(&self, target: Option<&str>) -> Vec<(String, String)> {
        let mut steps = Vec::new();
        for slot in Slot::ALL {
            let urn = format!("{URN_PREFIX}{slot}");
            if target.is_some_and(|target| target != urn) {
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
        steps.extend(self.extra_change.clone());
        if target.is_none() {
            steps.extend(
                self.other_creates
                    .iter()
                    .map(|urn| ("create".to_owned(), urn.clone())),
            );
            steps.push(("same".to_owned(), STACK_URN.to_owned()));
        }
        steps
    }

    fn apply_enclave(&mut self, target: &str) {
        for (op, urn) in self.enclave_plan(Some(target)) {
            let slot = urn.rsplit('-').next().unwrap().to_owned();
            match op.as_str() {
                "create" => {
                    self.counter += 1;
                    let id = format!("i-0{slot}{:03}", self.counter);
                    let session = self.new_session();
                    let ip = format!("192.0.2.{}", self.counter);
                    let commit = self.build(if slot == "b" { Slot::B } else { Slot::A }).0;
                    self.hosts.insert(
                        id.clone(),
                        Host {
                            ip,
                            commit,
                            running: true,
                            enclave: true,
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
        let task = |backend: &str, standby: &Option<String>, tag: &str| {
            crate::proxy::tests::task(backend, standby.as_deref(), &format!("repo:{tag}"))
        };
        let old = task(&self.backend, &self.standby, &self.running_tag);
        let new = task(&backend, &standby, &self.configured_tag);
        if old == new {
            return json!({ "steps": [{ "op": "read", "urn": "urn:pulumi:testnet::proxy::pulumi:pulumi:StackReference::org/enclave/testnet" }], "changeSummary": {} });
        }
        crate::proxy::tests::proxy_plan(old, new)
    }

    /// The revision of the proxy's task definition ECS runs, and its proxy container.
    fn running_task(&self) -> (u32, Value) {
        let (revision, backend, standby) = self
            .rolled_back
            .clone()
            .unwrap_or_else(|| (self.revision, self.backend.clone(), self.standby.clone()));
        let container = crate::proxy::tests::container(
            &backend,
            standby.as_deref(),
            &format!("repo:{}", self.running_tag),
        );
        (revision, container)
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
    init_records.insert(
        "aa".repeat(8),
        init_record(&"cf".repeat(32), &[(COMMIT.to_owned(), "0c".repeat(48))]),
    );
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
                commit: COMMIT.to_owned(),
                running: true,
                enclave: true,
                session: serving,
            },
        )]
        .into_iter()
        .collect(),
        backend: "http://192.0.2.10:3000".to_owned(),
        standby: None,
        running_tag: "v1".to_owned(),
        revision: 7,
        configured_tag: "v1".to_owned(),
        service_counts: (1, 1, 1),
        rolls_back: false,
        rolled_back: None,
        other_creates: Vec::new(),
        standby_output: None,
        ec2_states: BTreeMap::new(),
        workflow_runs: Vec::new(),
        init_records,
        monitor_builds: None,
        local_commits: vec![COMMIT.to_owned(), NEXT.to_owned()],
        format_changes: Vec::new(),
        sui_epoch: 1253,
        epoch_age: (3 * 3600, 27 * 3600),
        activate_false_failure: false,
        terminate_fails: false,
        extra_change: None,
        rotation_tags: Vec::new(),
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
            ["pulumi", "version"] => ok("v3.0.0\n".to_owned()),
            ["pulumi", "-C", dir, rest @ ..] => {
                let program = std::path::Path::new(dir).file_name()?.to_str()?;
                let proxy = program == "proxy";
                match rest {
                    ["config", "get", "audit", "--json", "--stack", _] if program == "monitor" => {
                        let build = |(commit, pcr0): &(String, String)| json!({ "git_revision": commit, "pcr0": pcr0 });
                        let Some(builds) = &s.monitor_builds else {
                            return fail();
                        };
                        let audit = json!({ "deployment": { "pcr_allowlist": {
                            "current_build": builds.first().map(build),
                            "prev_builds": builds.iter().skip(1).map(build).collect::<Vec<_>>(),
                        } } });
                        ok(json!({ "value": audit.to_string(), "objectValue": audit, "secret": false }).to_string())
                    }
                    ["config", "--stack", _, "--json"] => {
                        let mut config: serde_json::Map<String, Value> = s
                            .config
                            .iter()
                            .map(|(key, value)| (format!("enclave:{key}"), json!({ "value": value })))
                            .collect();
                        config.insert("aws:region".to_owned(), json!({ "value": "us-west-2" }));
                        ok(Value::Object(config).to_string())
                    }
                    ["config", "get", "proxy-image-tag", "--stack", _] if proxy => ok(format!("{}\n", s.configured_tag)),
                    ["config", "get", "aws-region", "--stack", _] if proxy => ok("us-west-2\n".to_owned()),
                    ["stack", "output", "--json", ..] => ok(s.outputs().to_string()),
                    ["stack", "output", "s3_access_key_id", ..] => ok("test-access-key\n".to_owned()),
                    ["stack", "output", "s3_secret_access_key", "--show-secrets", ..] => ok("test-secret-key\n".to_owned()),
                    ["stack", "tag", "ls", ..] => ok(Value::Object(
                        s.rotation_tags.iter().map(|tag| (tag.clone(), json!("x"))).collect(),
                    )
                    .to_string()),
                    ["stack", "export", ..] => {
                        let resources: Vec<Value> = if proxy {
                            vec![
                                json!({ "type": "aws:ecs/service:Service", "urn": SERVICE,
                                    "outputs": { "cluster": "proxy-cluster", "name": "proxy-service" } }),
                                json!({ "type": "aws:ecs/taskDefinition:TaskDefinition", "urn": TASK,
                                    "outputs": { "arn": task_definition(s.revision) } }),
                            ]
                        } else {
                            s.deployed
                                .iter()
                                .map(|(slot, id)| json!({ "type": "aws:ec2/instance:Instance", "urn": format!("{URN_PREFIX}{slot}"), "id": id,
                                    "outputs": { "arn": format!("arn:aws:ec2:us-west-2:{ACCOUNT}:instance/{id}") } }))
                                .collect()
                        };
                        ok(json!({ "deployment": { "manifest": { "version": "v3.0.0" }, "resources": resources } }).to_string())
                    }
                    ["preview", "--stack", _, "--json"] if proxy => ok(s.proxy_plan().to_string()),
                    ["preview", "--stack", _, "--json"] => {
                        let steps: Vec<Value> = s
                            .enclave_plan(None)
                            .into_iter()
                            .map(|(op, urn)| json!({ "op": op, "urn": urn }))
                            .collect();
                        ok(json!({ "steps": steps, "changeSummary": {} }).to_string())
                    }
                    ["preview", "--stack", _, "--target", target, "--target-dependents", "--json"] => {
                        let steps: Vec<Value> = s
                            .enclave_plan(Some(target))
                            .into_iter()
                            .map(|(op, urn)| json!({ "op": op, "urn": urn }))
                            .collect();
                        ok(json!({ "steps": steps, "changeSummary": {} }).to_string())
                    }
                    ["up", "--stack", _, "--yes"] if proxy => {
                        if s.rolls_back {
                            s.rolled_back = Some((s.revision, s.backend.clone(), s.standby.clone()));
                        }
                        s.revision += 1;
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
                        "gitRevision": host.commit,
                        "committeeEpoch": session.epoch.map(|epoch| epoch.to_string()),
                        "timestampMs": jiff::Timestamp::now().as_millisecond().to_string(),
                    })
                    .to_string())
                }
                None => fail(),
            },
            ["aws", "ec2", "describe-instances", .., "--instance-ids", id, "--query", _, "--output", "text"] => {
                match s.ec2_states.get(*id) {
                    Some(state) => ok(format!("{state}\n")),
                    None if s.hosts.contains_key(*id) => ok("running\n".to_owned()),
                    None => fail(),
                }
            }
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
                let revision = s.running_task().0;
                ok(format!("{desired}\t{running}\t{deployments}\t{}\n", task_definition(revision)))
            }
            ["aws", "ecs", "describe-task-definition", ..] => ok(s.running_task().1.to_string()),
            ["aws", "sts", "get-caller-identity", ..] => ok(format!("{ACCOUNT}\n")),
            ["aws", "s3", "cp", .., source, "-"] => {
                let session = source.split("/init/").nth(1)?.split('/').next()?.to_owned();
                match s.init_records.get(&session) {
                    Some(record) => ok(json!({ "message": { "Init": { "OIGuardianInfo": record } } }).to_string()),
                    None => fail(),
                }
            }
            ["aws", "s3api", "list-object-versions", .., "--prefix", key, "--query", _, "--output", "text"] => {
                let session = key.strip_prefix("init/")?.split('/').next()?;
                ok(if s.init_records.contains_key(session) { "1\t0\n" } else { "0\t0\n" }.to_owned())
            }
            ["aws", "s3api", "list-objects-v2", .., "--prefix", "init/", "--query", _, "--output", "json"] => {
                let keys: Vec<String> = s
                    .init_records
                    .keys()
                    .flat_map(|session| {
                        ["01-oi-attestation.json", "02-oi-guardian-info.json"]
                            .map(|name| format!("init/{session}/{name}"))
                    })
                    .collect();
                ok(Value::from(keys).to_string())
            }
            ["git", "-C", _, "rev-parse", "--verify", "--quiet", rev] => {
                let rev = rev.strip_suffix("^{commit}")?;
                match s.local_commits.iter().find(|commit| !rev.is_empty() && commit.starts_with(rev)) {
                    Some(commit) => ok(format!("{commit}\n")),
                    None => fail(),
                }
            }
            ["git", "-C", _, "diff", "--name-only", _, _, "--", ..] => ok(s.format_changes.join("\n")),
            ["aws", "ssm", "send-command", .., "--parameters", parameters] => {
                let instance = w[w.iter().position(|word| *word == "--instance-ids")? + 1];
                if s.ec2_states.contains_key(instance) {
                    return fail();
                }
                let script = parameters.to_owned();
                let terminate_fails = s.terminate_fails;
                let host = s.hosts.get_mut(instance)?;
                if script.contains("disable --now") {
                    host.running = false;
                    host.enclave = terminate_fails;
                }
                let out = if script.contains("GUARDIAN_RUNNING") {
                    let state = if host.running { "GUARDIAN_RUNNING" } else { "GUARDIAN_STOPPED" };
                    (state.to_owned(), true)
                } else if script.contains("an enclave still runs") && (host.running || host.enclave) {
                    ("an enclave still runs".to_owned(), false)
                } else {
                    (String::new(), true)
                };
                s.counter += 1;
                let id = format!("cmd-{}", s.counter);
                s.commands.insert(id.clone(), out);
                ok(format!("{id}\n"))
            }
            ["aws", "ssm", "wait", "command-executed", _, _, "--command-id", id, ..] => {
                Some((s.commands.get(*id).is_some_and(|(_, success)| *success), String::new()))
            }
            ["aws", "ssm", "get-command-invocation", _, _, "--command-id", id, ..] => {
                ok(format!("{}\t\n", s.commands.get(*id).map(|(out, _)| out.clone()).unwrap_or_default()))
            }
            ["gh", "api", "--paginate", runs, "--jq", ".workflow_runs[].path"] => {
                let (repo, query) = runs.strip_prefix("repos/")?.split_once("/actions/runs?status=")?;
                let status = query.split('&').next()?;
                ok(s.workflow_runs
                    .iter()
                    .filter(|(run_repo, run_status, _)| run_repo == repo && run_status == status)
                    .map(|(_, _, path)| format!("{path}\n"))
                    .collect())
            }
            ["cargo", "build", ..] => ok(r#"{"reason":"compiler-artifact","target":{"name":"hashi-guardian-init"},"executable":"/x/hashi-guardian-init"}"#.to_owned()),
            ["/x/hashi-guardian-init", "tools", "--help"] => ok("  check-config  Check a configuration\n".to_owned()),
            ["/x/hashi-guardian-init", "tools", "check-config", ..] => ok(String::new()),
            ["/x/hashi-guardian-init", "operator", "activate", ..] => {
                let others_quiet = s.hosts.values().all(|host| {
                    !(host.running || host.enclave)
                        || !host.session.lifecycle.starts_with("withdraw/ACTIVATED")
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

fn task_definition(revision: u32) -> String {
    format!("arn:aws:ecs:us-west-2:{ACCOUNT}:task-definition/proxy:{revision}")
}

/// Has the key provisioners provision `slot`'s guardian with the serving guardian's key, and the configuration a render
/// gives it: its own build, the other slot's and the stack's `prev-builds`. A different allowlist has another hash.
pub fn provision(state: &Rc<RefCell<State>>, slot: Slot) {
    let mut s = state.borrow_mut();
    let mut builds = vec![s.build(slot)];
    let listed: Vec<Value> = s
        .config
        .get("prev-builds")
        .map(|text| serde_json::from_str(text).unwrap())
        .unwrap_or_default();
    let listed = listed.iter().map(|build| {
        (
            build["git_revision"].as_str().unwrap().to_owned(),
            build["pcr0"].as_str().unwrap().to_owned(),
        )
    });
    for build in std::iter::once(s.build(slot.other()))
        .filter(|(commit, _)| !commit.is_empty())
        .chain(listed)
    {
        if !builds.iter().any(|(commit, _)| *commit == build.0) {
            builds.push(build);
        }
    }
    let serving = &s.hosts[&s.deployed[&s.outputs_active.to_string()]].session;
    let serving_record = &s.init_records[&serving.key[..16]];
    let hash = if init_record("", &builds)["deployment"] == serving_record["deployment"] {
        serving.config_hash.clone().unwrap()
    } else {
        let mut hasher = std::hash::DefaultHasher::new();
        std::hash::Hash::hash(&builds, &mut hasher);
        format!("{:016x}", std::hash::Hasher::finish(&hasher)).repeat(4)
    };
    let id = s.deployed[&slot.to_string()].clone();
    let host = s.hosts.get_mut(&id).unwrap();
    host.session.btc = Some(BTC.to_owned());
    host.session.config_hash = Some(hash.clone());
    host.session.lifecycle = "withdraw/PROVISIONER_INITIALIZED".to_owned();
    let session = host.session.key[..16].to_owned();
    s.init_records.insert(session, init_record(&hash, &builds));
}

/// A withdraw session's operator-init record, allowlisting `builds` with the first as its own.
pub fn init_record(config_hash: &str, builds: &[(String, String)]) -> Value {
    let build = |(commit, pcr0): &(String, String)| json!({ "git_revision": commit, "pcr0": pcr0 });
    json!({
        "deployment": {
            "bucket_info": { "name": "guardian-bucket", "region": "us-west-2" },
            "retention_environment": "testnet",
            "bitcoin_network": "signet",
            "pcr_allowlist": {
                "current_build": build(&builds[0]),
                "prev_builds": builds[1..].iter().map(build).collect::<Vec<_>>(),
            },
        },
        "mode": {
            "Withdraw": {
                "config_hash": config_hash,
                "limiter_config": { "refill_rate": 11574, "max_bucket_capacity": 1000000000 },
            },
        },
    })
}

/// Steps run against a serving world, from a checkout in a temporary directory.
pub struct Run {
    pub repo: tempfile::TempDir,
    pub state: Rc<RefCell<State>>,
    pub exec: Fake,
    pub env: Vec<(String, String)>,
}

impl Run {
    pub fn new() -> Self {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(COMMIT)).unwrap();
        let state = serving_world();
        let exec = exec(&state);
        let env = env(repo.path());
        Self {
            repo,
            state,
            exec,
            env,
        }
    }

    /// Runs `step` with the operator answering `answers`, and returns its result and the prompts it showed.
    pub fn step(
        &self,
        answers: &[&str],
        step: impl FnOnce(&Ctx) -> anyhow::Result<()>,
    ) -> (anyhow::Result<()>, Vec<String>) {
        let ask = Scripted::new(answers);
        let result = self.step_asking(&ask, step);
        let prompts = ask.prompts.borrow().clone();
        (result, prompts)
    }

    /// Runs `step` with `ask` answering its questions.
    pub fn step_asking(
        &self,
        ask: &dyn crate::ask::Ask,
        step: impl FnOnce(&Ctx) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        step(&Ctx::for_test(self.repo.path(), &self.exec, &self.pairs()).with_ask(ask))
    }

    /// Writes a slot's files as the render step does.
    pub fn render(&self, slot: Slot) {
        let ctx = Ctx::for_test(self.repo.path(), &self.exec, &self.pairs());
        let stack = Stack::load(&ctx).unwrap();
        let view = stack.slot(&ctx, slot).unwrap();
        SlotRender::new(&ctx, &stack, &view)
            .unwrap()
            .rendered
            .write(&view.dir)
            .unwrap();
    }

    fn pairs(&self) -> Vec<(&str, &str)> {
        self.env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }
}

/// The env file a rotation runs with, with its roster under `repo`.
pub fn env(repo: &std::path::Path) -> Vec<(String, String)> {
    let roster = crate::render::tests::roster_dir(&repo.join("roster"), &["alice", "bob"], "v1");
    [
        ("GUARDIAN_PULUMI_DIR", crate::stack::tests::ENCLAVE),
        ("GUARDIAN_STACK", "org/testnet"),
        ("GUARDIAN_PROXY_PULUMI_DIR", crate::stack::tests::PROXY),
        (
            "GUARDIAN_PROXY_URL",
            "https://guardian.testnet.hashi.sui.io",
        ),
        ("PULUMI_VERSION", "3.0.0"),
        (
            "GUARDIAN_WORKFLOWS",
            "org/infra/.github/workflows/guardian-*",
        ),
        ("KP_BUCKET", "kp-bucket"),
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

/// Adds the hashi-monitor that audits the guardian to `env`.
pub fn monitor(env: &mut Vec<(String, String)>) {
    const MONITOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/programs/monitor");
    if !env.iter().any(|(key, _)| key == "HASHI_MONITOR_PULUMI_DIR") {
        env.push(("HASHI_MONITOR_PULUMI_DIR".to_owned(), MONITOR.to_owned()));
    }
}
