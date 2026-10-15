// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian enclave's Pulumi stack, read fresh by every step so none acts on a remembered value. The stack has
//! two slots, a and b; its outputs follow the active one and name the other as the standby.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use serde::Deserialize;
use serde_json::Value;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read;
use crate::exec::read_json;

const PROJECT: &str = "hashi-guardian-enclave";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Slot {
    #[value(name = "a")]
    A,
    #[value(name = "b")]
    B,
}

impl Slot {
    pub const ALL: [Self; 2] = [Self::A, Self::B];

    /// The suffix of this slot's own configuration keys, such as `hashi-commit-b`.
    pub fn suffix(self) -> &'static str {
        match self {
            Self::A => "",
            Self::B => "-b",
        }
    }

    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::A => "a",
            Self::B => "b",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Active,
    Standby,
    Absent,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Absent => "absent",
        })
    }
}

pub struct Bucket {
    pub name: String,
    pub region: String,
}

/// One snapshot of the stack's configuration and outputs, so a step sees both as they were at one moment.
pub struct Stack {
    pub name: String,
    pub dir: String,
    config: BTreeMap<String, String>,
    outputs: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ConfigEntry {
    value: Option<Value>,
}

impl Stack {
    pub fn load(ctx: &Ctx) -> Result<Self> {
        let dir = ctx.env.require("GUARDIAN_PULUMI_DIR")?;
        let name = ctx.env.require("GUARDIAN_STACK")?;
        let config: BTreeMap<String, ConfigEntry> = read_json(
            ctx.exec,
            &pulumi(dir).args(["config", "--stack", name, "--json"]),
        )
        .with_context(|| format!("Could not read the configuration of stack {name} in {dir}."))?;
        let outputs: BTreeMap<String, Value> = read_json(
            ctx.exec,
            &pulumi(dir).args(["stack", "output", "--json", "--stack", name]),
        )
        .with_context(|| format!("Could not read the outputs of stack {name} in {dir}."))?;
        Ok(Self {
            name: name.to_owned(),
            dir: dir.to_owned(),
            config: config
                .into_iter()
                .filter_map(|(key, entry)| Some((key, scalar(entry.value?))))
                .collect(),
            outputs: outputs
                .into_iter()
                .map(|(key, value)| (key, scalar(value)))
                .collect(),
        })
    }

    /// The stack's name without its organization, which names its directory of rendered files.
    pub fn short_name(&self) -> &str {
        self.name.rsplit('/').next().unwrap_or(&self.name)
    }

    /// A configuration value, or `None` when the key is unset.
    pub fn config(&self, key: &str) -> Option<&str> {
        self.config
            .get(&format!("{PROJECT}:{key}"))
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    pub fn output(&self, key: &str) -> Option<&str> {
        self.outputs
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    /// As the enclave program reads it: slot a is on unless disabled, slot b is off unless enabled.
    pub fn slot_enabled(&self, slot: Slot) -> Result<bool> {
        match self.config(&format!("slot-{slot}-enabled")) {
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            None => Ok(slot == Slot::A),
            Some(other) => bail!(
                "Stack {} sets slot-{slot}-enabled to {other}, not true or false.",
                self.name
            ),
        }
    }

    /// The slot the outputs follow.
    pub fn active(&self) -> Result<Slot> {
        match self.output("active_slot") {
            None | Some("a") => Ok(Slot::A),
            Some("b") => Ok(Slot::B),
            Some(other) => bail!(
                "Stack {}'s active_slot output is {other}, not a or b.",
                self.name
            ),
        }
    }

    pub fn role(&self, slot: Slot) -> Result<Role> {
        Ok(if self.output("enclave_instance_id").is_none() {
            Role::Absent
        } else if slot == self.active()? {
            Role::Active
        } else if self.output("standby_instance_id").is_some() {
            Role::Standby
        } else {
            Role::Absent
        })
    }

    /// The slots the stack configures or still runs.
    pub fn slots(&self) -> Result<Vec<Slot>> {
        let mut slots = Vec::new();
        for slot in Slot::ALL {
            if self.slot_enabled(slot)? || self.role(slot)? != Role::Absent {
                slots.push(slot);
            }
        }
        Ok(slots)
    }

    pub fn instance(&self, slot: Slot) -> Result<Option<&str>> {
        Ok(match self.role(slot)? {
            Role::Active => self.output("enclave_instance_id"),
            Role::Standby => self.output("standby_instance_id"),
            Role::Absent => None,
        })
    }

    /// The guardian's log bucket, as the stack deployed it.
    pub fn bucket(&self) -> Result<Bucket> {
        match (
            self.output("s3_bucket_name"),
            self.output("s3_bucket_region"),
        ) {
            (Some(name), Some(region)) => Ok(Bucket {
                name: name.to_owned(),
                region: region.to_owned(),
            }),
            _ => bail!(
                "Stack {} in {} has no deployed guardian. Run the deploy step first.",
                self.name,
                self.dir
            ),
        }
    }

    /// The slot named on the command line, or else the stack's only one.
    pub fn select(&self, arg: Option<Slot>, step: &str) -> Result<Slot> {
        if let Some(slot) = arg {
            return Ok(slot);
        }
        match self.slots()?.as_slice() {
            [slot] => Ok(*slot),
            [] => bail!("Stack {} enables no guardian slot.", self.name),
            _ => bail!(
                "Stack {} has guardian slots a and b. Name the one this step acts on: {step} a or {step} b.",
                self.name
            ),
        }
    }

    /// What a step needs about a slot: its build, its deployed guardian, its tunnel and its rendered files.
    pub fn slot(&self, ctx: &Ctx, slot: Slot) -> Result<SlotView> {
        let suffix = slot.suffix();
        let commit = self.config(&format!("hashi-commit{suffix}")).unwrap_or("");
        if !is_hex(commit, 40) {
            bail!(
                "Stack {}'s hashi-commit{suffix} is not a full commit: {}",
                self.name,
                if commit.is_empty() { "unset" } else { commit }
            );
        }
        let base = ctx.env.tunnel_port()?;
        let port = match slot {
            Slot::A => base,
            Slot::B => base + 1,
        };
        Ok(SlotView {
            slot,
            commit: commit.to_owned(),
            pcr0_key: format!("eif-pcr0{suffix}"),
            role: self.role(slot)?,
            instance: self.instance(slot)?.map(str::to_owned),
            port,
            endpoint: format!("http://127.0.0.1:{port}"),
            dir: ctx
                .repo
                .join(".hashi/guardian")
                .join(self.short_name())
                .join(slot.to_string()),
        })
    }

    /// One output read on its own, so a secret one can be shown.
    pub fn output_value(&self, ctx: &Ctx, key: &str, secret: bool) -> Result<String> {
        let mut cmd = pulumi(&self.dir).args(["stack", "output", key]);
        if secret {
            cmd = cmd.arg("--show-secrets");
        }
        let value = read(ctx.exec, &cmd.args(["--stack", &self.name]))?;
        Ok(value.trim_end_matches('\n').to_owned())
    }

    /// The `rotation:*` tags sui-operations' rotation scripts keep on the stack.
    pub fn rotation_tags(&self, ctx: &Ctx) -> Result<Vec<String>> {
        let tags: BTreeMap<String, Value> = read_json(
            ctx.exec,
            &pulumi(&self.dir).args(["stack", "tag", "ls", "--stack", &self.name, "--json"]),
        )
        .with_context(|| format!("Could not list the tags of stack {}.", self.name))?;
        Ok(tags
            .into_keys()
            .filter(|key| key.starts_with("rotation:"))
            .collect())
    }

    /// The Pulumi CLI version that last wrote the stack's state.
    pub fn written_by(&self, ctx: &Ctx) -> Result<String> {
        #[derive(Deserialize)]
        struct Export {
            deployment: Deployment,
        }
        #[derive(Deserialize)]
        struct Deployment {
            manifest: Manifest,
        }
        #[derive(Deserialize)]
        struct Manifest {
            version: String,
        }
        let export: Export = read_json(
            ctx.exec,
            &pulumi(&self.dir).args(["stack", "export", "--stack", &self.name]),
        )
        .with_context(|| format!("Could not read stack {} in {}.", self.name, self.dir))?;
        Ok(export.deployment.manifest.version)
    }
}

/// What a step needs about one slot.
pub struct SlotView {
    pub slot: Slot,
    /// The commit the slot's guardian is built from.
    pub commit: String,
    /// The configuration key holding the slot's PCR0.
    pub pcr0_key: String,
    pub role: Role,
    pub instance: Option<String>,
    /// The local port its tunnel forwards.
    pub port: u16,
    pub endpoint: String,
    /// Its rendered files.
    pub dir: PathBuf,
}

impl SlotView {
    pub fn tunnel_down(&self) -> String {
        format!(
            "Could not reach slot {slot}'s guardian at {}. Run the tunnel step for slot {slot} again: it closes after 20 minutes without traffic.",
            self.endpoint,
            slot = self.slot
        )
    }

    /// The slot's instance, for steps that act on a deployed guardian.
    pub fn require_instance(&self, stack: &Stack) -> Result<&str> {
        self.instance.as_deref().ok_or_else(|| {
            anyhow!(
                "Slot {} of stack {} has no deployed guardian.",
                self.slot,
                stack.name
            )
        })
    }
}

/// The version of the Pulumi CLI on PATH.
pub fn pulumi_version(ctx: &Ctx) -> Result<String> {
    Ok(read(ctx.exec, &Cmd::new("pulumi").arg("version"))
        .context("Could not read the Pulumi CLI's version.")?
        .trim()
        .to_owned())
}

pub fn pulumi(dir: &str) -> Cmd {
    Cmd::new("pulumi").arg("-C").arg(dir)
}

pub fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn scalar(value: Value) -> String {
    match value {
        Value::String(text) => text,
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::exec::fake::Fake;

    pub const COMMIT: &str = "0873917ea0000000000000000000000000000000";

    /// A world whose pulumi answers with this configuration and these outputs.
    pub fn stack_world(config: Value, outputs: Value) -> Fake {
        Fake::new(move |words| {
            let rest: Vec<&str> = words.iter().skip(3).map(String::as_str).collect();
            match rest.as_slice() {
                ["config", "--stack", _, "--json"] => {
                    let entries: serde_json::Map<String, Value> = config
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(key, value)| {
                            (
                                format!("{PROJECT}:{key}"),
                                serde_json::json!({ "value": value, "secret": false }),
                            )
                        })
                        .collect();
                    Some((true, Value::Object(entries).to_string()))
                }
                ["stack", "output", "--json", "--stack", _] => Some((true, outputs.to_string())),
                _ => None,
            }
        })
    }

    pub fn one_slot() -> Fake {
        stack_world(
            serde_json::json!({ "hashi-commit": COMMIT, "eif-pcr0": "0c".repeat(48) }),
            serde_json::json!({
                "active_slot": "a",
                "enclave_instance_id": "i-0aaa",
                "standby_instance_id": "",
                "s3_bucket_name": "guardian-bucket",
                "s3_bucket_region": "us-west-2",
            }),
        )
    }

    pub fn two_slots() -> Fake {
        stack_world(
            serde_json::json!({
                "hashi-commit": COMMIT,
                "hashi-commit-b": COMMIT,
                "slot-b-enabled": "true",
            }),
            serde_json::json!({
                "active_slot": "a",
                "enclave_instance_id": "i-0aaa",
                "standby_instance_id": "i-0bbb",
                "s3_bucket_name": "guardian-bucket",
                "s3_bucket_region": "us-west-2",
            }),
        )
    }

    pub fn stack_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("GUARDIAN_PULUMI_DIR", "/ops/hashi-guardian-enclave"),
            ("GUARDIAN_STACK", "mysten/testnet"),
            (
                "GUARDIAN_PROXY_URL",
                "https://guardian.testnet.hashi.sui.io",
            ),
        ]
    }

    #[test]
    fn reads_a_one_slot_stack() {
        let exec = one_slot();
        let repo = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        let stack = Stack::load(&ctx).unwrap();
        assert_eq!(stack.slots().unwrap(), [Slot::A]);
        assert_eq!(stack.select(None, "info").unwrap(), Slot::A);
        let view = stack.slot(&ctx, Slot::A).unwrap();
        assert_eq!(view.role, Role::Active);
        assert_eq!(view.instance.as_deref(), Some("i-0aaa"));
        assert_eq!(view.endpoint, "http://127.0.0.1:3000");
        assert_eq!(view.dir, repo.path().join(".hashi/guardian/testnet/a"));
        assert_eq!(stack.bucket().unwrap().name, "guardian-bucket");
        assert_eq!(stack.role(Slot::B).unwrap(), Role::Absent);
    }

    #[test]
    fn names_slots_on_a_two_slot_stack() {
        let exec = two_slots();
        let repo = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        let stack = Stack::load(&ctx).unwrap();
        assert_eq!(
            stack.select(None, "info").unwrap_err().to_string(),
            "Stack mysten/testnet has guardian slots a and b. Name the one this step acts on: info a or info b."
        );
        let view = stack.slot(&ctx, Slot::B).unwrap();
        assert_eq!(view.role, Role::Standby);
        assert_eq!(view.instance.as_deref(), Some("i-0bbb"));
        assert_eq!(view.port, 3001);
        assert_eq!(view.pcr0_key, "eif-pcr0-b");
    }

    #[test]
    fn refuses_what_the_enclave_program_would_not_read() {
        let repo = tempfile::tempdir().unwrap();
        let exec = stack_world(
            serde_json::json!({ "slot-b-enabled": "yes", "hashi-commit": "0873917ea" }),
            serde_json::json!({}),
        );
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        let stack = Stack::load(&ctx).unwrap();
        assert_eq!(
            stack.slot_enabled(Slot::B).unwrap_err().to_string(),
            "Stack mysten/testnet sets slot-b-enabled to yes, not true or false."
        );
        assert_eq!(
            stack.slot(&ctx, Slot::A).err().unwrap().to_string(),
            "Stack mysten/testnet's hashi-commit is not a full commit: 0873917ea"
        );
        assert_eq!(
            stack.bucket().err().unwrap().to_string(),
            "Stack mysten/testnet in /ops/hashi-guardian-enclave has no deployed guardian. Run the deploy step first."
        );
    }
}
