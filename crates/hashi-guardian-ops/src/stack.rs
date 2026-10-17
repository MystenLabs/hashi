// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian enclave's Pulumi stack, read fresh by every step so none acts on a remembered value. The stack has
//! two slots, a and b; its outputs follow the active one and name the other as the standby.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;
use serde_json::Value;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read;
use crate::exec::read_json;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
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

/// The stack's configuration and outputs as a step found them when it started, so it acts on one view of both.
pub struct Stack {
    pub name: String,
    pub dir: String,
    /// The program's project, which prefixes its own configuration keys.
    project: String,
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
        let project = project_name(dir)?;
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
            project,
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

    /// A configuration value, or `None` when the key is unset.
    pub fn config(&self, key: &str) -> Option<&str> {
        self.config
            .get(&format!("{}:{key}", self.project))
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    pub fn output(&self, key: &str) -> Option<&str> {
        self.outputs
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    /// As the enclave program reads the key: slot a is on unless disabled, slot b is off unless enabled.
    pub fn slot_enabled(&self, slot: Slot) -> Result<bool> {
        match self.config(&format!("slot-{slot}-enabled")) {
            Some("1" | "t" | "T" | "TRUE" | "true" | "True") => Ok(true),
            Some("0" | "f" | "F" | "FALSE" | "false" | "False") => Ok(false),
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

    /// The stack's `rotation:*` tags, which hold rotation state apart from its configuration.
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

    /// The Pulumi CLI version that last wrote the stack's state, empty when the state doesn't say.
    pub fn written_by(&self, ctx: &Ctx) -> Result<String> {
        Ok(export(ctx, &self.dir, &self.name)?
            .deployment
            .manifest
            .version)
    }
}

/// The project a Pulumi program's own directory declares, whose name prefixes the program's configuration keys. `pulumi
/// -C` would use a parent directory's project instead, so a directory without one is refused.
pub fn project_name(dir: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Project {
        name: String,
    }
    let files: Vec<PathBuf> = ["Pulumi.yaml", "Pulumi.yml"]
        .iter()
        .map(|file| Path::new(dir).join(file))
        .filter(|path| path.is_file())
        .collect();
    let [file] = &files[..] else {
        bail!(
            "{dir} holds {} Pulumi project files, not one: name the Pulumi program's own directory.",
            files.len()
        );
    };
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("Could not read {}.", file.display()))?;
    let project: Project = serde_yaml::from_str(&text)
        .with_context(|| format!("{} names no Pulumi project.", file.display()))?;
    if project.name.is_empty() || project.name.contains(':') {
        bail!(
            "{} names the Pulumi project {:?}, which no configuration key can carry.",
            file.display(),
            project.name
        );
    }
    Ok(project.name)
}

#[derive(Deserialize)]
pub struct Export {
    pub deployment: Deployment,
}

#[derive(Deserialize)]
pub struct Deployment {
    pub manifest: Manifest,
}

#[derive(Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub version: String,
}

/// A stack's state, as `pulumi stack export` prints it.
pub fn export(ctx: &Ctx, dir: &str, stack: &str) -> Result<Export> {
    read_json(
        ctx.exec,
        &pulumi(dir).args(["stack", "export", "--stack", stack]),
    )
    .with_context(|| format!("Could not read stack {stack} in {dir}."))
}

/// The version of the Pulumi CLI on PATH, as `v<version>` like [`pulumi_pin`].
pub fn pulumi_version(ctx: &Ctx) -> Result<String> {
    let version = read(ctx.exec, &Cmd::new("pulumi").arg("version"))
        .context("Could not read the Pulumi CLI's version.")?;
    Ok(format!("v{}", version.trim().trim_start_matches('v')))
}

/// The Pulumi CLI version `PULUMI_VERSION` pins, as `v<version>` like [`pulumi_version`].
pub fn pulumi_pin(ctx: &Ctx) -> Result<String> {
    let pin = ctx.env.require("PULUMI_VERSION")?;
    Ok(format!("v{}", pin.trim().trim_start_matches('v')))
}

pub fn pulumi(dir: &str) -> Cmd {
    Cmd::new("pulumi").arg("-C").arg(dir)
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
    /// The test programs' directories, each holding only its project file.
    pub const ENCLAVE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/programs/enclave");

    /// A world whose pulumi answers with this configuration and these outputs.
    pub fn stack_world(config: Value, outputs: Value) -> Fake {
        Fake::new(move |words| {
            let rest: Vec<&str> = words.iter().skip(3).map(String::as_str).collect();
            match rest.as_slice() {
                ["config", "--stack", _, "--json"] => {
                    // A provider's keys sit beside the program's own.
                    let mut entries = serde_json::Map::new();
                    entries.insert(
                        "aws:region".to_owned(),
                        serde_json::json!({ "value": "us-west-2", "secret": false }),
                    );
                    for (key, value) in config.as_object().unwrap() {
                        entries.insert(
                            format!("enclave:{key}"),
                            serde_json::json!({ "value": value, "secret": false }),
                        );
                    }
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
            ("GUARDIAN_PULUMI_DIR", ENCLAVE),
            ("GUARDIAN_STACK", "org/testnet"),
            (
                "GUARDIAN_PROXY_URL",
                "https://guardian.testnet.hashi.sui.io",
            ),
            ("PULUMI_VERSION", "3.0.0"),
        ]
    }

    #[test]
    fn reads_a_one_slot_stack() {
        let exec = one_slot();
        let repo = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        let stack = Stack::load(&ctx).unwrap();
        assert_eq!(stack.slots().unwrap(), [Slot::A]);
        assert_eq!(stack.role(Slot::A).unwrap(), Role::Active);
        assert_eq!(stack.instance(Slot::A).unwrap(), Some("i-0aaa"));
        assert_eq!(stack.role(Slot::B).unwrap(), Role::Absent);
    }

    #[test]
    fn reads_both_slots_of_a_two_slot_stack() {
        let exec = two_slots();
        let repo = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        let stack = Stack::load(&ctx).unwrap();
        assert_eq!(stack.slots().unwrap(), [Slot::A, Slot::B]);
        assert_eq!(stack.role(Slot::B).unwrap(), Role::Standby);
        assert_eq!(stack.instance(Slot::B).unwrap(), Some("i-0bbb"));
    }

    #[test]
    fn refuses_what_the_enclave_program_would_not_read() {
        let repo = tempfile::tempdir().unwrap();
        let exec = stack_world(
            serde_json::json!({ "slot-b-enabled": "yes" }),
            serde_json::json!({ "active_slot": "c" }),
        );
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        let stack = Stack::load(&ctx).unwrap();
        assert_eq!(
            stack.slot_enabled(Slot::B).unwrap_err().to_string(),
            "Stack org/testnet sets slot-b-enabled to yes, not true or false."
        );
        assert_eq!(
            stack.active().unwrap_err().to_string(),
            "Stack org/testnet's active_slot output is c, not a or b."
        );
    }

    #[test]
    fn reads_only_the_programs_own_configuration() {
        let repo = tempfile::tempdir().unwrap();
        // A key in another namespace is no key of the program's.
        let exec = Fake::new(|words| {
            let config = serde_json::json!({
                "proxy:hashi-commit": { "value": COMMIT },
                "enclave:eif-pcr0": { "value": "0c".repeat(48) },
            });
            let reply = if words.iter().any(|word| word == "config") {
                config.to_string()
            } else {
                "{}".to_owned()
            };
            Some((true, reply))
        });
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        let stack = Stack::load(&ctx).unwrap();
        assert_eq!(stack.config("hashi-commit"), None);
        assert_eq!(stack.config("eif-pcr0"), Some("0c".repeat(48).as_str()));

        // Pulumi would take a parent directory's project for one the directory lacks.
        let programs = tempfile::tempdir().unwrap();
        let program = programs.path().join("program");
        std::fs::create_dir_all(&program).unwrap();
        std::fs::write(programs.path().join("Pulumi.yaml"), "name: parent\n").unwrap();
        let dir = program.display().to_string();
        assert_eq!(
            project_name(&dir).unwrap_err().to_string(),
            format!(
                "{dir} holds 0 Pulumi project files, not one: name the Pulumi program's own directory."
            )
        );
        std::fs::write(program.join("Pulumi.yaml"), "runtime: go\n").unwrap();
        assert!(
            project_name(&dir)
                .unwrap_err()
                .to_string()
                .ends_with("Pulumi.yaml names no Pulumi project.")
        );
        std::fs::write(program.join("Pulumi.yaml"), "name: program\nruntime: go\n").unwrap();
        assert_eq!(project_name(&dir).unwrap(), "program");
        std::fs::write(program.join("Pulumi.yml"), "name: program\n").unwrap();
        assert!(project_name(&dir).is_err());
    }

    #[test]
    fn follows_the_active_slot_after_a_switchover() {
        let repo = tempfile::tempdir().unwrap();
        // The program exports an empty standby once the old slot is torn down.
        let exec = stack_world(
            serde_json::json!({ "slot-a-enabled": "False", "slot-b-enabled": "1", "active-slot": "b" }),
            serde_json::json!({
                "active_slot": "b",
                "enclave_instance_id": "i-0bbb",
                "standby_instance_id": "",
                "s3_bucket_name": "guardian-bucket",
            }),
        );
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        let stack = Stack::load(&ctx).unwrap();
        assert_eq!(stack.active().unwrap(), Slot::B);
        assert!(!stack.slot_enabled(Slot::A).unwrap());
        assert!(stack.slot_enabled(Slot::B).unwrap());
        assert_eq!(stack.role(Slot::A).unwrap(), Role::Absent);
        assert_eq!(stack.instance(Slot::B).unwrap(), Some("i-0bbb"));
    }
}
