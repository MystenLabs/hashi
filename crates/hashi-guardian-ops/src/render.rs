// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A slot's configuration: `guardian-init.yaml` for the key provisioners and `operator.yaml` for the operator, beside
//! the certificates they list. Both name everything the operator and the key provisioners must agree on, with the
//! endpoint each reaches the guardian by.
//!
//! The layout is guardian.sh's, byte for byte, so files rendered by either stay fresh for the other.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;

use crate::Ctx;
use crate::stack::SlotView;
use crate::stack::Stack;
use crate::stack::is_hex;

pub const ATTESTATION_SUFFIXES: [&str; 3] = [
    "attestation-device.pem",
    "attestation-sig.pem",
    "attestation-dec.pem",
];

/// What the files say, from the stack and the environment file.
pub struct Settings {
    pub proxy_url: String,
    pub tunnel_endpoint: String,
    pub bucket: String,
    pub region: String,
    pub retention_environment: String,
    pub bitcoin_network: String,
    pub commit: String,
    pub pcr0: String,
    pub sui_rpc: String,
    pub package_id: String,
    pub object_id: String,
    pub refill_rate: u64,
    pub max_bucket_capacity: u64,
    pub access_key: String,
    pub secret_key: String,
}

impl Settings {
    pub fn read(ctx: &Ctx, stack: &Stack, view: &SlotView) -> Result<Self> {
        let bucket = stack.bucket()?;
        let pcr0 = stack.config(&view.pcr0_key).unwrap_or("");
        if !is_hex(pcr0, 96) {
            bail!(
                "{} is not a PCR0 measurement: {}",
                view.pcr0_key,
                if pcr0.is_empty() { "unset" } else { pcr0 }
            );
        }
        let sats = |key: &str| -> Result<u64> {
            let value = stack
                .config(key)
                .ok_or_else(|| anyhow!("stack {} has no {key}", stack.name))?;
            value.parse().map_err(|_| {
                anyhow!(
                    "stack {}'s {key} is not a whole number: {value}",
                    stack.name
                )
            })
        };
        let refill_rate = sats("refill-rate-sats-per-sec")?;
        let max_bucket_capacity = sats("max-bucket-capacity-sats")?;
        // Every reader must allowlist each build that wrote the log, and this configuration lists only its own. The
        // other slot's keys name its build after its teardown too.
        let other = view.slot.other();
        let suffix = other.suffix();
        if let Some(commit) = stack.config(&format!("hashi-commit{suffix}"))
            && (commit != view.commit || stack.config(&format!("eif-pcr0{suffix}")) != Some(pcr0))
        {
            bail!(
                "slots a and b of stack {} name different builds; a guardian must allowlist every build that wrote its log, and slot {}'s configurations can list only its own",
                stack.name,
                view.slot
            );
        }
        // The enclave keeps the key it is initialized with, so this must be the stack's long-lived one.
        let access_key = stack
            .output("s3_access_key_id")
            .ok_or_else(|| anyhow!("stack {} has no s3_access_key_id output", stack.name))?
            .to_owned();
        let secret_key = stack
            .output_value(ctx, "s3_secret_access_key", true)
            .context("could not read the guardian's S3 secret key")?;
        let env = &ctx.env;
        // The files quote every value as JSON does, which YAML reads the same only for printable ASCII.
        let plain = |key: &str| -> Result<String> {
            let value = env.require(key)?;
            if !value.chars().all(|c| c == ' ' || c.is_ascii_graphic()) {
                bail!("{key} holds characters other than printable ASCII");
            }
            Ok(value.to_owned())
        };
        Ok(Self {
            proxy_url: env.proxy_url()?.url,
            tunnel_endpoint: view.endpoint.clone(),
            bucket: bucket.name,
            region: bucket.region,
            retention_environment: plain("RETENTION_ENVIRONMENT")?,
            bitcoin_network: plain("BITCOIN_NETWORK")?,
            commit: view.commit.clone(),
            pcr0: pcr0.to_owned(),
            sui_rpc: plain("SUI_RPC")?,
            package_id: plain("HASHI_PACKAGE_ID")?,
            object_id: plain("HASHI_OBJECT_ID")?,
            refill_rate,
            max_bucket_capacity,
            access_key,
            secret_key,
        })
    }
}

/// A verified roster, as `download-kp-pubkeys.sh` wrote it: one directory per key provisioner.
pub struct Roster {
    pub threshold: u32,
    certs: Vec<Cert>,
}

struct Cert {
    name: String,
    /// The certificate and its attestation files, by file name.
    files: Vec<(String, Vec<u8>)>,
}

impl Roster {
    pub fn load(dir: &str, threshold: u32) -> Result<Self> {
        let root = Path::new(dir);
        if !root.join("roster.txt").is_file() {
            bail!("no verified roster in {dir}; run the download-kp-pubkeys step first");
        }
        let mut found = Vec::new();
        for id in entries(root)? {
            if root.join(&id).is_dir() {
                for name in entries(&root.join(&id))? {
                    if name.ends_with("-kp-pubkey.asc") {
                        // The configurations list certificates unquoted, as guardian.sh did.
                        let plain = |part: &str| {
                            part.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                        };
                        if !plain(&id) || !plain(&name) {
                            bail!(
                                "{dir}/{id}/{name} has a name the configurations can't list: use letters, digits, dots, hyphens and underscores only"
                            );
                        }
                        found.push((id.clone(), name));
                    }
                }
            }
        }
        // In the order of bash's `*/*-kp-pubkey.asc`, which sorts whole paths: `a-b/` comes before `a/`.
        found.sort_by_key(|(id, name)| format!("{id}/{name}"));
        let mut certs = Vec::new();
        for (id, name) in found {
            let dir = root.join(&id);
            let stem = name.trim_end_matches(".asc");
            let mut files = vec![(name.clone(), read(&dir.join(&name))?)];
            for suffix in ATTESTATION_SUFFIXES {
                let sibling = format!("{stem}.{suffix}");
                files.push((sibling.clone(), read(&dir.join(&sibling))?));
            }
            certs.push(Cert { name, files });
        }
        if certs.is_empty() {
            bail!("no certificates in {dir}");
        }
        Ok(Self { threshold, certs })
    }

    pub fn kp_count(&self) -> usize {
        self.certs.len()
    }

    fn names(&self) -> Vec<&str> {
        self.certs.iter().map(|cert| cert.name.as_str()).collect()
    }
}

/// Non-hidden entries of a directory, which bash's globs match.
fn entries(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("could not read {}", dir.display()))?
    {
        let name = entry?.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow!("{} holds a name that is not UTF-8", dir.display()))?;
        if !name.starts_with('.') {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("could not read {}", path.display()))
}

/// Rendered files by path relative to the slot's directory. `operator.yaml` holds the stack's S3 key.
pub struct Rendered {
    files: BTreeMap<String, Vec<u8>>,
}

impl Rendered {
    /// The slot's files.
    pub fn new(settings: &Settings, dealt: &Roster) -> Self {
        let mut rendered = Self {
            files: BTreeMap::new(),
        };
        rendered.add_configs(settings, dealt);
        rendered.add_certs(dealt);
        rendered
    }

    fn add_configs(&mut self, settings: &Settings, roster: &Roster) {
        self.files.insert(
            "guardian-init.yaml".to_owned(),
            config(settings, &settings.proxy_url, roster).into_bytes(),
        );
        let operator = format!(
            "{}\ns3_credentials:\n  access_key: {}\n  secret_key: {}\n",
            config(settings, &settings.tunnel_endpoint, roster),
            quote(&settings.access_key),
            quote(&settings.secret_key)
        );
        self.files
            .insert("operator.yaml".to_owned(), operator.into_bytes());
    }

    /// Adds a roster's files under `certs/`.
    fn add_certs(&mut self, roster: &Roster) {
        for cert in &roster.certs {
            for (name, bytes) in &cert.files {
                self.files.insert(format!("certs/{name}"), bytes.clone());
            }
        }
    }

    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Every file, by its path in the slot's directory.
    pub fn files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    /// The configuration files, without the certificates they list.
    pub fn configs(&self) -> impl Iterator<Item = &str> {
        self.files
            .keys()
            .map(String::as_str)
            .filter(|path| path.ends_with(".yaml"))
    }

    /// Where [`Rendered::write_unchecked`] puts a file, relative to the slot's directory: each configuration waits
    /// under another name until the guardian's tools have checked it, so no step finds one they never passed.
    pub fn written(path: &str) -> String {
        if path.ends_with(".yaml") {
            format!("{path}.unchecked")
        } else {
            path.to_owned()
        }
    }

    /// Removes the configurations, so no step runs with one the guardian's tools refused.
    pub fn remove_configs(&self, dir: &Path) -> Result<()> {
        for config in self.configs() {
            for path in [dir.join(config), dir.join(Self::written(config))] {
                if path.exists() {
                    std::fs::remove_file(&path)
                        .with_context(|| format!("could not remove {}", path.display()))?;
                }
            }
        }
        Ok(())
    }

    /// Writes the files into `dir`, replacing the certificates and configurations an earlier render left. Other files
    /// there, such as a ceremony's records, stay.
    pub fn write(&self, dir: &Path) -> Result<()> {
        self.write_unchecked(dir)?;
        self.place_configs(dir)
    }

    /// Writes the files as [`Rendered::write`] does, with the configurations where [`Rendered::written`] says until
    /// [`Rendered::place_configs`].
    pub fn write_unchecked(&self, dir: &Path) -> Result<()> {
        self.remove_configs(dir)?;
        let certs = dir.join("certs");
        if certs.exists() {
            std::fs::remove_dir_all(&certs)
                .with_context(|| format!("could not remove {}", certs.display()))?;
        }
        for (relative, bytes) in &self.files {
            let path = dir.join(Self::written(relative));
            std::fs::create_dir_all(path.parent().unwrap_or(dir))?;
            if relative.ends_with("operator.yaml") {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .and_then(|mut file| file.write_all(bytes))
            } else {
                std::fs::write(&path, bytes)
            }
            .with_context(|| format!("could not write {}", path.display()))?;
        }
        Ok(())
    }

    /// Moves the configurations into place, once checked.
    pub fn place_configs(&self, dir: &Path) -> Result<()> {
        for config in self.configs() {
            let (from, to) = (dir.join(Self::written(config)), dir.join(config));
            std::fs::rename(&from, &to).with_context(|| {
                format!("could not move {} to {}", from.display(), to.display())
            })?;
        }
        Ok(())
    }

    /// The files in `dir` that differ from this render. Only the files a render writes count: Finder, for one, adds
    /// its own to a directory it has shown.
    pub fn stale(&self, dir: &Path) -> Vec<&str> {
        self.files
            .iter()
            .filter(|(relative, bytes)| {
                std::fs::read(dir.join(relative)).ok().as_ref() != Some(*bytes)
            })
            .map(|(relative, _)| relative.as_str())
            .collect()
    }
}

/// A slot's files as a render would write them now, with what they were rendered from.
pub struct SlotRender {
    pub settings: Settings,
    pub dealt: Roster,
    pub rendered: Rendered,
}

impl SlotRender {
    pub fn new(ctx: &Ctx, stack: &Stack, view: &SlotView) -> Result<Self> {
        let settings = Settings::read(ctx, stack, view)?;
        let dealt = Roster::load(
            ctx.env.require("KP_ROSTER_DIR")?,
            threshold(ctx, "KP_THRESHOLD")?,
        )?;
        let rendered = Rendered::new(&settings, &dealt);
        Ok(Self {
            settings,
            dealt,
            rendered,
        })
    }
}

fn threshold(ctx: &Ctx, key: &str) -> Result<u32> {
    let value = ctx.env.require(key)?;
    value
        .parse()
        .map_err(|_| anyhow!("{key} is not a number: {value}"))
}

/// Stops unless the slot's rendered files are what a render would write now: the stack, the environment file and
/// the rosters can each have changed since the render step ran.
pub fn require_fresh(ctx: &Ctx, stack: &Stack, view: &SlotView) -> Result<()> {
    let operator = view.dir.join("operator.yaml");
    if !operator.is_file() {
        bail!(
            "no {}; run the render step for slot {} first",
            operator.display(),
            view.slot
        );
    }
    let render = SlotRender::new(ctx, stack, view)?;
    let stale = render.rendered.stale(&view.dir);
    if !stale.is_empty() {
        bail!(
            "out of date in {}: {}; the stack, {} or the roster changed after the render step; run it again, then publish again and have every key provisioner download again, unless only operator.yaml is out of date",
            view.dir.display(),
            stale.join(", "),
            ctx.env.path().display()
        );
    }
    Ok(())
}

/// A rendered configuration. `endpoint` is how its reader reaches the guardian: the proxy for key provisioners, the
/// slot's tunnel for the operator.
fn config(settings: &Settings, endpoint: &str, roster: &Roster) -> String {
    let s = settings;
    let mut lines = vec![
        format!("guardian_endpoint: {}", quote(endpoint)),
        format!("relay_endpoint: {}", quote(&s.proxy_url)),
        String::new(),
        "deployment:".to_owned(),
        "  bucket_info:".to_owned(),
        format!("    name: {}", quote(&s.bucket)),
        format!("    region: {}", quote(&s.region)),
        format!(
            "  retention_environment: {}",
            quote(&s.retention_environment)
        ),
        format!("  bitcoin_network: {}", quote(&s.bitcoin_network)),
        "  pcr_allowlist:".to_owned(),
        "    current_build:".to_owned(),
        format!("      git_revision: {}", quote(&s.commit)),
        format!("      pcr0: {}", quote(&s.pcr0)),
        "    prev_builds: []".to_owned(),
        String::new(),
        "hashi:".to_owned(),
        format!("  sui_rpc: {}", quote(&s.sui_rpc)),
        format!("  package_id: {}", quote(&s.package_id)),
        format!("  hashi_object_id: {}", quote(&s.object_id)),
        String::new(),
    ];
    lines.extend(roster_lines("kp_roster", roster));
    lines.extend([
        String::new(),
        "limiter_config:".to_owned(),
        format!("  refill_rate: {}", s.refill_rate),
        format!("  max_bucket_capacity: {}", s.max_bucket_capacity),
    ]);
    lines.join("\n") + "\n"
}

fn roster_lines(name: &str, roster: &Roster) -> Vec<String> {
    let mut lines = vec![
        format!("{name}:"),
        format!("  num_shares: {}", roster.kp_count()),
        format!("  threshold: {}", roster.threshold),
        "  kp_pgp_cert_paths:".to_owned(),
    ];
    lines.extend(
        roster
            .names()
            .into_iter()
            .map(|cert| format!("    - certs/{cert}")),
    );
    lines
}

/// A YAML double-quoted string. JSON's escaping is valid YAML, and matches bash's `"%s"` for any plain value.
fn quote(value: &str) -> String {
    serde_json::Value::from(value).to_string()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn settings() -> Settings {
        Settings {
            proxy_url: "https://guardian.testnet.hashi.sui.io".to_owned(),
            tunnel_endpoint: "http://127.0.0.1:3001".to_owned(),
            bucket: "guardian-bucket".to_owned(),
            region: "us-west-2".to_owned(),
            retention_environment: "testnet".to_owned(),
            bitcoin_network: "signet".to_owned(),
            commit: "0873917ea0000000000000000000000000000000".to_owned(),
            pcr0: "0c".repeat(48),
            sui_rpc: "https://fullnode.testnet.sui.io:443".to_owned(),
            package_id: format!("0x{}1", "0".repeat(63)),
            object_id: format!("0x{}2", "0".repeat(63)),
            refill_rate: 11574,
            max_bucket_capacity: 1_000_000_000,
            access_key: "test-access-key".to_owned(),
            secret_key: "test-secret-key".to_owned(),
        }
    }

    /// A roster directory as `download-kp-pubkeys.sh` writes it, each file holding `tag` and its own name.
    pub fn roster_dir(root: &Path, ids: &[&str], tag: &str) -> String {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join("roster.txt"), "1  x\n").unwrap();
        for id in ids {
            let dir = root.join(id);
            std::fs::create_dir_all(&dir).unwrap();
            let stem = format!("{id}-kp-pubkey");
            for name in std::iter::once(format!("{stem}.asc"))
                .chain(ATTESTATION_SUFFIXES.iter().map(|s| format!("{stem}.{s}")))
            {
                std::fs::write(dir.join(&name), format!("{tag} {name}")).unwrap();
            }
            std::fs::write(dir.join(format!("{id}-kp-fingerprint.txt")), "F").unwrap();
        }
        root.display().to_string()
    }

    #[test]
    fn matches_guardian_sh_byte_for_byte() {
        // guardian.sh's write_config rendered these, on main at d732e3717.
        let golden = |name: &str| {
            std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("testdata/render")
                    .join(name),
            )
            .unwrap()
        };
        let scratch = tempfile::tempdir().unwrap();
        let dealt = Roster::load(
            &roster_dir(&scratch.path().join("dealt"), &["alice", "bob"], "v1"),
            2,
        )
        .unwrap();
        let mut s = settings();
        s.tunnel_endpoint = s.proxy_url.clone();
        assert_eq!(config(&s, &s.proxy_url, &dealt), golden("one-roster.yaml"));
        let rendered = Rendered::new(&settings(), &dealt);
        let operator = String::from_utf8(rendered.file("operator.yaml").unwrap().to_vec()).unwrap();
        assert!(operator.ends_with(&golden("credentials.yaml")));
    }

    #[test]
    fn loads_only_a_verified_roster() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = roster_dir(&scratch.path().join("r"), &["bob", "alice"], "v1");
        assert_eq!(
            Roster::load(&dir, 2).unwrap().names(),
            ["alice-kp-pubkey.asc", "bob-kp-pubkey.asc"]
        );
        let prefixes = roster_dir(&scratch.path().join("p"), &["a", "a-b", "a.c", "a_d"], "v1");
        assert_eq!(
            Roster::load(&prefixes, 2).unwrap().names(),
            [
                "a-b-kp-pubkey.asc",
                "a.c-kp-pubkey.asc",
                "a-kp-pubkey.asc",
                "a_d-kp-pubkey.asc"
            ]
        );
        std::fs::remove_file(
            scratch
                .path()
                .join("r/bob/bob-kp-pubkey.attestation-sig.pem"),
        )
        .unwrap();
        assert!(Roster::load(&dir, 2).is_err());
        // A name YAML would read differently unquoted.
        let odd = roster_dir(&scratch.path().join("o"), &["a #b"], "v1");
        assert!(
            Roster::load(&odd, 2)
                .err()
                .unwrap()
                .to_string()
                .ends_with("a name the configurations can't list: use letters, digits, dots, hyphens and underscores only")
        );
        std::fs::remove_file(scratch.path().join("r/roster.txt")).unwrap();
        assert_eq!(
            Roster::load(&dir, 2).err().unwrap().to_string(),
            format!("no verified roster in {dir}; run the download-kp-pubkeys step first")
        );
    }

    #[test]
    fn writes_and_checks_freshness() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = tempfile::tempdir().unwrap();
        let dealt = Roster::load(
            &roster_dir(&scratch.path().join("dealt"), &["alice", "bob"], "v1"),
            2,
        )
        .unwrap();
        let rendered = Rendered::new(&settings(), &dealt);
        let slot = scratch.path().join("slot");
        std::fs::create_dir_all(&slot).unwrap();
        std::fs::write(slot.join("kp-shares.json"), "kept").unwrap();
        rendered.write(&slot).unwrap();
        assert!(rendered.stale(&slot).is_empty());
        assert!(slot.join("kp-shares.json").exists());
        let mode = std::fs::metadata(slot.join("operator.yaml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::write(slot.join(".DS_Store"), "x").unwrap();
        std::fs::write(slot.join("certs/alice-kp-pubkey.asc"), "changed").unwrap();
        assert_eq!(rendered.stale(&slot), ["certs/alice-kp-pubkey.asc"]);
        // Until the guardian's tools pass them, the configurations wait under other names.
        rendered.write_unchecked(&slot).unwrap();
        for config in ["operator.yaml", "guardian-init.yaml"] {
            assert!(!slot.join(config).exists());
            assert!(slot.join(format!("{config}.unchecked")).is_file());
        }
        rendered.place_configs(&slot).unwrap();
        for config in ["operator.yaml", "guardian-init.yaml"] {
            assert!(slot.join(config).is_file());
            assert!(!slot.join(format!("{config}.unchecked")).exists());
        }
    }

    /// Slot `slot`'s settings, from a stack with `config` whose slot a serves.
    fn read_settings(
        config: serde_json::Value,
        slot: crate::stack::Slot,
        network: &str,
    ) -> Result<Settings> {
        let stack = crate::stack::tests::stack_world(
            config,
            serde_json::json!({
                "active_slot": "a",
                "enclave_instance_id": "i-0aaa",
                "standby_instance_id": "",
                "s3_bucket_name": "guardian-bucket",
                "s3_bucket_region": "us-west-2",
                "s3_access_key_id": "test-access-key",
            }),
        );
        let exec = crate::exec::fake::Fake::new(move |words| {
            if words.iter().any(|word| word == "s3_secret_access_key") {
                return Some((true, "test-secret-key\n".to_owned()));
            }
            crate::exec::Exec::output(&stack, &crate::exec::Cmd::new("pulumi").args(&words[1..]))
                .ok()
                .map(|output| (output.success, output.stdout))
        });
        let repo = tempfile::tempdir().unwrap();
        let mut env = crate::stack::tests::stack_env();
        env.extend([
            ("SUI_RPC", "https://fullnode.testnet.sui.io:443"),
            ("HASHI_PACKAGE_ID", "0x1"),
            ("HASHI_OBJECT_ID", "0x2"),
            ("BITCOIN_NETWORK", network),
            ("RETENTION_ENVIRONMENT", "testnet"),
        ]);
        let ctx = Ctx::for_test(repo.path(), &exec, &env);
        let stack = Stack::load(&ctx)?;
        let view = stack.slot(&ctx, slot)?;
        Settings::read(&ctx, &stack, &view)
    }

    #[test]
    fn refuses_a_stack_whose_other_slot_names_another_build() {
        use crate::stack::Slot;
        use crate::stack::tests::COMMIT;
        let config = |other: &str| {
            serde_json::json!({
                "hashi-commit": COMMIT,
                "eif-pcr0": "0c".repeat(48),
                "hashi-commit-b": other,
                "eif-pcr0-b": "0c".repeat(48),
                "slot-b-enabled": "false",
                "refill-rate-sats-per-sec": "11574",
                "max-bucket-capacity-sats": "1000000000",
            })
        };
        read_settings(config(COMMIT), Slot::A, "signet").unwrap();
        // A torn-down slot's keys still name a build that wrote the log.
        assert_eq!(
            read_settings(config(&"c4".repeat(20)), Slot::A, "signet")
                .err()
                .unwrap()
                .to_string(),
            "slots a and b of stack org/testnet name different builds; a guardian must allowlist every build that wrote its log, and slot a's configurations can list only its own"
        );
        assert_eq!(
            read_settings(config(COMMIT), Slot::A, "sig\u{85}net")
                .err()
                .unwrap()
                .to_string(),
            "BITCOIN_NETWORK holds characters other than printable ASCII"
        );
    }
}
