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
                .ok_or_else(|| anyhow!("Stack {} has no {key}.", stack.name))?;
            value.parse().map_err(|_| {
                anyhow!(
                    "Stack {}'s {key} is not a whole number: {value}",
                    stack.name
                )
            })
        };
        let refill_rate = sats("refill-rate-sats-per-sec")?;
        let max_bucket_capacity = sats("max-bucket-capacity-sats")?;
        // Every reader must allowlist each build that wrote the log, and this configuration lists one.
        let other = view.slot.other();
        if stack.slots()?.contains(&other) {
            let suffix = other.suffix();
            if stack.config(&format!("hashi-commit{suffix}")) != Some(&view.commit)
                || stack.config(&format!("eif-pcr0{suffix}")) != Some(pcr0)
            {
                bail!(
                    "Slots a and b of stack {} have different builds. Both write one log bucket, so give slot {} the same hashi-commit and eif-pcr0 as slot {other}.",
                    stack.name,
                    view.slot
                );
            }
        }
        // The enclave keeps the key it is initialized with, so this must be the stack's long-lived one.
        let access_key = stack
            .output_value(ctx, "s3_access_key_id", false)
            .context("Could not read the guardian's S3 access key.")?;
        let secret_key = stack
            .output_value(ctx, "s3_secret_access_key", true)
            .context("Could not read the guardian's S3 secret key.")?;
        let env = &ctx.env;
        Ok(Self {
            proxy_url: env.proxy_url()?.url,
            tunnel_endpoint: view.endpoint.clone(),
            bucket: bucket.name,
            region: bucket.region,
            retention_environment: env.require("RETENTION_ENVIRONMENT")?.to_owned(),
            bitcoin_network: env.require("BITCOIN_NETWORK")?.to_owned(),
            commit: view.commit.clone(),
            pcr0: pcr0.to_owned(),
            sui_rpc: env.require("SUI_RPC")?.to_owned(),
            package_id: env.require("HASHI_PACKAGE_ID")?.to_owned(),
            object_id: env.require("HASHI_OBJECT_ID")?.to_owned(),
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
            bail!("No verified roster in {dir}. Run download-kp-pubkeys.sh first.");
        }
        let mut found = Vec::new();
        for id in entries(root)? {
            if root.join(&id).is_dir() {
                for name in entries(&root.join(&id))? {
                    if name.ends_with("-kp-pubkey.asc") {
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
            bail!("No certificates in {dir}.");
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
        std::fs::read_dir(dir).with_context(|| format!("Could not read {}.", dir.display()))?
    {
        let name = entry?.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow!("{} holds a name that is not UTF-8.", dir.display()))?;
        if !name.starts_with('.') {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("Could not read {}.", path.display()))
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

    /// The configuration files, without the certificates they list.
    pub fn configs(&self) -> impl Iterator<Item = &str> {
        self.files
            .keys()
            .map(String::as_str)
            .filter(|path| path.ends_with(".yaml"))
    }

    /// Removes the operator's files, so no step runs with a configuration the guardian's tools refused.
    pub fn remove_operator_configs(&self, dir: &Path) -> Result<()> {
        for path in self
            .configs()
            .filter(|path| path.ends_with("operator.yaml"))
        {
            let path = dir.join(path);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("Could not remove {}.", path.display()))?;
            }
        }
        Ok(())
    }

    /// Writes the files into `dir`, replacing the certificates an earlier render left. Other files there, such as a
    /// ceremony's records, stay.
    pub fn write(&self, dir: &Path) -> Result<()> {
        let certs = dir.join("certs");
        if certs.exists() {
            std::fs::remove_dir_all(&certs)
                .with_context(|| format!("Could not remove {}.", certs.display()))?;
        }
        for (relative, bytes) in &self.files {
            let path = dir.join(relative);
            std::fs::create_dir_all(path.parent().unwrap_or(dir))?;
            if relative.ends_with("operator.yaml") {
                if path.exists() {
                    std::fs::remove_file(&path)?;
                }
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .and_then(|mut file| file.write_all(bytes))
            } else {
                std::fs::write(&path, bytes)
            }
            .with_context(|| format!("Could not write {}.", path.display()))?;
        }
        Ok(())
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
        std::fs::remove_file(scratch.path().join("r/roster.txt")).unwrap();
        assert_eq!(
            Roster::load(&dir, 2).err().unwrap().to_string(),
            format!("No verified roster in {dir}. Run download-kp-pubkeys.sh first.")
        );
    }

    #[test]
    fn writes_the_operators_file_for_its_eyes_only() {
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
        assert!(slot.join("kp-shares.json").exists());
        assert!(slot.join("certs/alice-kp-pubkey.asc").is_file());
        let mode = std::fs::metadata(slot.join("operator.yaml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
