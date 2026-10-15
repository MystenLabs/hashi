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

const ATTESTATION_SUFFIXES: [&str; 3] = [
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
    pub dir: String,
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
        let mut certs = Vec::new();
        for id in sorted_entries(root)? {
            let id_dir = root.join(&id);
            if !id_dir.is_dir() {
                continue;
            }
            for name in sorted_entries(&id_dir)? {
                let Some(stem) = name
                    .strip_suffix(".asc")
                    .filter(|_| name.ends_with("-kp-pubkey.asc"))
                else {
                    continue;
                };
                let mut files = vec![(name.clone(), read(&id_dir.join(&name))?)];
                for suffix in ATTESTATION_SUFFIXES {
                    let sibling = format!("{stem}.{suffix}");
                    files.push((sibling.clone(), read(&id_dir.join(&sibling))?));
                }
                certs.push(Cert { name, files });
            }
        }
        if certs.is_empty() {
            bail!("No certificates in {dir}.");
        }
        Ok(Self {
            dir: dir.to_owned(),
            threshold,
            certs,
        })
    }

    pub fn kp_count(&self) -> usize {
        self.certs.len()
    }

    fn names(&self) -> Vec<&str> {
        self.certs.iter().map(|cert| cert.name.as_str()).collect()
    }
}

/// Non-hidden entries of a directory in byte order, as bash's globs list them under `LC_ALL=C`.
fn sorted_entries(dir: &Path) -> Result<Vec<String>> {
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
    names.sort();
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
    /// The slot's files. A KP-set rotation adds `rotate-kp-set/`, whose files list both rosters for the re-deal, while
    /// the slot's own files list the new roster, which provisions guardians once the re-deal completes.
    pub fn new(settings: &Settings, dealt: &Roster, new: Option<&Roster>) -> Result<Self> {
        let mut rendered = Self {
            files: BTreeMap::new(),
        };
        let Some(new) = new else {
            rendered.add_configs("", settings, dealt, None);
            rendered.add_certs("", dealt, None)?;
            return Ok(rendered);
        };
        rendered.add_configs("", settings, new, None);
        rendered.add_certs("", new, None)?;
        rendered.add_configs("rotate-kp-set/", settings, dealt, Some(new));
        rendered.add_certs("rotate-kp-set/", dealt, None)?;
        rendered.add_certs("rotate-kp-set/", new, Some(dealt))?;
        Ok(rendered)
    }

    fn add_configs(
        &mut self,
        prefix: &str,
        settings: &Settings,
        roster: &Roster,
        new: Option<&Roster>,
    ) {
        self.files.insert(
            format!("{prefix}guardian-init.yaml"),
            config(settings, &settings.proxy_url, roster, new).into_bytes(),
        );
        let operator = format!(
            "{}\ns3_credentials:\n  access_key: {}\n  secret_key: {}\n",
            config(settings, &settings.tunnel_endpoint, roster, new),
            quote(&settings.access_key),
            quote(&settings.secret_key)
        );
        self.files
            .insert(format!("{prefix}operator.yaml"), operator.into_bytes());
    }

    /// Adds a roster's files under `certs/`. A configuration lists two rosters by file name, so one name must be one
    /// certificate in both.
    fn add_certs(&mut self, prefix: &str, roster: &Roster, other: Option<&Roster>) -> Result<()> {
        for cert in &roster.certs {
            for (name, bytes) in &cert.files {
                let path = format!("{prefix}certs/{name}");
                if let Some(existing) = self.files.get(&path)
                    && existing != bytes
                {
                    bail!(
                        "{name} differs between {} and {}. A key provisioner with a new certificate needs a new user ID.",
                        other.map_or(roster.dir.as_str(), |other| other.dir.as_str()),
                        roster.dir
                    );
                }
                self.files.insert(path, bytes.clone());
            }
        }
        Ok(())
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
        for stale in ["certs", "rotate-kp-set"] {
            let path = dir.join(stale);
            if path.exists() {
                std::fs::remove_dir_all(&path)
                    .with_context(|| format!("Could not remove {}.", path.display()))?;
            }
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
    /// The roster a KP-set rotation re-deals to.
    pub new: Option<Roster>,
    pub rendered: Rendered,
}

impl SlotRender {
    pub fn new(ctx: &Ctx, stack: &Stack, view: &SlotView) -> Result<Self> {
        let settings = Settings::read(ctx, stack, view)?;
        let dealt = Roster::load(
            ctx.env.require("KP_ROSTER_DIR")?,
            threshold(ctx, "KP_THRESHOLD")?,
        )?;
        let new = match ctx.env.get("NEW_KP_ROSTER_DIR") {
            Some(dir) => Some(Roster::load(dir, threshold(ctx, "NEW_KP_THRESHOLD")?)?),
            None => None,
        };
        let rendered = Rendered::new(&settings, &dealt, new.as_ref())?;
        Ok(Self {
            settings,
            dealt,
            new,
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
            "No {}. Run the render step for slot {} first.",
            operator.display(),
            view.slot
        );
    }
    let render = SlotRender::new(ctx, stack, view)?;
    let stale = render.rendered.stale(&view.dir);
    if !stale.is_empty() {
        bail!(
            "Out of date in {}: {}. The stack, {} or the roster changed after the render step. Run it again, then publish again and have every key provisioner download again, unless only operator.yaml is out of date.",
            view.dir.display(),
            stale.join(", "),
            ctx.env.path().display()
        );
    }
    Ok(())
}

/// A rendered configuration. `endpoint` is how its reader reaches the guardian: the proxy for key provisioners, the
/// slot's tunnel for the operator.
fn config(settings: &Settings, endpoint: &str, roster: &Roster, new: Option<&Roster>) -> String {
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
    if let Some(new) = new {
        lines.push(String::new());
        lines.extend(roster_lines("new_kp_roster", new));
    }
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
        // Rendered by guardian.sh's own write_config, at the commit the 10-15 rotation ran.
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
        let new = Roster::load(
            &roster_dir(
                &scratch.path().join("new"),
                &["alice", "bob", "carol"],
                "v1",
            ),
            3,
        )
        .unwrap();
        let mut s = settings();
        s.tunnel_endpoint = s.proxy_url.clone();
        assert_eq!(
            config(&s, &s.proxy_url, &dealt, None),
            golden("one-roster.yaml")
        );
        assert_eq!(
            config(&s, "http://127.0.0.1:3001", &dealt, Some(&new)),
            golden("two-rosters.yaml")
        );
        let rendered = Rendered::new(&settings(), &dealt, None).unwrap();
        let operator = String::from_utf8(rendered.file("operator.yaml").unwrap().to_vec()).unwrap();
        assert!(operator.ends_with(&golden("credentials.yaml")));
    }

    #[test]
    fn renders_a_re_deal_beside_the_new_sets_files() {
        let scratch = tempfile::tempdir().unwrap();
        let dealt = Roster::load(
            &roster_dir(&scratch.path().join("dealt"), &["alice", "bob"], "v1"),
            2,
        )
        .unwrap();
        let new = Roster::load(
            &roster_dir(&scratch.path().join("new"), &["alice", "carol"], "v1"),
            2,
        )
        .unwrap();
        let rendered = Rendered::new(&settings(), &dealt, Some(&new)).unwrap();
        let text = |path: &str| String::from_utf8(rendered.file(path).unwrap().to_vec()).unwrap();
        assert!(text("guardian-init.yaml").contains("    - certs/carol-kp-pubkey.asc"));
        assert!(!text("guardian-init.yaml").contains("bob"));
        assert!(text("rotate-kp-set/guardian-init.yaml").contains("new_kp_roster:"));
        assert!(rendered.file("certs/bob-kp-pubkey.asc").is_none());
        for id in ["alice", "bob", "carol"] {
            assert!(
                rendered
                    .file(&format!(
                        "rotate-kp-set/certs/{id}-kp-pubkey.attestation-dec.pem"
                    ))
                    .is_some()
            );
        }
    }

    #[test]
    fn refuses_one_name_for_two_certificates() {
        let scratch = tempfile::tempdir().unwrap();
        let dealt_dir = roster_dir(&scratch.path().join("dealt"), &["alice"], "v1");
        let new_dir = roster_dir(&scratch.path().join("new"), &["alice"], "v2");
        let dealt = Roster::load(&dealt_dir, 2).unwrap();
        let new = Roster::load(&new_dir, 2).unwrap();
        let error = Rendered::new(&settings(), &dealt, Some(&new))
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            format!(
                "alice-kp-pubkey.asc differs between {dealt_dir} and {new_dir}. A key provisioner with a new certificate needs a new user ID."
            )
        );
    }

    #[test]
    fn loads_only_a_verified_roster() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = roster_dir(&scratch.path().join("r"), &["bob", "alice"], "v1");
        assert_eq!(
            Roster::load(&dir, 2).unwrap().names(),
            ["alice-kp-pubkey.asc", "bob-kp-pubkey.asc"]
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
    fn writes_and_checks_freshness() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = tempfile::tempdir().unwrap();
        let dealt = Roster::load(
            &roster_dir(&scratch.path().join("dealt"), &["alice", "bob"], "v1"),
            2,
        )
        .unwrap();
        let rendered = Rendered::new(&settings(), &dealt, None).unwrap();
        let slot = scratch.path().join("slot");
        std::fs::create_dir_all(slot.join("rotate-kp-set")).unwrap();
        std::fs::write(slot.join("kp-shares.json"), "kept").unwrap();
        rendered.write(&slot).unwrap();
        assert!(rendered.stale(&slot).is_empty());
        assert!(!slot.join("rotate-kp-set").exists());
        assert!(slot.join("kp-shares.json").exists());
        let mode = std::fs::metadata(slot.join("operator.yaml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::write(slot.join(".DS_Store"), "x").unwrap();
        std::fs::write(slot.join("certs/alice-kp-pubkey.asc"), "changed").unwrap();
        assert_eq!(rendered.stale(&slot), ["certs/alice-kp-pubkey.asc"]);
    }
}
