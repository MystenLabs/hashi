// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The operator's environment file: `KEY=VALUE` lines naming the guardian stack and its key provisioners.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;

/// The keys the file may set. It used to be sourced by bash, which let it set anything, such as `PATH` or
/// `AWS_PROFILE`; those belong in the shell now, so any other key is refused.
const KEYS: &[&str] = &[
    "GUARDIAN_PULUMI_DIR",
    "GUARDIAN_STACK",
    "GUARDIAN_PROXY_URL",
    "PULUMI_VERSION",
];

pub struct Env {
    path: PathBuf,
    values: BTreeMap<String, String>,
}

/// The proxy's public URL, and the authority gRPC clients dial for it.
pub struct ProxyUrl {
    pub url: String,
    pub authority: String,
}

impl Env {
    /// Reads `path`. Unlike when bash sourced it, a key the file leaves out stays unset: a shell value meant for
    /// another stack would otherwise mix in.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => bail!(
                "no environment file at {}; copy crates/hashi-guardian-ops/guardian.env.sample",
                path.display()
            ),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("could not read the environment file {}", path.display())
                });
            }
        };
        let home = std::env::var("HOME").ok();
        let values = parse(&text, home.as_deref())
            .with_context(|| format!("could not read the environment file {}", path.display()))?;
        Ok(Self::new(path.to_owned(), values))
    }

    pub fn new(path: PathBuf, values: BTreeMap<String, String>) -> Self {
        debug_assert!(
            values.keys().all(|key| KEYS.contains(&key.as_str())),
            "values hold a key the file may not set: {:?}",
            values.keys().collect::<Vec<_>>()
        );
        Self { path, values }
    }

    /// A key's value. An empty value counts as unset, as `${KEY:-}` reads it.
    pub fn get(&self, key: &str) -> Option<&str> {
        debug_assert!(KEYS.contains(&key), "{key} is not a key the file may set");
        self.values
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    pub fn require(&self, key: &str) -> Result<&str> {
        self.get(key)
            .ok_or_else(|| anyhow!("{} does not set {key}", self.path.display()))
    }

    pub fn proxy_url(&self) -> Result<ProxyUrl> {
        let url = self.require("GUARDIAN_PROXY_URL")?;
        let host = url.strip_prefix("https://").filter(|host| {
            !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        });
        let Some(host) = host else {
            bail!("GUARDIAN_PROXY_URL must be https:// and a host name, with no path: {url}");
        };
        Ok(ProxyUrl {
            url: url.to_owned(),
            authority: format!("{host}:443"),
        })
    }
}

fn parse(text: &str, home: Option<&str>) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            bail!("line {number} is not KEY=VALUE");
        };
        if key.starts_with("export ") {
            bail!("line {number} starts with export: write KEY=VALUE");
        }
        if !KEYS.contains(&key) {
            bail!("line {number} sets {key}, which no step reads; set it in your shell instead");
        }
        let value = parse_value(raw, home).with_context(|| format!("line {number} sets {key}"))?;
        if values.insert(key.to_owned(), value).is_some() {
            bail!("line {number} sets {key} a second time");
        }
    }
    Ok(values)
}

/// Reads a value as bash would: double-quoted, single-quoted or bare, then an optional comment. Only `$HOME` is
/// expanded; anything else bash would act on is refused rather than read differently.
fn parse_value(raw: &str, home: Option<&str>) -> Result<String> {
    let (value, rest) = match raw.chars().next() {
        Some(quote @ ('"' | '\'')) => {
            let end = raw[1..]
                .find(quote)
                .ok_or_else(|| anyhow!("a value with no closing {quote}"))?;
            let inner = &raw[1..1 + end];
            let value = if quote == '"' {
                expand(inner, home)?
            } else {
                inner.to_owned()
            };
            (value, &raw[2 + end..])
        }
        _ => {
            let end = raw.find(char::is_whitespace).unwrap_or(raw.len());
            let word = &raw[..end];
            if word.contains(['"', '\'', ';', '&', '|', '<', '>', '(', ')']) {
                bail!("a value with quotes or shell operators inside it");
            }
            if word.starts_with('~') || word.contains(":~") {
                bail!("a ~, which bash would expand: write $HOME instead");
            }
            (expand(word, home)?, &raw[end..])
        }
    };
    let comment = rest.trim_start();
    if !comment.is_empty() && (comment.len() == rest.len() || !comment.starts_with('#')) {
        bail!("text after its value");
    }
    Ok(value)
}

fn expand(text: &str, home: Option<&str>) -> Result<String> {
    if text.contains(['\\', '`']) {
        bail!("a backslash or backtick");
    }
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('$') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let length = if after.starts_with("{HOME}") {
            "{HOME}".len()
        } else if after.starts_with("HOME")
            && !after[4..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        {
            "HOME".len()
        } else {
            bail!("a $ other than $HOME, which is the only variable this file can use");
        };
        out.push_str(home.ok_or_else(|| anyhow!("$HOME, but HOME is not set"))?);
        rest = &after[length..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> Result<BTreeMap<String, String>> {
        parse(text, Some("/Users/op"))
    }

    const SAMPLE: &str = include_str!("../guardian.env.sample");

    #[test]
    fn reads_the_sample() {
        let values = parsed(SAMPLE).unwrap();
        assert_eq!(values["GUARDIAN_PULUMI_DIR"], "/Users/op/infra/enclave");
        assert_eq!(values["GUARDIAN_STACK"], "org/testnet");
        assert_eq!(values["PULUMI_VERSION"], "3.0.0");
    }

    /// The sample documents every key, set or commented out, so an operator learns of each from it.
    #[test]
    fn the_sample_names_every_key() {
        let named: Vec<&str> = SAMPLE
            .lines()
            .map(|line| line.trim_start_matches("# "))
            .filter_map(|line| line.split_once('=').map(|(key, _)| key))
            .filter(|key| {
                !key.is_empty() && key.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
            })
            .collect();
        let mut sorted = named.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), named.len(), "the sample names a key twice");
        let mut keys = KEYS.to_vec();
        keys.sort_unstable();
        assert_eq!(sorted, keys);
    }

    #[test]
    fn reads_values_as_bash_does() {
        assert!(parsed("# comment\n\n").unwrap().is_empty());
        let values = parsed(
            "GUARDIAN_STACK=org/testnet # trailing comment\nGUARDIAN_PULUMI_DIR='$HOME/x'\nGUARDIAN_PROXY_URL=\"${HOME}/a b\"\nPULUMI_VERSION=\n",
        )
        .unwrap();
        assert_eq!(values["GUARDIAN_STACK"], "org/testnet");
        assert_eq!(values["GUARDIAN_PULUMI_DIR"], "$HOME/x");
        assert_eq!(values["GUARDIAN_PROXY_URL"], "/Users/op/a b");
        assert_eq!(values["PULUMI_VERSION"], "");
    }

    #[test]
    fn refuses_what_bash_would_read_differently() {
        for text in [
            "PATH=/usr/bin",
            "AWS_PROFILE=operator",
            "export GUARDIAN_STACK=org/testnet",
            "GUARDIAN_STACK",
            "GUARDIAN_STACK=$USER",
            "GUARDIAN_STACK=$HOMEDIR",
            "GUARDIAN_STACK=\"$(whoami)\"",
            "GUARDIAN_STACK=`whoami`",
            "GUARDIAN_STACK=a\\ b",
            "GUARDIAN_STACK=a;b",
            "GUARDIAN_STACK=\"unterminated",
            "GUARDIAN_STACK=\"a\"b",
            "GUARDIAN_STACK=a#b c",
            "GUARDIAN_STACK=a\nGUARDIAN_STACK=b",
            "GUARDIAN_PULUMI_DIR=~/enclave",
            "GUARDIAN_PULUMI_DIR=/a:~/b",
        ] {
            assert!(parsed(text).is_err(), "accepted {text:?}");
        }
        assert_eq!(
            parsed("export GUARDIAN_STACK=org/testnet")
                .unwrap_err()
                .to_string(),
            "line 1 starts with export: write KEY=VALUE"
        );
    }

    #[test]
    #[should_panic(expected = "values hold a key the file may not set")]
    fn holds_only_keys_the_file_may_set() {
        let values = [("AWS_PROFILE".to_owned(), "operator".to_owned())].into();
        let _ = Env::new(PathBuf::from("testnet.env"), values);
    }

    #[test]
    fn says_why_it_cannot_read_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("testnet.env");
        assert_eq!(
            Env::load(&missing).err().unwrap().to_string(),
            format!(
                "no environment file at {}; copy crates/hashi-guardian-ops/guardian.env.sample",
                missing.display()
            )
        );
        let error = format!("{:#}", Env::load(dir.path()).err().unwrap());
        assert!(
            error.starts_with(&format!(
                "could not read the environment file {}: ",
                dir.path().display()
            )),
            "{error}"
        );
        std::fs::write(&missing, "GUARDIAN_STACK=org/testnet\n").unwrap();
        assert_eq!(
            Env::load(&missing).unwrap().get("GUARDIAN_STACK"),
            Some("org/testnet")
        );
    }

    fn env(values: &[(&str, &str)]) -> Env {
        Env::new(
            PathBuf::from("testnet.env"),
            values
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    #[test]
    fn checks_values() {
        let proxy = env(&[(
            "GUARDIAN_PROXY_URL",
            "https://guardian.testnet.hashi.sui.io",
        )])
        .proxy_url()
        .unwrap();
        assert_eq!(proxy.authority, "guardian.testnet.hashi.sui.io:443");
        for bad in [
            "http://guardian.testnet.hashi.sui.io",
            "https://guardian.testnet.hashi.sui.io/",
            "https://",
        ] {
            assert!(env(&[("GUARDIAN_PROXY_URL", bad)]).proxy_url().is_err());
        }
        assert_eq!(
            env(&[]).require("GUARDIAN_STACK").unwrap_err().to_string(),
            "testnet.env does not set GUARDIAN_STACK"
        );
    }
}
