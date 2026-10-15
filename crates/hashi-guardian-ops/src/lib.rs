// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian operator's steps, run by `operator/scripts/guardian.sh`. It drives the guardian's infrastructure
//! (Pulumi, AWS, the proxy) from the latest checkout, and takes everything that must match the guardian from the
//! guardian's own commit: see [`commit`].

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;

pub mod ask;
pub mod commit;
pub mod env;
pub mod exec;
pub mod github;
pub mod guardian;
pub mod host;
pub mod kp_bucket;
pub mod plan;
pub mod proxy;
pub mod render;
pub mod stack;
pub mod steps;
pub mod sui;
#[cfg(test)]
mod world;

use ask::Ask;
use env::Env;
use exec::Exec;

pub struct Ctx<'a> {
    pub env: Env,
    pub exec: &'a dyn Exec,
    pub ask: &'a dyn Ask,
    /// The hashi checkout this tool runs from, which holds its rendered files under `.hashi/`.
    pub repo: PathBuf,
}

impl<'a> Ctx<'a> {
    pub fn new(env_file: &Path, exec: &'a dyn Exec, ask: &'a dyn Ask) -> Result<Self> {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        Ok(Self {
            env: Env::load(env_file)?,
            exec,
            ask,
            repo: std::fs::canonicalize(&repo)
                .with_context(|| format!("Could not find this checkout at {}.", repo.display()))?,
        })
    }

    #[cfg(test)]
    pub fn for_test(repo: &Path, exec: &'a dyn Exec, values: &[(&str, &str)]) -> Self {
        let values = values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        Self {
            env: Env::new(PathBuf::from("testnet.env"), values).unwrap(),
            exec,
            ask: &ask::scripted::NO_ANSWERS,
            repo: repo.to_owned(),
        }
    }

    #[cfg(test)]
    pub fn with_ask(self, ask: &'a dyn Ask) -> Self {
        Self { ask, ..self }
    }
}

pub fn say(title: &str) {
    println!("\n== {title} ==");
}

pub fn warn(message: &str) {
    eprintln!("\nWARNING: {message}");
}

/// Ends a step by naming the one after it, so the steps and the runbook can't drift apart.
pub fn next(step: &str) {
    println!("\nNext: {step}");
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// hashi is public, so fixtures keep the shapes of real records with none of their account data.
    #[test]
    fn fixtures_hold_no_credentials_or_account_data() {
        let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                let words: Vec<&str> = text
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == ':'))
                    .collect();
                for word in words {
                    let found = (word.len() >= 20
                        && word.starts_with("AKIA")
                        && word[4..20]
                            .bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
                        || (word.len() == 12 && word.bytes().all(|b| b.is_ascii_digit()))
                        || word.starts_with("arn:aws:")
                        || is_private_ip(word);
                    assert!(!found, "{} holds {word}", path.display());
                }
            }
        }
    }

    fn is_private_ip(word: &str) -> bool {
        let octets: Vec<u8> = word
            .split('.')
            .filter_map(|part| part.parse().ok())
            .collect();
        octets.len() == 4
            && word.split('.').count() == 4
            && match octets[..2] {
                [10, _] => true,
                [172, second] => (16..=31).contains(&second),
                [192, 168] => true,
                _ => false,
            }
    }
}
