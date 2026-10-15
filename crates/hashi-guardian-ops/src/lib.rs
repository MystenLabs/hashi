// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian operator's steps, run by `operator/scripts/guardian.sh`. It drives the guardian's infrastructure
//! (Pulumi, AWS, the proxy) from the latest checkout, and takes everything that must match the guardian from the
//! guardian's own commit: see [`commit`].

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;

pub mod commit;
pub mod env;
pub mod exec;
pub mod guardian;
pub mod host;
pub mod stack;
pub mod steps;
pub mod sui;

use env::Env;
use exec::Exec;

pub struct Ctx<'a> {
    pub env: Env,
    pub exec: &'a dyn Exec,
    /// The hashi checkout this tool runs from, which holds its rendered files under `.hashi/`.
    pub repo: PathBuf,
}

impl<'a> Ctx<'a> {
    pub fn new(env_file: &Path, exec: &'a dyn Exec) -> Result<Self> {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        Ok(Self {
            env: Env::load(env_file)?,
            exec,
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
            repo: repo.to_owned(),
        }
    }
}

pub fn say(title: &str) {
    println!("\n== {title} ==");
}

pub fn warn(message: &str) {
    eprintln!("\nWARNING: {message}");
}
