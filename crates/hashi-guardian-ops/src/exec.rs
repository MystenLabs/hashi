// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! External commands. Every step reaches Pulumi, AWS, GitHub, git, cargo and the guardian only through [`Exec`], so
//! tests can stand in for all of them at once.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use serde::de::DeserializeOwned;

/// The external programs the steps run.
pub const REQUIRED: [(&str, &str); 7] = [
    ("aws", "AWS CLI v2"),
    ("cargo", "Rust toolchain (rustup)"),
    ("curl", "standard system utilities"),
    ("git", "git"),
    ("grpcurl", "grpcurl"),
    ("pulumi", "Pulumi CLI"),
    ("tar", "standard system utilities"),
];

#[derive(Clone, Debug)]
pub struct Cmd {
    program: OsString,
    args: Vec<OsString>,
    cwd: Option<PathBuf>,
    env_remove: Vec<OsString>,
}

impl Cmd {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: program.as_ref().to_owned(),
            args: Vec::new(),
            cwd: None,
            env_remove: Vec::new(),
        }
    }

    /// Leaves `name` out of the command's environment.
    pub fn env_remove(mut self, name: impl AsRef<OsStr>) -> Self {
        self.env_remove.push(name.as_ref().to_owned());
        self
    }

    pub fn removed_env(&self) -> &[OsString] {
        &self.env_remove
    }

    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    pub fn args<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(mut self, args: I) -> Self {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_owned()));
        self
    }

    pub fn cwd(mut self, dir: impl AsRef<Path>) -> Self {
        self.cwd = Some(dir.as_ref().to_owned());
        self
    }

    /// The program and its arguments as text, for tests and messages.
    pub fn words(&self) -> Vec<String> {
        std::iter::once(&self.program)
            .chain(&self.args)
            .map(|word| word.to_string_lossy().into_owned())
            .collect()
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        // Keeps parsed output stable regardless of the operator's locale, and the AWS CLI on its default endpoints
        // and out of a pager.
        command
            .env("LC_ALL", "C")
            .env("AWS_PAGER", "")
            .env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true");
        if let Some(dir) = &self.cwd {
            command.current_dir(dir);
        }
        for name in &self.env_remove {
            command.env_remove(name);
        }
        command
    }

    fn describe(&self) -> String {
        const LIMIT: usize = 160;
        let text = self.words().join(" ");
        match text.char_indices().nth(LIMIT) {
            Some((end, _)) => format!("`{}…`", &text[..end]),
            None => format!("`{text}`"),
        }
    }
}

pub struct Output {
    pub success: bool,
    pub stdout: String,
}

pub trait Exec {
    /// Runs `cmd` to completion with its stdout captured and its stderr on the terminal, as `$(...)` does.
    fn output(&self, cmd: &Cmd) -> io::Result<Output>;

    /// Replaces this process with `cmd`, as bash's `exec` does. Returns only if that fails.
    fn exec(&self, cmd: &Cmd) -> io::Error;

    /// Whether `program` is on PATH.
    fn has(&self, program: &str) -> bool;
}

/// The real world.
pub struct System;

impl Exec for System {
    fn output(&self, cmd: &Cmd) -> io::Result<Output> {
        // Without the terminal, a command can neither take an answer typed ahead for a step's prompt nor hang on a
        // prompt of its own that nobody sees.
        let output = cmd
            .command()
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()?;
        Ok(Output {
            success: output.status.success(),
            stdout: String::from_utf8(output.stdout)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        })
    }

    fn exec(&self, cmd: &Cmd) -> io::Error {
        cmd.command().exec()
    }

    fn has(&self, program: &str) -> bool {
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                dir.join(program)
                    .metadata()
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
        })
    }
}

/// Runs `cmd` and returns its stdout, failing unless it exits successfully.
pub fn read(exec: &dyn Exec, cmd: &Cmd) -> Result<String> {
    let output = exec
        .output(cmd)
        .with_context(|| format!("Could not run {}.", cmd.describe()))?;
    if !output.success {
        return Err(anyhow!("{} failed.", cmd.describe()));
    }
    Ok(output.stdout)
}

/// Runs `cmd` and decodes its stdout as JSON.
pub fn read_json<T: DeserializeOwned>(exec: &dyn Exec, cmd: &Cmd) -> Result<T> {
    let stdout = read(exec, cmd)?;
    serde_json::from_str(&stdout).with_context(|| {
        format!(
            "{} printed something other than the JSON expected.",
            cmd.describe()
        )
    })
}

/// Stops unless every program the steps run is on PATH.
pub fn require_programs(exec: &dyn Exec) -> Result<()> {
    let missing: Vec<String> = REQUIRED
        .iter()
        .filter(|(program, _)| !exec.has(program))
        .map(|(program, package)| format!("  - {program} ({package})"))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "The following required CLI tools are not installed or not on PATH:\n{}\n\nInstall the listed tools, then run this step again.",
        missing.join("\n")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_commands_in_the_scripts_environment() {
        let command = Cmd::new("aws").env_remove("RUSTUP_TOOLCHAIN").command();
        let envs: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for (key, value) in [
            ("LC_ALL", Some("C")),
            ("AWS_PAGER", Some("")),
            ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", Some("true")),
            ("RUSTUP_TOOLCHAIN", None),
        ] {
            assert!(
                envs.contains(&(key.to_owned(), value.map(str::to_owned))),
                "{key}"
            );
        }
    }
}

#[cfg(test)]
pub mod fake {
    //! A stand-in world: each command is answered by a handler, and every command is recorded.

    use std::cell::RefCell;

    use super::*;

    pub type Handler = Box<dyn Fn(&[String]) -> Option<Output>>;

    pub struct Fake {
        handler: Handler,
        pub log: RefCell<Vec<Vec<String>>>,
        /// The variables each logged command leaves out of its environment.
        pub removed_env: RefCell<Vec<Vec<String>>>,
    }

    impl Fake {
        /// A world answering each command with `handler`'s (success, stdout); `None` means the command is unknown,
        /// which fails the test.
        pub fn new(handler: impl Fn(&[String]) -> Option<(bool, String)> + 'static) -> Self {
            Self {
                handler: Box::new(move |words| {
                    handler(words).map(|(success, stdout)| Output { success, stdout })
                }),
                log: RefCell::default(),
                removed_env: RefCell::default(),
            }
        }

        pub fn ran(&self, prefix: &[&str]) -> bool {
            self.log.borrow().iter().any(|words| {
                words.len() >= prefix.len() && words.iter().zip(prefix).all(|(w, p)| w == p)
            })
        }
    }

    impl Exec for Fake {
        fn output(&self, cmd: &Cmd) -> io::Result<Output> {
            let words = cmd.words();
            self.log.borrow_mut().push(words.clone());
            self.removed_env.borrow_mut().push(
                cmd.removed_env()
                    .iter()
                    .map(|name| name.to_string_lossy().into_owned())
                    .collect(),
            );
            Ok((self.handler)(&words).unwrap_or_else(|| panic!("unexpected command: {words:?}")))
        }

        fn exec(&self, cmd: &Cmd) -> io::Error {
            self.log.borrow_mut().push(cmd.words());
            io::Error::other("exec in a test")
        }

        fn has(&self, _program: &str) -> bool {
            true
        }
    }
}
