// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use hashi_types::pgp::EncryptionRecipient;
use hashi_types::pgp::RecipientAttestation;
use hashi_types::pgp::assemble_public_cert;
use sequoia_openpgp::Cert;
use sequoia_openpgp::Fingerprint;
use sequoia_openpgp::parse::Parse;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use crate::cli::print_info;
use crate::cli::print_success;

#[derive(Clone, Debug)]
pub struct RecipientInput {
    path: PathBuf,
    subkey: Option<Fingerprint>,
}

impl FromStr for RecipientInput {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (path, subkey) = match value.rsplit_once('=') {
            Some((path, fingerprint)) => (path, Some(parse_recipient_fingerprint(fingerprint)?)),
            None => (value, None),
        };
        anyhow::ensure!(
            !path.is_empty(),
            "recipient certificate path must not be empty"
        );
        Ok(Self {
            path: PathBuf::from(path),
            subkey,
        })
    }
}

fn parse_recipient_fingerprint(value: &str) -> Result<Fingerprint> {
    anyhow::ensure!(
        matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "recipient subkey fingerprint must be a full 40- or 64-digit hexadecimal fingerprint"
    );
    value.parse()
}

#[derive(Debug)]
struct RecipientAttestationBytes {
    device_pem: Vec<u8>,
    dec_pem: Vec<u8>,
}

fn load_recipient_attestations(
    inputs: &[PathBuf],
) -> Result<BTreeMap<Fingerprint, RecipientAttestationBytes>> {
    let mut attestations = BTreeMap::new();
    let mut triples = inputs.chunks_exact(3);
    anyhow::ensure!(
        triples.remainder().is_empty(),
        "each recipient attestation requires SUBKEY_FINGERPRINT DEVICE_PEM DEC_PEM"
    );
    for triple in &mut triples {
        let fingerprint = parse_recipient_fingerprint(
            triple[0]
                .to_str()
                .context("recipient subkey fingerprint must be valid UTF-8")?,
        )?;
        anyhow::ensure!(
            !attestations.contains_key(&fingerprint),
            "duplicate recipient attestation for subkey {fingerprint}"
        );
        let device_pem = fs::read(&triple[1]).with_context(|| {
            format!(
                "Failed to read recipient device attestation PEM {}",
                triple[1].display()
            )
        })?;
        let dec_pem = fs::read(&triple[2]).with_context(|| {
            format!(
                "Failed to read recipient DEC attestation PEM {}",
                triple[2].display()
            )
        })?;
        attestations.insert(
            fingerprint,
            RecipientAttestationBytes {
                device_pem,
                dec_pem,
            },
        );
    }
    Ok(attestations)
}

pub fn run(
    primary_cert: &Path,
    recipients: &[RecipientInput],
    recipient_attestations: &[PathBuf],
    require_recipient_attestation: bool,
    output: &Path,
    gpg_homedir: Option<&Path>,
) -> Result<()> {
    let primary = Cert::from_file(primary_cert).with_context(|| {
        format!(
            "Failed to read primary public certificate {}",
            primary_cert.display()
        )
    })?;
    let recipient_certs = recipients
        .iter()
        .map(|recipient| {
            Cert::from_file(&recipient.path).with_context(|| {
                format!(
                    "Failed to read recipient public certificate {}",
                    recipient.path.display()
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let recipients = recipients
        .iter()
        .zip(&recipient_certs)
        .map(|(input, cert)| EncryptionRecipient {
            cert,
            subkey: input.subkey.as_ref(),
        })
        .collect::<Vec<_>>();
    let attestation_bytes = load_recipient_attestations(recipient_attestations)?;
    let attestations = attestation_bytes
        .iter()
        .map(|(fingerprint, evidence)| {
            (
                fingerprint.clone(),
                RecipientAttestation {
                    device_pem: &evidence.device_pem,
                    dec_pem: &evidence.dec_pem,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let context = match gpg_homedir {
        Some(home) => sequoia_gpg_agent::Context::with_homedir(home),
        None => sequoia_gpg_agent::Context::new(),
    }
    .context(
        "Failed to initialize GnuPG context; gpgconf and an existing GnuPG home are required",
    )?;
    context
        .start("gpg-agent")
        .context("Failed to start the GnuPG agent")?;
    let mut signer =
        sequoia_gpg_agent::KeyPair::new_for_gnupg_context(&context, primary.primary_key().key())
            .context("Failed to create the gpg-agent signer for the primary key")?;
    let assembled = assemble_public_cert(
        &primary,
        &recipients,
        &attestations,
        require_recipient_attestation,
        &mut signer,
    )
    .context("Failed to assemble backup certificate")?;
    let cert = Cert::from_bytes(assembled.armored().as_bytes())
        .context("Failed to parse assembled public certificate")?;

    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staging = tempfile::Builder::new()
        .prefix(".hashi-assemble-cert-")
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "Failed to create certificate staging file in {}",
                parent.display()
            )
        })?;
    staging
        .write_all(assembled.armored().as_bytes())
        .context("Failed to write assembled public certificate")?;
    staging
        .as_file()
        .sync_all()
        .context("Failed to sync assembled public certificate")?;
    staging
        .persist_noclobber(output)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "Failed to publish certificate {}; output must not exist",
                output.display()
            )
        })?;

    print_success(&format!(
        "Assembled backup certificate written to {}",
        output.display()
    ));
    print_info(&format!("Primary fingerprint: {}", cert.fingerprint()));
    for key in cert.keys().subkeys() {
        print_info(&format!(
            "Recipient encryption subkey fingerprint: {}",
            key.key().fingerprint()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn recipient_input_parses_paths_and_full_fingerprints() {
        let path = "certs/recipient public.asc";
        let input: RecipientInput = path.parse().unwrap();
        assert_eq!(input.path, Path::new(path));
        assert!(input.subkey.is_none());

        for fingerprint in ["a".repeat(40), "B".repeat(64)] {
            let input: RecipientInput = format!("{path}={fingerprint}").parse().unwrap();
            assert_eq!(input.path, Path::new(path));
            assert_eq!(input.subkey, Some(fingerprint.parse().unwrap()));
        }

        for invalid in [
            String::new(),
            format!("={}", "A".repeat(40)),
            format!("{path}="),
            format!("{path}=0123456789ABCDEF"),
            format!("{path}={}", "G".repeat(40)),
        ] {
            assert!(invalid.parse::<RecipientInput>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn assemble_cert_cli_parses_recipient_attestation_triples() {
        use clap::Parser as _;

        #[derive(clap::Parser)]
        struct TestCli {
            #[command(subcommand)]
            command: crate::cli::BackupCommands,
        }

        let first = "a".repeat(40);
        let second = "B".repeat(64);
        let mut args = vec![
            "hashi",
            "assemble-cert",
            "--primary-cert",
            "primary.asc",
            "--recipient",
            "recipient.asc",
            "--output",
            "assembled.asc",
            "--require-recipient-attestation",
            "--recipient-attestation",
            &first,
            "device one.pem",
            "dec one.pem",
            "--recipient-attestation",
            &second,
            "device two.pem",
            "dec two.pem",
        ];
        let crate::cli::BackupCommands::AssembleCert {
            recipient_attestation,
            require_recipient_attestation,
            ..
        } = TestCli::try_parse_from(&args).unwrap().command
        else {
            panic!("expected assemble-cert");
        };
        assert!(require_recipient_attestation);
        assert_eq!(
            recipient_attestation,
            [
                first.as_str(),
                "device one.pem",
                "dec one.pem",
                second.as_str(),
                "device two.pem",
                "dec two.pem",
            ]
            .map(PathBuf::from)
        );
        args.pop();
        assert!(TestCli::try_parse_from(&args).is_err());
    }

    #[test]
    fn recipient_attestation_files_reject_case_insensitive_duplicate_fingerprints() {
        let dir = TempDir::new().unwrap();
        let device = dir.path().join("device.pem");
        let dec = dir.path().join("dec.pem");
        fs::write(&device, b"device evidence").unwrap();
        fs::write(&dec, b"DEC evidence").unwrap();
        let fingerprint = "a".repeat(40);
        let mut inputs = vec![PathBuf::from(&fingerprint), device.clone(), dec.clone()];
        inputs.extend([PathBuf::from(fingerprint.to_uppercase()), device, dec]);
        assert!(
            load_recipient_attestations(&inputs)
                .unwrap_err()
                .to_string()
                .contains("duplicate recipient attestation")
        );
    }
}
