// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use fastcrypto_tbls::nodes::Node;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::threshold_schnorr::Parameters;
use fastcrypto_tbls::threshold_schnorr::avss;
use hashi::backup::BACKUP_MANIFEST_FILE_NAME;
use hashi::backup::DB_SNAPSHOT_TAR_PREFIX;
use hashi::backup::extract_dir_name;
use hashi::config::Config;
use hashi::db::Database;
use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::EncryptionPrivateKey;
use hashi_types::pgp::PgpPublicCert;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::types::KeyFlags;
use sui_sdk_types::Address;
use tempfile::TempDir;

// These are deliberately real subprocess tests: gpg and gpgconf are prerequisites,
// not optional coverage. Each agent is killed before its private home is removed,
// including when an assertion unwinds.
struct GpgHome(TempDir);

impl GpgHome {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        Self(home)
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command.env("GNUPGHOME", self.0.path());
        command.env_remove("GPG_AGENT_INFO");
        command.env("LC_ALL", "C");
        command
    }

    fn cli(&self) -> Command {
        let mut command = self.command(env!("CARGO_BIN_EXE_hashi"));
        command.env("HOME", self.0.path());
        command.env("XDG_CONFIG_HOME", self.0.path());
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("HASHI_") {
                command.env_remove(name);
            }
        }
        for name in [
            "SUI_RPC_URL",
            "BTC_RPC_URL",
            "BTC_RPC_USER",
            "BTC_RPC_PASSWORD",
            "BTC_NETWORK",
            "BTC_PRIVATE_KEY",
            "BTC_RPC_NETWORK",
            "BTC_RPC_PRIVATE_KEY",
        ] {
            command.env_remove(name);
        }
        command
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        // Never panic during unwinding, but do not silently hide cleanup failures.
        match self
            .command("gpgconf")
            .args(["--kill", "gpg-agent"])
            .output()
        {
            Ok(output) if output.status.success() => {}
            result => eprintln!("failed to stop isolated test gpg-agent: {result:?}"),
        }
    }
}

fn run(command: &mut Command) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("could not execute {command:?}: {error}"))
}

fn success(command: &mut Command) -> Output {
    let output = run(command);
    assert!(
        output.status.success(),
        "{command:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn failure(command: &mut Command, expected: &str) {
    let output = run(command);
    assert!(!output.status.success(), "unexpected success: {command:?}");
    let diagnostics = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        diagnostics.contains(expected),
        "expected {expected:?}: {diagnostics}"
    );
}

struct Identity {
    cert: Cert,
    public_path: PathBuf,
    secret: Vec<u8>,
}

impl Identity {
    fn new(root: &Path, name: &str, subkeys: usize) -> Self {
        let mut builder = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
            .add_userid(name);
        for _ in 0..subkeys {
            builder = builder.add_transport_encryption_subkey();
        }
        let cert = builder.generate().unwrap().0;
        let mut secret = Vec::new();
        // Export only the last encryption secret subkey. The multi-subkey public
        // input remains ambiguous, and restore can succeed only if assembly
        // actually chose its explicitly requested second subkey.
        let selected = cert
            .keys()
            .subkeys()
            .last()
            .map(|key| key.key().fingerprint());
        cert.clone()
            .retain_subkeys(|key| Some(key.key().fingerprint()) == selected)
            .as_tsk()
            .armored()
            .serialize(&mut secret)
            .unwrap();
        let cert = cert.strip_secret_key_material();
        let public_path = root.join(format!("{name}-public.asc"));
        cert.armored()
            .serialize(&mut fs::File::create(&public_path).unwrap())
            .unwrap();
        Self {
            cert,
            public_path,
            secret,
        }
    }

    fn fingerprint(&self, index: usize) -> String {
        self.cert
            .keys()
            .subkeys()
            .nth(index)
            .unwrap()
            .key()
            .fingerprint()
            .to_hex()
    }

    fn selected(&self, index: usize) -> String {
        format!("{}={}", self.public_path.display(), self.fingerprint(index))
    }
}

struct AssemblyFixture {
    root: TempDir,
    home: GpgHome,
    primary: Identity,
    recipients: Vec<Identity>,
    unrelated: Identity,
}

impl AssemblyFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = GpgHome::new();
        let primary = Identity::new(root.path(), "certifier", 0);
        let primary_secret = root.path().join("certifier-secret.asc");
        fs::write(&primary_secret, &primary.secret).unwrap();
        success(
            home.command("gpg")
                .args(["--batch", "--import"])
                .arg(&primary_secret),
        );
        fs::remove_file(primary_secret).unwrap();
        let recipients = (0..3)
            .map(|i| {
                Identity::new(
                    root.path(),
                    &format!("recipient-{i}"),
                    if i == 1 { 2 } else { 1 },
                )
            })
            .collect();
        let unrelated = Identity::new(root.path(), "unrelated", 1);
        Self {
            root,
            home,
            primary,
            recipients,
            unrelated,
        }
    }

    fn assemble(&self, output: &Path) -> Command {
        let mut command = self.home.cli();
        command
            .args(["backup", "assemble-cert", "--primary-cert"])
            .arg(&self.primary.public_path)
            .arg("--gpg-homedir")
            .arg(self.home.0.path())
            .arg("--output")
            .arg(output);
        command
    }
}

#[test]
fn same_cli_archive_restores_with_each_independent_recipient() {
    let fixture = AssemblyFixture::new();
    let certificate_path = fixture.root.path().join("assembled.asc");
    success(
        fixture
            .assemble(&certificate_path)
            .arg("--recipient")
            .arg(&fixture.recipients[0].public_path)
            .arg("--recipient")
            .arg(fixture.recipients[1].selected(1))
            .arg("--recipient")
            .arg(fixture.recipients[2].selected(0)),
    );
    let certificate = fs::read_to_string(&certificate_path).unwrap();
    let assembled = Cert::from_bytes(certificate.as_bytes()).unwrap();
    assert!(!assembled.is_tsk());
    assert_eq!(assembled.fingerprint(), fixture.primary.cert.fingerprint());
    assert_eq!(
        assembled
            .keys()
            .subkeys()
            .map(|k| k.key().fingerprint().to_hex())
            .collect::<BTreeSet<_>>(),
        [
            fixture.recipients[0].fingerprint(0),
            fixture.recipients[1].fingerprint(1),
            fixture.recipients[2].fingerprint(0)
        ]
        .into_iter()
        .collect()
    );

    let source = tempfile::tempdir().unwrap();
    let config_path = source.path().join("node-config.toml");
    let db_path = source.path().join("db");
    let archives = tempfile::tempdir().unwrap();
    let mut config = Config::new_for_testing();
    let tls_bytes = config.tls_private_key.take().unwrap().into_bytes();
    let operator_bytes = b"operator-key-file-preserved-verbatim";
    let tls_path = source.path().join("tls.pem");
    let operator_path = source.path().join("operator.key");
    fs::write(&tls_path, &tls_bytes).unwrap();
    fs::write(&operator_path, operator_bytes).unwrap();
    config.tls_private_key = Some(tls_path.to_str().unwrap().to_owned());
    config.operator_private_key = Some(operator_path.to_str().unwrap().to_owned());
    config.db = Some(db_path.clone());
    config.backup_dir = archives.path().to_owned();
    config.backup_pgp_cert = PgpPublicCert::new(certificate).unwrap();
    config.save(&config_path).unwrap();
    let config_bytes = fs::read(&config_path).unwrap();

    let mut rng = rand::thread_rng();
    // Two distinct epochs/keys make swapped or collapsed epoch indexes observable.
    let keys: Vec<_> = [7, 42]
        .into_iter()
        .map(|epoch| {
            (
                epoch,
                EncryptionPrivateKey::new(&mut rng),
                Bls12381PrivateKey::generate(&mut rng),
            )
        })
        .collect();
    let nodes = Nodes::new(
        (0..5)
            .map(|id| Node {
                id,
                pk: EncryptionPrivateKey::new(&mut rng).public_key(),
                weight: 1,
            })
            .collect(),
    )
    .unwrap();
    let dealer_message = avss::Dealer::new(
        None,
        nodes,
        Parameters { t: 3, f: 1 },
        b"backup-cli-e2e".to_vec(),
        &mut rng,
    )
    .unwrap()
    .create_message(&mut rng);
    let mut rotations = BTreeMap::new();
    rotations.insert(NonZeroU16::new(1).unwrap(), dealer_message.clone());
    let dealer = Address::new([3; 32]);
    {
        let db = Database::open(&db_path).unwrap();
        for (epoch, encryption, signing) in &keys {
            db.store_encryption_key(*epoch, encryption).unwrap();
            db.store_signing_key(*epoch, signing).unwrap();
        }
        db.store_dealer_message(42, &dealer, &dealer_message)
            .unwrap();
        db.store_rotation_messages(43, &dealer, &rotations).unwrap();
    }
    // Exactly one save; all recipients below consume this same immutable archive.
    success(
        fixture
            .home
            .cli()
            .args(["backup", "save"])
            .arg(&config_path)
            .arg("--output-dir")
            .arg(archives.path())
            .arg("--local-only"),
    );
    let archive_paths: Vec<_> = fs::read_dir(archives.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(archive_paths.len(), 1);
    let archive = &archive_paths[0];
    let archive_bytes = fs::read(archive).unwrap();
    // Nothing in the original config, referenced files, or database can satisfy
    // a restore assertion (or be accidentally used by a restore subprocess).
    source.close().unwrap();
    assert!(!db_path.exists());

    for recipient in &fixture.recipients {
        let home = GpgHome::new();
        let secret = home.0.path().join("only-recipient-secret.asc");
        fs::write(&secret, &recipient.secret).unwrap();
        let output = tempfile::tempdir().unwrap();
        success(
            home.cli()
                .args(["backup", "restore"])
                .arg(archive)
                .arg("--backup-pgp-secret-key")
                .arg(&secret)
                .arg("--output-dir")
                .arg(output.path()),
        );
        let extracted = output.path().join(extract_dir_name(archive).unwrap());
        assert_eq!(
            fs::read(extracted.join("node-config.toml")).unwrap(),
            config_bytes
        );
        assert_eq!(fs::read(extracted.join("tls.pem")).unwrap(), tls_bytes);
        assert_eq!(
            fs::read(extracted.join("operator.key")).unwrap(),
            operator_bytes
        );
        assert!(extracted.join(BACKUP_MANIFEST_FILE_NAME).is_file());
        let db = Database::open(&extracted.join(DB_SNAPSHOT_TAR_PREFIX)).unwrap();
        for (epoch, encryption, signing) in &keys {
            assert_eq!(
                db.get_encryption_key(*epoch).unwrap().as_ref(),
                Some(encryption)
            );
            assert_eq!(
                bcs::to_bytes(&db.get_signing_key(*epoch).unwrap().unwrap()).unwrap(),
                bcs::to_bytes(signing).unwrap()
            );
        }
        assert_eq!(db.latest_encryption_key_epoch().unwrap(), Some(42));
        assert_eq!(db.latest_signing_key_epoch().unwrap(), Some(42));
        assert!(db.get_encryption_key(41).unwrap().is_none());
        assert!(db.get_signing_key(41).unwrap().is_none());
        assert_eq!(
            db.get_dealer_message(42, &dealer).unwrap(),
            Some(bcs::to_bytes(&dealer_message).unwrap())
        );
        assert_eq!(
            db.get_rotation_messages(43, &dealer).unwrap(),
            Some(bcs::to_bytes(&rotations).unwrap())
        );
        assert_eq!(fs::read(archive).unwrap(), archive_bytes);
    }

    let home = GpgHome::new();
    let secret = home.0.path().join("unrelated-secret.asc");
    fs::write(&secret, &fixture.unrelated.secret).unwrap();
    let output = tempfile::tempdir().unwrap();
    let result = run(home
        .cli()
        .args(["backup", "restore"])
        .arg(archive)
        .arg("--backup-pgp-secret-key")
        .arg(secret)
        .arg("--output-dir")
        .arg(output.path()));
    assert!(
        !result.status.success(),
        "unrelated key decrypted the archive"
    );
    assert!(
        !output
            .path()
            .join(extract_dir_name(archive).unwrap())
            .exists()
    );
    assert_eq!(
        fs::read_dir(output.path()).unwrap().count(),
        0,
        "failed restore left staging files"
    );
}

#[test]
fn cli_assembly_rejects_invalid_inputs_without_publishing_or_clobbering() {
    let fixture = AssemblyFixture::new();
    let recipient = &fixture.recipients[0];
    let evidence = fixture.root.path().join("invalid-attestation.pem");
    fs::write(&evidence, "not an attestation certificate").unwrap();
    for (case, expected) in [
        ("required", "recipient DEC attestation is required"),
        ("invalid-optional", "recipient DEC attestation is invalid"),
        (
            "unselected",
            "attestation supplied for an unselected encryption key",
        ),
        (
            "wrong-selector",
            "recipient has no matching usable encryption subkey",
        ),
        ("ambiguous", "recipient has ambiguous encryption subkeys"),
    ] {
        let output = fixture.root.path().join(format!("{case}.asc"));
        let mut command = fixture.assemble(&output);
        command.arg("--recipient");
        match case {
            "wrong-selector" => {
                command.arg(format!(
                    "{}={}",
                    recipient.public_path.display(),
                    fixture.unrelated.fingerprint(0)
                ));
            }
            "ambiguous" => {
                command.arg(&fixture.recipients[1].public_path);
            }
            _ => {
                command.arg(&recipient.public_path);
            }
        }
        match case {
            "required" => {
                command.arg("--require-recipient-attestation");
            }
            "invalid-optional" | "unselected" => {
                command
                    .arg("--recipient-attestation")
                    .arg(if case == "unselected" {
                        fixture.unrelated.fingerprint(0)
                    } else {
                        recipient.fingerprint(0)
                    })
                    .arg(&evidence)
                    .arg(&evidence);
            }
            _ => {}
        }
        failure(&mut command, expected);
        assert!(
            !output.exists(),
            "failed {case} assembly published a certificate"
        );
    }
    let output = fixture.root.path().join("existing.asc");
    let sentinel = b"existing output must survive";
    fs::write(&output, sentinel).unwrap();
    failure(
        fixture
            .assemble(&output)
            .arg("--recipient")
            .arg(&recipient.public_path),
        "output must not exist",
    );
    assert_eq!(fs::read(output).unwrap(), sentinel);
}
