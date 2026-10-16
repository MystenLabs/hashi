// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::Base64;
use base64ct::Encoding;
use fastcrypto::groups::GroupElement;
use fastcrypto::groups::Scalar;
use fastcrypto::groups::ristretto255::RistrettoPoint as EG;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::ecies_v1::PublicKey;
use fastcrypto_tbls::nodes::Node;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::Parameters;
use fastcrypto_tbls::threshold_schnorr::S;
use fastcrypto_tbls::threshold_schnorr::avss::Dealer;
use fastcrypto_tbls::threshold_schnorr::avss::DkOutput;
use fastcrypto_tbls::threshold_schnorr::avss::ProcessedMessage;
use fastcrypto_tbls::threshold_schnorr::avss::Receiver;
use hashi::backup::MPC_RECOVERY_FILE_NAME;
use hashi::backup::MpcRecoveryRecord;
use hashi::backup::RecoveredMpcKey;
use hashi::backup::build_backup_manifest;
use hashi::backup::encrypt_files_to_pgp_archive;
use hashi::backup::read_mpc_recovery_record;
use hashi::db::Database;
use hashi::mpc::types::MpcOutput;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::decrypt_with_secret_key;
use hashi_types::pgp::test_utils;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use sui_sdk_types::Address;
use tempfile::TempDir;

const CHAIN: &str = "offline-recovery-integration";
const EPOCH: u64 = 17;
const OFFLINE_RPC: &str = "http://127.0.0.1:0";

// This is a real encrypted AVSS exchange, not fabricated shares or public-key echoes.
// Dealers 0 and 1 supply weight three; receiver 0 owns two of five global shares.
fn dkg_records() -> (Vec<MpcRecoveryRecord>, S) {
    let mut rng = StdRng::seed_from_u64(0x5245434f564552);
    let keys: Vec<_> = (0..4).map(|_| PrivateKey::<EG>::new(&mut rng)).collect();
    let nodes = Nodes::new(
        keys.iter()
            .enumerate()
            .map(|(id, key)| Node {
                id: id as u16,
                pk: PublicKey::from_private_key(key),
                weight: [2, 1, 1, 1][id],
            })
            .collect(),
    )
    .unwrap();
    let params = Parameters { t: 3, f: 1 };
    let mut outputs: Vec<HashMap<_, _>> = (0..4).map(|_| HashMap::new()).collect();
    let mut root = S::zero();
    for dealer_id in 0..2u16 {
        let secret = S::rand(&mut rng);
        root += secret;
        let sid = format!("cli-recovery-dealer-{dealer_id}").into_bytes();
        let dealer =
            Dealer::new(Some(secret), nodes.clone(), params, sid.clone(), &mut rng).unwrap();
        let message = dealer.create_message(&mut rng);
        for (id, key) in keys.iter().enumerate() {
            let receiver = Receiver::new(
                nodes.clone(),
                id as u16,
                params,
                sid.clone(),
                None,
                key.clone(),
            )
            .unwrap();
            let ProcessedMessage::Valid(output) =
                receiver.process_message(&message, &mut rng).unwrap()
            else {
                panic!("honest AVSS dealing produced a complaint");
            };
            outputs[id].insert(dealer_id, output);
        }
    }
    let records = outputs
        .into_iter()
        .enumerate()
        .map(|(id, outputs)| {
            let output = DkOutput::complete_dkg(3, &nodes, outputs).unwrap();
            assert_eq!(output.vk, G::generator() * root);
            let output = MpcOutput {
                public_key: output.vk,
                key_shares: output.my_shares,
                commitments: output
                    .commitments
                    .into_iter()
                    .map(|eval| (eval.index, eval.value))
                    .collect(),
                threshold: 3,
            };
            MpcRecoveryRecord::from_output(
                CHAIN,
                Address::new([42; 32]),
                EPOCH,
                Address::new([id as u8; 32]),
                &output,
            )
            .unwrap()
        })
        .collect();
    (records, root)
}

struct Fixture {
    dir: TempDir,
    records: Vec<MpcRecoveryRecord>,
    encrypted: Vec<PathBuf>,
    plain: Vec<PathBuf>,
    raw: Vec<PathBuf>,
    public: PathBuf,
    secret: PathBuf,
    output_cert: PathBuf,
    output_secret: String,
    public_key: G,
    forbidden: Vec<Vec<u8>>,
    originals: Vec<(PathBuf, Vec<u8>)>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (records, root) = dkg_records();
        let public_key = G::generator() * root;
        let public = dir.path().join("trusted-public.bcs");
        fs::write(&public, bcs::to_bytes(&public_key).unwrap()).unwrap();
        fs::write(
            dir.path().join("cli.toml"),
            format!("sui_rpc_url = \"{OFFLINE_RPC}\"\n"),
        )
        .unwrap();
        let (cert, secret_key) = test_utils::mock_pgp_keypair();
        let secret = dir.path().join("operator-secret.asc");
        fs::write(&secret, &secret_key).unwrap();
        let recipient = PgpPublicCert::new(cert).unwrap();
        let (output_public, output_secret) = test_utils::mock_pgp_keypair();
        let output_cert = dir.path().join("output-recipient.asc");
        fs::write(&output_cert, output_public).unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let db = Database::open(db_dir.path()).unwrap();
        let mut manifest = build_backup_manifest(&[], db_dir.path()).unwrap();
        manifest.recovery = Some(MPC_RECOVERY_FILE_NAME.into());
        let mut encrypted = Vec::new();
        let mut plain = Vec::new();
        let mut raw = Vec::new();
        for (id, record) in records.iter().enumerate() {
            let archive = dir.path().join(format!("node-{id}.tar.asc"));
            encrypt_files_to_pgp_archive(&manifest, &db, &recipient, &archive, Some(record))
                .unwrap();
            let mut tar = Vec::new();
            decrypt_with_secret_key(fs::File::open(&archive).unwrap(), secret_key.as_bytes())
                .unwrap()
                .read_to_end(&mut tar)
                .unwrap();
            let extracted = read_mpc_recovery_record(Cursor::new(tar.clone())).unwrap();
            let tar_path = dir.path().join(format!("node-{id}.tar"));
            fs::write(&tar_path, tar).unwrap();
            let raw_path = dir.path().join(format!("node-{id}.bcs"));
            fs::write(&raw_path, bcs::to_bytes(&extracted).unwrap()).unwrap();
            encrypted.push(archive);
            plain.push(tar_path);
            raw.push(raw_path);
        }
        // Check common accidental logging representations without ever printing them on failure.
        let mut forbidden = Vec::new();
        for scalar in std::iter::once(root).chain(records.iter().flat_map(|record| {
            let MpcRecoveryRecord::V1(record) = record;
            record.key_shares.shares.iter().map(|share| share.value)
        })) {
            let bytes = bcs::to_bytes(&scalar).unwrap();
            forbidden.push(hex::encode(&bytes).into_bytes());
            forbidden.push(hex::encode_upper(&bytes).into_bytes());
            forbidden.push(Base64::encode_string(&bytes).into_bytes());
            forbidden.push(format!("{scalar:?}").into_bytes());
            forbidden.push(bytes);
        }
        let originals = encrypted
            .iter()
            .chain(&plain)
            .chain(&raw)
            .chain([&public, &secret, &output_cert])
            .map(|path| (path.clone(), fs::read(path).unwrap()))
            .collect();
        Self {
            dir,
            records,
            encrypted,
            plain,
            raw,
            public,
            secret,
            output_cert,
            output_secret,
            public_key,
            forbidden,
            originals,
        }
    }

    fn run(
        &self,
        inputs: &[PathBuf],
        output: &Path,
        public: &Path,
        backend: &[&std::ffi::OsStr],
    ) -> Output {
        self.run_with_recipient(
            inputs,
            output,
            public,
            backend,
            Some(self.output_cert.as_os_str()),
        )
    }

    fn run_with_recipient(
        &self,
        inputs: &[PathBuf],
        output: &Path,
        public: &Path,
        backend: &[&std::ffi::OsStr],
        recipient: Option<&std::ffi::OsStr>,
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hashi"));
        // No inherited credentials, CLI settings, GPG home, or logging configuration.
        command
            .env_clear()
            .env("HOME", self.dir.path())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default());
        command
            .current_dir(self.dir.path())
            .args(["backup", "recover-mpc-key", "--config"])
            .arg(self.dir.path().join("cli.toml"))
            .args(["--sui-rpc-url", OFFLINE_RPC, "--mpc-public-key"])
            .arg(public)
            .arg("--output")
            .arg(output)
            .args(backend)
            .args(inputs);
        if let Some(recipient) = recipient {
            command.arg("--output-pgp-cert").arg(recipient);
        }
        let result = command.output().unwrap();
        self.assert_safe(&result);
        result
    }

    fn export(
        &self,
        archive: &Path,
        output: &Path,
        backend: &[&std::ffi::OsStr],
        recipient: Option<&std::ffi::OsStr>,
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hashi"));
        command
            .env_clear()
            .env("HOME", self.dir.path())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .current_dir(self.dir.path())
            .args(["backup", "export-mpc-recovery-record", "--config"])
            .arg(self.dir.path().join("cli.toml"))
            .args(["--sui-rpc-url", OFFLINE_RPC, "--output"])
            .arg(output)
            .args(backend)
            .arg(archive);
        if let Some(recipient) = recipient {
            command.arg("--output-pgp-cert").arg(recipient);
        }
        let result = command.output().unwrap();
        self.assert_safe(&result);
        result
    }

    fn assert_safe(&self, result: &Output) {
        for stream in [&result.stdout, &result.stderr] {
            for secret in &self.forbidden {
                assert!(
                    !stream.windows(secret.len()).any(|window| window == secret),
                    "CLI exposed private scalar material"
                );
            }
        }
        for (path, original) in &self.originals {
            assert!(
                fs::read(path).unwrap() == *original,
                "CLI modified a recovery input"
            );
        }
    }

    fn local_backend(&self) -> [&std::ffi::OsStr; 2] {
        [
            std::ffi::OsStr::new("--backup-pgp-secret-key"),
            self.secret.as_os_str(),
        ]
    }

    fn succeeds(&self, inputs: &[PathBuf], backend: &[&std::ffi::OsStr]) {
        self.succeeds_with_recipient(
            inputs,
            backend,
            self.output_cert.as_os_str(),
            "root.bcs.asc",
        );
    }

    fn succeeds_with_recipient(
        &self,
        inputs: &[PathBuf],
        backend: &[&std::ffi::OsStr],
        recipient: &std::ffi::OsStr,
        filename: &str,
    ) {
        let output_dir = tempfile::tempdir_in(self.dir.path()).unwrap();
        let output = output_dir.path().join(filename);
        let result =
            self.run_with_recipient(inputs, &output, &self.public, backend, Some(recipient));
        assert!(
            result.status.success(),
            "recovery process failed: {}",
            result.status
        );
        let ciphertext = fs::read(&output).unwrap();
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        for secret in &self.forbidden {
            assert!(
                !ciphertext
                    .windows(secret.len())
                    .any(|window| window == secret),
                "recovered output exposed private scalar material"
            );
        }
        let mut plaintext = Vec::new();
        decrypt_with_secret_key(
            fs::File::open(&output).unwrap(),
            self.output_secret.as_bytes(),
        )
        .unwrap()
        .read_to_end(&mut plaintext)
        .unwrap();
        let input_secret = fs::read(&self.secret).unwrap();
        let wrong_key_result =
            decrypt_with_secret_key(fs::File::open(&output).unwrap(), &input_secret).and_then(
                |mut reader| {
                    let mut bytes = Vec::new();
                    reader.read_to_end(&mut bytes)?;
                    Ok(bytes)
                },
            );
        assert!(
            wrong_key_result.is_err(),
            "input backup key decrypted output encrypted to a distinct recipient"
        );
        let RecoveredMpcKey::V1(root) = bcs::from_bytes(&plaintext).unwrap();
        assert_eq!(root.chain_id, CHAIN);
        assert_eq!(root.hashi_object_id, Address::new([42; 32]));
        assert_eq!(root.epoch, EPOCH);
        assert_eq!(root.public_key, self.public_key);
        assert_eq!(G::generator() * root.private_key, self.public_key);
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            fs::read_dir(output_dir.path())
                .unwrap()
                .all(|entry| entry.unwrap().path() == output)
        );
    }

    fn rejects(&self, inputs: &[PathBuf], public: &Path, backend: &[&std::ffi::OsStr]) {
        let output_dir = tempfile::tempdir_in(self.dir.path()).unwrap();
        let result = self.run(
            inputs,
            &output_dir.path().join("root.bcs.asc"),
            public,
            backend,
        );
        assert!(
            !result.status.success(),
            "invalid recovery unexpectedly succeeded"
        );
        assert!(
            fs::read_dir(output_dir.path()).unwrap().next().is_none(),
            "failed recovery left output or staging files"
        );
    }
}

#[test]
fn recovers_weighted_quorum_from_encrypted_plain_raw_and_mixed_inputs() {
    let fixture = Fixture::new();
    fixture.succeeds(&fixture.encrypted[..2], &fixture.local_backend());
    fixture.succeeds(&fixture.plain[..2], &[]);
    fixture.succeeds(&fixture.raw[..2], &[]);
    fixture.succeeds(
        &[
            fixture.encrypted[0].clone(),
            fixture.plain[2].clone(),
            fixture.raw[3].clone(),
        ],
        &fixture.local_backend(),
    );
    fixture.succeeds(
        &fixture.encrypted.iter().rev().cloned().collect::<Vec<_>>(),
        &fixture.local_backend(),
    );
    fixture.succeeds(&fixture.raw, &[]);
    fixture.succeeds(
        &[
            fixture.encrypted[0].clone(),
            fixture.encrypted[1].clone(),
            fixture.encrypted[0].clone(),
        ],
        &fixture.local_backend(),
    );

    let mut record = fixture.records[0].clone();
    let MpcRecoveryRecord::V1(inner) = &mut record;
    inner
        .key_shares
        .shares
        .push(inner.key_shares.shares[0].clone());
    let path = fixture.dir.path().join("repeated-local-index.bcs");
    fs::write(&path, bcs::to_bytes(&record).unwrap()).unwrap();
    fixture.succeeds(&[path.clone(), fixture.raw[1].clone()], &[]);
    // Repeating local indices does not add weight toward the threshold.
    fixture.rejects(&[path], &fixture.public, &[]);
}

#[test]
fn requires_valid_output_recipient_and_accepts_inline_armor() {
    let fixture = Fixture::new();
    let armor = fs::read_to_string(&fixture.output_cert).unwrap();
    // A non-armored filename must still contain encrypted output. Passing armor
    // as a separate argument also exercises its leading hyphens.
    fixture.succeeds_with_recipient(
        &fixture.encrypted[..2],
        &fixture.local_backend(),
        armor.as_ref(),
        "root.bcs",
    );
    let invalid = fixture.dir.path().join("invalid-recipient.asc");
    fs::write(&invalid, b"not an OpenPGP certificate").unwrap();
    let secret_armor = fs::read_to_string(&fixture.secret).unwrap();
    for recipient in [
        None,
        Some(invalid.as_os_str()),
        Some(std::ffi::OsStr::new("not an OpenPGP certificate")),
        Some(fixture.secret.as_os_str()),
        Some(std::ffi::OsStr::new(&secret_armor)),
    ] {
        let output_dir = tempfile::tempdir_in(fixture.dir.path()).unwrap();
        let result = fixture.run_with_recipient(
            &fixture.encrypted[..2],
            &output_dir.path().join("root.bcs.asc"),
            &fixture.public,
            &fixture.local_backend(),
            recipient,
        );
        assert!(
            !result.status.success(),
            "invalid output recipient was accepted"
        );
        assert!(
            fs::read_dir(output_dir.path()).unwrap().next().is_none(),
            "invalid output recipient left output or staging files"
        );
    }
}

#[test]
fn rejects_invalid_quorums_and_validates_every_surplus_record() {
    let fixture = Fixture::new();
    fixture.rejects(&fixture.raw[..1], &fixture.public, &[]);
    fixture.rejects(
        &[fixture.encrypted[0].clone(), fixture.encrypted[0].clone()],
        &fixture.public,
        &fixture.local_backend(),
    );
    let wrong_public = fixture.dir.path().join("wrong-public.bcs");
    fs::write(
        &wrong_public,
        bcs::to_bytes(&(fixture.public_key + G::generator())).unwrap(),
    )
    .unwrap();
    fixture.rejects(&fixture.raw[..2], &wrong_public, &[]);
    for mutation in [
        "epoch",
        "deployment",
        "threshold",
        "commitment",
        "key",
        "share",
        "duplicate share",
    ] {
        let mut record = if mutation == "duplicate share" {
            fixture.records[0].clone()
        } else {
            fixture.records[3].clone()
        };
        let MpcRecoveryRecord::V1(inner) = &mut record;
        match mutation {
            "epoch" => inner.epoch += 1,
            "deployment" => inner.hashi_object_id = Address::new([43; 32]),
            "threshold" => inner.threshold += 1,
            // Alter another node's commitment so this record remains locally valid.
            "commitment" => {
                let own = inner.key_shares.shares[0].index;
                let (_, commitment) = inner
                    .commitments
                    .iter_mut()
                    .find(|(index, _)| **index != own)
                    .unwrap();
                *commitment += G::generator();
            }
            "key" => inner.public_key += G::generator(),
            "share" | "duplicate share" => inner.key_shares.shares[0].value += S::from(1u128),
            _ => unreachable!(),
        }
        let path = fixture.dir.path().join(format!("invalid-{mutation}.bcs"));
        fs::write(&path, bcs::to_bytes(&record).unwrap()).unwrap();
        // A complete good quorum comes first: surplus must not be silently ignored.
        fixture.rejects(
            &[fixture.raw[0].clone(), fixture.raw[1].clone(), path],
            &fixture.public,
            &[],
        );
    }
}

#[test]
fn rejects_damaged_archives_missing_records_and_decryption_failures() {
    let fixture = Fixture::new();
    let backend = fixture.local_backend();
    fixture.rejects(&fixture.encrypted[..2], &fixture.public, &[]);
    let (_, wrong_secret) = test_utils::mock_pgp_keypair();
    let wrong_key = fixture.dir.path().join("wrong-secret.asc");
    fs::write(&wrong_key, wrong_secret).unwrap();
    fixture.rejects(
        &fixture.encrypted[..2],
        &fixture.public,
        &["--backup-pgp-secret-key".as_ref(), wrong_key.as_os_str()],
    );
    let encrypted = fs::read(&fixture.encrypted[3]).unwrap();
    let tampered = tamper_authentication_trailer(&encrypted);
    let raw = fs::read(&fixture.raw[3]).unwrap();
    for (name, bytes) in [
        ("tampered.tar.asc", tampered),
        (
            "truncated.tar.asc",
            encrypted[..encrypted.len() / 2].to_vec(),
        ),
        ("truncated.bcs", raw[..raw.len() / 2].to_vec()),
    ] {
        let path = fixture.dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        fixture.rejects(
            &[fixture.raw[0].clone(), fixture.raw[1].clone(), path],
            &fixture.public,
            &backend,
        );
    }
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    let manifest = build_backup_manifest(&[], db_dir.path()).unwrap();
    let (cert, secret) = test_utils::mock_pgp_keypair();
    let empty = fixture.dir.path().join("no-record.tar.asc");
    encrypt_files_to_pgp_archive(
        &manifest,
        &db,
        &PgpPublicCert::new(cert).unwrap(),
        &empty,
        None,
    )
    .unwrap();
    let mut tar = Vec::new();
    decrypt_with_secret_key(fs::File::open(empty).unwrap(), secret.as_bytes())
        .unwrap()
        .read_to_end(&mut tar)
        .unwrap();
    let empty = fixture.dir.path().join("no-record.tar");
    fs::write(&empty, tar).unwrap();
    fixture.rejects(
        &[
            fixture.raw[0].clone(),
            fixture.raw[1].clone(),
            empty.clone(),
        ],
        &fixture.public,
        &[],
    );
    let output_dir = tempfile::tempdir_in(fixture.dir.path()).unwrap();
    assert!(
        !fixture
            .export(
                &empty,
                &output_dir.path().join("record.bcs.asc"),
                &[],
                Some(fixture.output_cert.as_os_str()),
            )
            .status
            .success()
    );
    assert!(fs::read_dir(output_dir.path()).unwrap().next().is_none());
}

#[test]
fn exports_distinct_operator_backups_for_coordinator_only_recovery() {
    let mut fixture = Fixture::new();
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    let mut manifest = build_backup_manifest(&[], db_dir.path()).unwrap();
    manifest.recovery = Some(MPC_RECOVERY_FILE_NAME.into());
    let coordinator_secret = fixture.dir.path().join("coordinator-secret.asc");
    fs::write(&coordinator_secret, &fixture.output_secret).unwrap();
    let coordinator_backend = [
        "--backup-pgp-secret-key".as_ref(),
        coordinator_secret.as_os_str(),
    ];
    let output_dir = tempfile::tempdir_in(fixture.dir.path()).unwrap();
    let mut exports = Vec::new();
    for id in 0..2 {
        let (cert, secret) = test_utils::mock_pgp_keypair();
        let archive = fixture.dir.path().join(format!("operator-{id}.tar.asc"));
        let key = fixture.dir.path().join(format!("operator-{id}-secret.asc"));
        fs::write(&key, secret).unwrap();
        encrypt_files_to_pgp_archive(
            &manifest,
            &db,
            &PgpPublicCert::new(cert).unwrap(),
            &archive,
            Some(&fixture.records[id]),
        )
        .unwrap();
        fixture
            .originals
            .push((archive.clone(), fs::read(&archive).unwrap()));
        fixture
            .originals
            .push((key.clone(), fs::read(&key).unwrap()));
        let output = output_dir.path().join(format!("operator-{id}.bcs.asc"));
        let backend = ["--backup-pgp-secret-key".as_ref(), key.as_os_str()];
        // Operators need their own key, not the coordinator's key, to export.
        for wrong_backend in [&coordinator_backend[..], &[][..]] {
            assert!(
                !fixture
                    .export(
                        &archive,
                        &output,
                        wrong_backend,
                        Some(fixture.output_cert.as_os_str()),
                    )
                    .status
                    .success()
            );
            assert!(!output.exists());
        }
        let armor = fs::read_to_string(&fixture.output_cert).unwrap();
        let recipient = if id == 0 {
            fixture.output_cert.as_os_str()
        } else {
            std::ffi::OsStr::new(&armor)
        };
        let result = fixture.export(&archive, &output, &backend, Some(recipient));
        assert!(result.status.success());
        let recipient_fingerprint = PgpPublicCert::new(armor).unwrap().fingerprint().to_hex();
        assert!(String::from_utf8_lossy(&result.stderr).contains(&recipient_fingerprint));
        let ciphertext = fs::read(&output).unwrap();
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        let mut plaintext = Vec::new();
        decrypt_with_secret_key(
            Cursor::new(ciphertext.clone()),
            fixture.output_secret.as_bytes(),
        )
        .unwrap()
        .read_to_end(&mut plaintext)
        .unwrap();
        assert!(plaintext == bcs::to_bytes(&fixture.records[id]).unwrap());
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fixture.originals.push((output.clone(), ciphertext));
        exports.push(output);
    }
    fixture.succeeds(&exports, &coordinator_backend);
    fixture.succeeds(
        &[exports[0].clone(), fixture.raw[1].clone()],
        &coordinator_backend,
    );
    fixture.rejects(&exports, &fixture.public, &fixture.local_backend());
    fixture.rejects(&exports, &fixture.public, &[]);
    assert_eq!(
        fs::read_dir(output_dir.path()).unwrap().count(),
        exports.len()
    );

    let failed_dir = tempfile::tempdir_in(fixture.dir.path()).unwrap();
    let output = failed_dir.path().join("record.bcs.asc");
    for recipient in [None, Some(std::ffi::OsStr::new("not a certificate"))] {
        assert!(
            !fixture
                .export(&fixture.plain[0], &output, &[], recipient)
                .status
                .success()
        );
    }
    assert!(fs::read_dir(failed_dir.path()).unwrap().next().is_none());
    assert!(
        fixture
            .export(
                &fixture.plain[0],
                &output,
                &[],
                Some(fixture.output_cert.as_os_str()),
            )
            .status
            .success()
    );
    fixture.succeeds(&[output, exports[1].clone()], &coordinator_backend);

    let ciphertext = fs::read(&exports[0]).unwrap();
    for (name, bytes) in [
        (
            "tampered.bcs.asc",
            tamper_authentication_trailer(&ciphertext),
        ),
        (
            "truncated.bcs.asc",
            ciphertext[..ciphertext.len() / 2].to_vec(),
        ),
    ] {
        let path = fixture.dir.path().join(name);
        fs::write(&path, bytes).unwrap();
        // Authenticate surplus records even after a complete good quorum.
        fixture.rejects(
            &[exports[0].clone(), exports[1].clone(), path],
            &fixture.public,
            &coordinator_backend,
        );
    }
    let mut invalid_record = fixture.records[0].clone();
    let MpcRecoveryRecord::V1(inner) = &mut invalid_record;
    inner.key_shares.shares[0].value += S::from(1u128);
    let recipient = PgpPublicCert::new(fs::read_to_string(&fixture.output_cert).unwrap()).unwrap();
    for (name, bytes) in [
        (
            "invalid-share.bcs.asc",
            bcs::to_bytes(&invalid_record).unwrap(),
        ),
        ("invalid-bcs.bcs.asc", vec![255]),
    ] {
        let path = fixture.dir.path().join(name);
        let mut writer =
            hashi_types::pgp::armored_encrypt_writer(fs::File::create(&path).unwrap(), &recipient)
                .unwrap();
        std::io::Write::write_all(&mut writer, &bytes).unwrap();
        writer.finalize().unwrap();
        fixture.rejects(
            &[exports[0].clone(), exports[1].clone(), path],
            &fixture.public,
            &coordinator_backend,
        );
    }
    let damaged = fixture.dir.path().join("export-tampered.tar.asc");
    fs::write(
        &damaged,
        tamper_authentication_trailer(&fs::read(&fixture.encrypted[0]).unwrap()),
    )
    .unwrap();
    let failed_dir = tempfile::tempdir_in(fixture.dir.path()).unwrap();
    assert!(
        !fixture
            .export(
                &damaged,
                &failed_dir.path().join("record.bcs.asc"),
                &fixture.local_backend(),
                Some(fixture.output_cert.as_os_str()),
            )
            .status
            .success()
    );
    assert!(fs::read_dir(failed_dir.path()).unwrap().next().is_none());
}

fn tamper_authentication_trailer(encrypted: &[u8]) -> Vec<u8> {
    // Preserve valid armor but corrupt the authentication trailer. Omit the
    // optional CRC so rejection cannot be merely an armor checksum failure.
    let armor = std::str::from_utf8(encrypted).unwrap();
    let payload: String = armor
        .lines()
        .skip_while(|line| !line.is_empty())
        .skip(1)
        .take_while(|line| !line.starts_with('=') && !line.starts_with("-----"))
        .collect();
    let mut packet = Base64::decode_vec(&payload).unwrap();
    *packet.last_mut().unwrap() ^= 1;
    let encoded = Base64::encode_string(&packet);
    let mut tampered = b"-----BEGIN PGP MESSAGE-----\n\n".to_vec();
    for line in encoded.as_bytes().chunks(64) {
        tampered.extend_from_slice(line);
        tampered.push(b'\n');
    }
    tampered.extend_from_slice(b"-----END PGP MESSAGE-----\n");
    tampered
}

#[test]
fn refuses_existing_outputs_and_symlinks_without_modifying_inputs() {
    let fixture = Fixture::new();
    let dir = tempfile::tempdir_in(fixture.dir.path()).unwrap();
    let output = dir.path().join("existing.bcs");
    fs::write(&output, b"do not overwrite").unwrap();
    assert!(
        !fixture
            .run(&fixture.raw[..2], &output, &fixture.public, &[])
            .status
            .success()
    );
    assert!(
        !fixture
            .export(
                &fixture.encrypted[0],
                &output,
                &fixture.local_backend(),
                Some(fixture.output_cert.as_os_str()),
            )
            .status
            .success()
    );
    assert_eq!(fs::read(&output).unwrap(), b"do not overwrite");
    let target = dir.path().join("absent.bcs");
    let link = dir.path().join("dangling.bcs");
    symlink(&target, &link).unwrap();
    assert!(
        !fixture
            .run(&fixture.raw[..2], &link, &fixture.public, &[])
            .status
            .success()
    );
    assert!(
        !fixture
            .export(
                &fixture.plain[0],
                &link,
                &[],
                Some(fixture.output_cert.as_os_str()),
            )
            .status
            .success()
    );
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!target.exists());
    let existing_link = dir.path().join("existing-link.bcs");
    symlink(&output, &existing_link).unwrap();
    assert!(
        !fixture
            .run(&fixture.raw[..2], &existing_link, &fixture.public, &[])
            .status
            .success()
    );
    assert_eq!(fs::read(&output).unwrap(), b"do not overwrite");
    assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
        let path = entry.unwrap().path();
        path == output || path == link || path == existing_link
    }));
}

// Keep the agent alive only for this test; cleanup also runs during panic unwinding.
struct GpgHome(TempDir);
impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", self.0.path())
            .args(["--kill", "gpg-agent"])
            .output();
    }
}

#[test]
fn recovers_distinct_recipients_through_an_isolated_gpg_agent() {
    let mut fixture = Fixture::new();
    let home = GpgHome(tempfile::tempdir().unwrap());
    test_utils::prepare_gnupg_home(home.0.path());
    let db_dir = tempfile::tempdir().unwrap();
    let db = Database::open(db_dir.path()).unwrap();
    let mut manifest = build_backup_manifest(&[], db_dir.path()).unwrap();
    manifest.recovery = Some(MPC_RECOVERY_FILE_NAME.into());
    let mut archives = Vec::new();
    for (id, record) in fixture.records.iter().enumerate() {
        let (cert, secret) = test_utils::mock_pgp_keypair();
        test_utils::gpg_import_secret_key(home.0.path(), &secret);
        let path = fixture.dir.path().join(format!("distinct-{id}.tar.asc"));
        encrypt_files_to_pgp_archive(
            &manifest,
            &db,
            &PgpPublicCert::new(cert).unwrap(),
            &path,
            Some(record),
        )
        .unwrap();
        fixture
            .originals
            .push((path.clone(), fs::read(&path).unwrap()));
        archives.push(path);
    }
    let backend = [
        "--use-gpg-agent".as_ref(),
        "--gpg-homedir".as_ref(),
        home.0.path().as_os_str(),
    ];
    fixture.succeeds(&archives[..2], &backend);
    let exports_dir = tempfile::tempdir_in(fixture.dir.path()).unwrap();
    let mut exports = Vec::new();
    for (id, archive) in archives[..2].iter().enumerate() {
        let output = exports_dir.path().join(format!("agent-{id}.bcs.asc"));
        assert!(
            fixture
                .export(
                    archive,
                    &output,
                    &backend,
                    Some(fixture.output_cert.as_os_str())
                )
                .status
                .success()
        );
        exports.push(output);
    }
    let coordinator_home = GpgHome(tempfile::tempdir().unwrap());
    test_utils::prepare_gnupg_home(coordinator_home.0.path());
    test_utils::gpg_import_secret_key(coordinator_home.0.path(), &fixture.output_secret);
    fixture.succeeds(
        &exports,
        &[
            "--use-gpg-agent".as_ref(),
            "--gpg-homedir".as_ref(),
            coordinator_home.0.path().as_os_str(),
        ],
    );
    archives.reverse();
    fixture.succeeds(&archives, &backend);
    fixture.rejects(&archives, &fixture.public, &fixture.local_backend());
}
