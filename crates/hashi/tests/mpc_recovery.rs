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
            .chain([&public, &secret])
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_hashi"));
        // No inherited credentials, CLI settings, GPG home, or logging configuration.
        command
            .env_clear()
            .env("HOME", self.dir.path())
            .env("PATH", std::env::var_os("PATH").unwrap_or_default());
        let result = command
            .current_dir(self.dir.path())
            .args(["backup", "recover-mpc-key", "--config"])
            .arg(self.dir.path().join("cli.toml"))
            .args(["--sui-rpc-url", OFFLINE_RPC, "--mpc-public-key"])
            .arg(public)
            .arg("--output")
            .arg(output)
            .args(backend)
            .args(inputs)
            .output()
            .unwrap();
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
        result
    }

    fn local_backend(&self) -> [&std::ffi::OsStr; 2] {
        [
            std::ffi::OsStr::new("--backup-pgp-secret-key"),
            self.secret.as_os_str(),
        ]
    }

    fn succeeds(&self, inputs: &[PathBuf], backend: &[&std::ffi::OsStr]) {
        let output_dir = tempfile::tempdir_in(self.dir.path()).unwrap();
        let output = output_dir.path().join("root.bcs");
        let result = self.run(inputs, &output, &self.public, backend);
        assert!(
            result.status.success(),
            "recovery process failed: {}",
            result.status
        );
        let RecoveredMpcKey::V1(root) = bcs::from_bytes(&fs::read(&output).unwrap()).unwrap();
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
        let result = self.run(inputs, &output_dir.path().join("root.bcs"), public, backend);
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
    // Preserve valid armor but corrupt the encrypted packet's authentication trailer.
    // Omitting the optional armor CRC ensures rejection is not merely a CRC failure.
    let armor = std::str::from_utf8(&encrypted).unwrap();
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
        &[fixture.raw[0].clone(), fixture.raw[1].clone(), empty],
        &fixture.public,
        &[],
    );
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
    archives.reverse();
    fixture.succeeds(&archives, &backend);
    fixture.rejects(&archives, &fixture.public, &fixture.local_backend());
}
