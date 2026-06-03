// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use sequoia_openpgp as openpgp;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::stream::DecryptionHelper;
use sequoia_openpgp::parse::stream::DecryptorBuilder;
use sequoia_openpgp::parse::stream::MessageStructure;
use sequoia_openpgp::parse::stream::VerificationHelper;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::stream::Compressor;
use sequoia_openpgp::serialize::stream::Encryptor;
use sequoia_openpgp::serialize::stream::LiteralWriter;
use sequoia_openpgp::serialize::stream::Message;
use sequoia_openpgp::types::SymmetricAlgorithm;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::cmp::Ordering;
use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::Child;
use std::process::ChildStdout;
use std::process::Command;
use std::process::Stdio;
use std::sync::LazyLock;

static POLICY: LazyLock<StandardPolicy> = LazyLock::new(StandardPolicy::new);

#[derive(Debug, Clone)]
pub struct PgpPublicCert {
    armored: String,
    cert: openpgp::Cert,
}

impl PgpPublicCert {
    pub fn new(armored: String) -> Result<Self> {
        let cert =
            openpgp::Cert::from_bytes(armored.as_bytes()).context("invalid OpenPGP certificate")?;
        validate_pgp_cert(&cert)?;
        Ok(Self { armored, cert })
    }

    pub fn armored(&self) -> &str {
        &self.armored
    }
}

impl fmt::Display for PgpPublicCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cert.fingerprint())
    }
}

// `armored` fully determines `cert`, so all comparisons key off it alone.
// (`Cert` is only `PartialEq`, so `Eq`/`Ord` can't be derived anyway.)
impl PartialEq for PgpPublicCert {
    fn eq(&self, other: &Self) -> bool {
        self.armored == other.armored
    }
}

impl Eq for PgpPublicCert {}

impl Ord for PgpPublicCert {
    fn cmp(&self, other: &Self) -> Ordering {
        self.armored.cmp(&other.armored)
    }
}

impl PartialOrd for PgpPublicCert {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for PgpPublicCert {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.armored())
    }
}

impl<'de> Deserialize<'de> for PgpPublicCert {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let armored = String::deserialize(deserializer)?;
        Self::new(armored).map_err(serde::de::Error::custom)
    }
}

fn validate_pgp_cert(cert: &openpgp::Cert) -> Result<()> {
    if cert.keys().secret().next().is_some() {
        anyhow::bail!("OpenPGP backup certificate must not contain secret key material")
    }

    cert.keys()
        .with_policy(&*POLICY, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .next()
        .ok_or_else(|| anyhow::anyhow!("OpenPGP certificate has no usable encryption key"))?;
    Ok(())
}

pub fn encrypt_armored(plaintext: &[u8], cert: &PgpPublicCert) -> Result<String> {
    let mut ciphertext = Vec::new();
    let mut writer = armored_encrypt_writer(&mut ciphertext, cert)?;
    writer
        .write_all(plaintext)
        .context("OpenPGP encryption failed")?;
    writer
        .finalize()
        .context("OpenPGP encryption finalization failed")?;
    String::from_utf8(ciphertext).context("OpenPGP ASCII armor was not valid UTF-8")
}

pub fn armored_encrypt_writer<'a, W>(output: W, cert: &'a PgpPublicCert) -> Result<Message<'a>>
where
    W: 'a + Write + Send + Sync,
{
    let recipients = cert
        .cert
        .keys()
        .with_policy(&*POLICY, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();
    let message = Message::new(output);
    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Message)
        .build()
        .context("OpenPGP armor setup failed")?;
    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .context("OpenPGP encryption setup failed")?;
    // Compress inside the encryption layer so the archive is stored as a
    // single OpenPGP message; the decryptor inflates this transparently.
    let message = Compressor::new(message)
        .build()
        .context("OpenPGP compression setup failed")?;
    LiteralWriter::new(message)
        .build()
        .context("OpenPGP literal data setup failed")
}

pub fn decrypt_with_secret_key<R>(input: R, secret_key: &[u8]) -> Result<impl io::Read + use<R>>
where
    R: Read + Send + Sync + 'static,
{
    let cert = openpgp::Cert::from_bytes(secret_key).context("invalid OpenPGP secret key")?;
    ensure_usable_unencrypted_secret_key(&cert)?;
    let helper = LocalSecretKeyDecryptHelper { cert };
    DecryptorBuilder::from_reader(input)
        .context("invalid OpenPGP message")?
        .with_policy(&*POLICY, None, helper)
        .context("OpenPGP decryption failed")
}

/// Decrypt `backup` by shelling out to `gpg --decrypt`, returning a reader that
/// streams the plaintext.
///
/// The spawned `gpg` process is owned by the returned reader: reaching EOF waits
/// for `gpg` and turns a non-zero exit into an `io::Error`, and dropping the
/// reader early kills and reaps `gpg` so it can never be orphaned or deadlock on
/// a full pipe. Callers only deal with `io::Read`.
pub fn decrypt_with_gpg(backup: &Path, homedir: Option<&Path>) -> Result<impl io::Read + use<>> {
    let mut command = Command::new("gpg");
    command.arg("--decrypt").arg("--").arg(backup);
    if let Some(homedir) = homedir {
        command.env("GNUPGHOME", homedir);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .with_context(|| "Failed to run `gpg --decrypt`; is gpg installed and on PATH?")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to capture gpg stdout"))?;
    Ok(GpgDecryptReader {
        child,
        stdout,
        finished: false,
    })
}

struct GpgDecryptReader {
    child: Child,
    stdout: ChildStdout,
    finished: bool,
}

impl io::Read for GpgDecryptReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.stdout.read(buf)?;
        if n == 0 && !self.finished {
            self.finished = true;
            let status = self.child.wait()?;
            if !status.success() {
                return Err(io::Error::other(format!("gpg failed to decrypt: {status}")));
            }
        }
        Ok(n)
    }
}

impl Drop for GpgDecryptReader {
    fn drop(&mut self) {
        if !self.finished {
            // The consumer stopped early (e.g. a tar/gzip parse error on
            // truncated output). Kill and reap gpg so it cannot linger writing
            // into a pipe nobody is reading.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn ensure_usable_unencrypted_secret_key(cert: &openpgp::Cert) -> Result<()> {
    let mut has_transport_secret_key = false;
    let mut has_unencrypted_transport_secret_key = false;

    for key in cert
        .keys()
        .secret()
        .with_policy(&*POLICY, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
    {
        has_transport_secret_key = true;
        if key.key().has_unencrypted_secret() {
            has_unencrypted_transport_secret_key = true;
            break;
        }
    }

    if has_unencrypted_transport_secret_key {
        Ok(())
    } else if has_transport_secret_key {
        anyhow::bail!(
            "OpenPGP secret key has no unencrypted transport encryption key. Passphrase-protected secret keys are not supported with --backup-pgp-secret-key; use --use-gpg-agent instead."
        )
    } else {
        anyhow::bail!("OpenPGP secret key has no usable transport encryption key")
    }
}

struct LocalSecretKeyDecryptHelper {
    cert: openpgp::Cert,
}

impl VerificationHelper for LocalSecretKeyDecryptHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for LocalSecretKeyDecryptHelper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        for key in self
            .cert
            .keys()
            .secret()
            .with_policy(&*POLICY, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            let key = key.key().clone();
            if !key.has_unencrypted_secret() {
                continue;
            }
            let mut keypair = key.into_keypair()?;
            for pkesk in pkesks {
                if pkesk
                    .decrypt(&mut keypair, sym_algo)
                    .is_some_and(|(algo, session_key)| decrypt(algo, &session_key))
                {
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }
}

pub mod test_utils {
    use super::PgpPublicCert;
    use sequoia_openpgp as openpgp;
    use sequoia_openpgp::cert::prelude::CertBuilder;
    use sequoia_openpgp::serialize::Serialize;
    use sequoia_openpgp::types::Features;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;
    use std::process::Output;

    pub fn assert_command_success(output: &Output, command: &str) {
        assert!(
            output.status.success(),
            "{command} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    pub fn prepare_gnupg_home(homedir: &Path) {
        fs::set_permissions(homedir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    pub fn gpg_import_secret_key(homedir: &Path, secret_key: &str) {
        let secret_key_path = homedir.join("backup-secret-key.asc");
        fs::write(&secret_key_path, secret_key).unwrap();
        let output = Command::new("gpg")
            .env("GNUPGHOME", homedir)
            .arg("--batch")
            .arg("--import")
            .arg(&secret_key_path)
            .output()
            .unwrap();
        assert_command_success(&output, "gpg --import");
    }

    pub fn gpg_import_key(homedir: &Path, key_path: &Path) {
        let output = Command::new("gpg")
            .env("GNUPGHOME", homedir)
            .arg("--batch")
            .arg("--import")
            .arg(key_path)
            .output()
            .unwrap();
        assert_command_success(&output, "gpg --import");
    }

    pub fn gpg_generate_keypair(homedir: &Path) -> (String, String) {
        let output = Command::new("gpg")
            .env("GNUPGHOME", homedir)
            .arg("--batch")
            .arg("--passphrase")
            .arg("")
            .arg("--quick-generate-key")
            .arg("Hashi Backup <backup@example.com>")
            .arg("rsa2048")
            .arg("encrypt")
            .arg("0")
            .output()
            .unwrap();
        assert_command_success(&output, "gpg --quick-generate-key");

        let public = Command::new("gpg")
            .env("GNUPGHOME", homedir)
            .arg("--armor")
            .arg("--export")
            .arg("backup@example.com")
            .output()
            .unwrap();
        assert_command_success(&public, "gpg --export");

        let secret = Command::new("gpg")
            .env("GNUPGHOME", homedir)
            .arg("--armor")
            .arg("--export-secret-keys")
            .arg("backup@example.com")
            .output()
            .unwrap();
        assert_command_success(&secret, "gpg --export-secret-keys");

        (
            String::from_utf8(public.stdout).unwrap(),
            String::from_utf8(secret.stdout).unwrap(),
        )
    }

    pub fn mock_pgp_keypair() -> (String, String) {
        let (cert, _) = CertBuilder::general_purpose(["backup@example.com"])
            .set_profile(openpgp::Profile::RFC4880)
            .unwrap()
            .set_features(Features::empty().set_seipdv1())
            .unwrap()
            .generate()
            .unwrap();
        let mut public = Vec::new();
        cert.armored().export(&mut public).unwrap();
        let mut secret = Vec::new();
        cert.as_tsk().armored().serialize(&mut secret).unwrap();
        (
            String::from_utf8(public).unwrap(),
            String::from_utf8(secret).unwrap(),
        )
    }

    pub fn mock_pgp_cert_armored() -> String {
        mock_pgp_keypair().0
    }

    pub fn mock_pgp_certs_armored(n: usize) -> Vec<String> {
        (0..n).map(|_| mock_pgp_cert_armored()).collect()
    }

    pub fn mock_pgp_cert() -> PgpPublicCert {
        PgpPublicCert::new(mock_pgp_cert_armored()).unwrap()
    }

    pub fn mock_pgp_certs(n: usize) -> Vec<PgpPublicCert> {
        (0..n).map(|_| mock_pgp_cert()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io;
    use std::process::Command;

    fn temp_gnupg_home() -> tempfile::TempDir {
        let homedir = tempfile::Builder::new().tempdir().unwrap();
        test_utils::prepare_gnupg_home(homedir.path());
        homedir
    }

    #[test]
    fn test_encrypt_armored_and_decrypt() {
        let (public, secret) = test_utils::mock_pgp_keypair();
        let public_cert = PgpPublicCert::new(public).unwrap();

        let plaintext = b"secret share bytes";
        let ciphertext = encrypt_armored(plaintext, &public_cert).unwrap();
        assert!(ciphertext.starts_with("-----BEGIN PGP MESSAGE-----"));

        let mut decryptor = decrypt_with_secret_key(
            std::io::Cursor::new(ciphertext.into_bytes()),
            secret.as_bytes(),
        )
        .unwrap();
        let mut decrypted = Vec::new();
        io::copy(&mut decryptor, &mut decrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_public_cert_rejects_secret_key_material() {
        let (_public, secret) = test_utils::mock_pgp_keypair();

        let err = PgpPublicCert::new(secret).unwrap_err();

        assert!(
            err.to_string()
                .contains("must not contain secret key material"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_gpg_encrypted_message_can_be_decrypted_with_sequoia() {
        let homedir = temp_gnupg_home();
        let (_public, secret) = test_utils::gpg_generate_keypair(homedir.path());
        let plaintext = b"secret share bytes";

        let plaintext_path = homedir.path().join("plaintext");
        let ciphertext_path = homedir.path().join("ciphertext.asc");
        fs::write(&plaintext_path, plaintext).unwrap();

        let output = Command::new("gpg")
            .env("GNUPGHOME", homedir.path())
            .arg("--batch")
            .arg("--yes")
            .arg("--armor")
            .arg("--trust-model")
            .arg("always")
            .arg("--encrypt")
            .arg("--recipient")
            .arg("backup@example.com")
            .arg("--output")
            .arg(&ciphertext_path)
            .arg(&plaintext_path)
            .output()
            .unwrap();
        test_utils::assert_command_success(&output, "gpg --encrypt");

        let input = fs::File::open(&ciphertext_path).unwrap();
        let mut decryptor = decrypt_with_secret_key(input, secret.as_bytes()).unwrap();
        let mut decrypted = Vec::new();
        io::copy(&mut decryptor, &mut decrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_sequoia_encrypted_message_can_be_decrypted_with_gpg() {
        let homedir = temp_gnupg_home();
        let (public, secret) = test_utils::mock_pgp_keypair();
        let public_cert = PgpPublicCert::new(public).unwrap();
        let plaintext = b"secret share bytes";
        let ciphertext = encrypt_armored(plaintext, &public_cert).unwrap();

        let secret_key_path = homedir.path().join("secret-key.asc");
        fs::write(&secret_key_path, secret).unwrap();
        test_utils::gpg_import_key(homedir.path(), &secret_key_path);

        let ciphertext_path = homedir.path().join("ciphertext.asc");
        fs::write(&ciphertext_path, ciphertext).unwrap();

        let output = Command::new("gpg")
            .env("GNUPGHOME", homedir.path())
            .arg("--decrypt")
            .arg(&ciphertext_path)
            .output()
            .unwrap();
        test_utils::assert_command_success(&output, "gpg --decrypt");
        assert_eq!(plaintext, output.stdout.as_slice());

        let mut decryptor = decrypt_with_gpg(&ciphertext_path, Some(homedir.path())).unwrap();
        let mut decrypted = Vec::new();
        io::copy(&mut decryptor, &mut decrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
