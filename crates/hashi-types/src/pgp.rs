// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use sequoia_openpgp as openpgp;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::stream::DecryptionHelper;
use sequoia_openpgp::parse::stream::DecryptorBuilder;
use sequoia_openpgp::parse::stream::DetachedVerifierBuilder;
use sequoia_openpgp::parse::stream::MessageLayer;
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
use std::path::PathBuf;
use std::process::Child;
use std::process::ChildStdout;
use std::process::Command;
use std::process::Stdio;
use std::sync::LazyLock;
use tracing::info;

static POLICY: LazyLock<StandardPolicy> = LazyLock::new(StandardPolicy::new);

#[derive(Debug, Clone)]
pub struct PgpPublicCert {
    armored: String,
    cert: openpgp::Cert,
}

/// A PGP certificate's primary fingerprint — sequoia's canonical type;
/// `to_hex()` is the bare uppercase form persisted as `KPFingerprint`.
pub use sequoia_openpgp::Fingerprint;

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

    pub fn fingerprint(&self) -> Fingerprint {
        self.cert.fingerprint()
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

/// Load and validate each armored OpenPGP cert at `paths`, logging the
/// fingerprint + path of each. Returns the certs in input order.
pub fn load_certs(paths: &[PathBuf]) -> Result<Vec<PgpPublicCert>> {
    let mut certs = Vec::with_capacity(paths.len());
    for path in paths {
        let armored = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read PGP cert at {}", path.display()))?;
        let cert = PgpPublicCert::new(armored)
            .with_context(|| format!("invalid PGP cert at {}", path.display()))?;
        info!(fingerprint = %cert, path = %path.display(), "loaded PGP cert");
        certs.push(cert);
    }
    Ok(certs)
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

/// Recipient key handles found in an armored OpenPGP message's PKESK packets,
/// parsed WITHOUT decrypting. One entry per recipient encryption key. Use to
/// confirm a ciphertext is addressed to the expected cert without holding its
/// secret key (e.g. a yubikey-bound key, which can't be inspected in memory).
///
/// Rejects anonymous/hidden recipients: if the recipient key handle is omitted,
/// callers cannot prove the ciphertext is addressed only to the expected cert.
pub fn pgp_message_recipients(armored: &str) -> Result<Vec<openpgp::KeyHandle>> {
    use openpgp::parse::PacketParser;
    use openpgp::parse::PacketParserResult;
    use openpgp::parse::Parse;

    let mut handles = Vec::new();
    let mut ppr =
        PacketParser::from_bytes(armored.as_bytes()).context("invalid OpenPGP message")?;
    while let PacketParserResult::Some(pp) = ppr {
        // `recurse` extracts the current packet (owned) and yields the next
        // parser result; it also descends into nested structures. For an
        // encrypted message the PKESKs sit at the top level and the SEIP body
        // is opaque (still ciphertext), so only the recipients are visible.
        let (packet, next_ppr) = pp.recurse().context("parsing OpenPGP packet stream")?;
        if let openpgp::Packet::PKESK(pkesk) = packet {
            let handle = pkesk
                .recipient()
                .ok_or_else(|| anyhow::anyhow!("OpenPGP message has an anonymous recipient"))?;
            handles.push(handle);
        }
        ppr = next_ppr;
    }
    Ok(handles)
}

/// True if `cert` owns `handle` — i.e. `handle` aliases one of the cert's
/// (primary or sub) keys. Handles the KeyID-vs-Fingerprint suffix matching so a
/// PKESK's 8-byte KeyID matches a cert key's full fingerprint.
pub fn cert_owns_key_handle(cert: &PgpPublicCert, handle: &openpgp::KeyHandle) -> bool {
    cert.cert
        .keys()
        .any(|k| key_handles_alias(&k.key().key_handle(), handle))
}

fn key_handles_alias(a: &openpgp::KeyHandle, b: &openpgp::KeyHandle) -> bool {
    a.aliases(b) || b.aliases(a)
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
        writer: None,
        finished: false,
    })
}

/// Like [`decrypt_with_gpg`], but feeds `ciphertext` to gpg over its stdin
/// instead of a file path. A background writer thread writes the ciphertext so
/// reading decrypted bytes off stdout can proceed concurrently without
/// deadlocking when the ciphertext exceeds the OS pipe buffer (~64 KB on
/// Linux). The thread owns its `ChildStdin` and drops it on completion,
/// signalling EOF to gpg. The reader joins the writer in `Drop` so it can't
/// outlive it.
pub fn decrypt_with_gpg_stdin(
    ciphertext: &[u8],
    homedir: Option<&Path>,
) -> Result<impl io::Read + use<>> {
    let mut command = Command::new("gpg");
    command.arg("--decrypt").arg("--");
    if let Some(homedir) = homedir {
        command.env("GNUPGHOME", homedir);
    }
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .with_context(|| "Failed to run `gpg --decrypt`; is gpg installed and on PATH?")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to open gpg stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to capture gpg stdout"))?;

    // Copy the ciphertext onto the writer thread so the caller does not need to
    // keep its buffer alive while gpg runs.
    let ciphertext_owned = ciphertext.to_vec();
    let writer = std::thread::Builder::new()
        .name("gpg-stdin-writer".into())
        .spawn(move || {
            let _ = stdin.write_all(&ciphertext_owned);
            // Drop stdin so gpg sees EOF and finishes its stdout stream.
            drop(stdin);
        })
        .context("spawn gpg stdin writer thread")?;

    Ok(GpgDecryptReader {
        child,
        stdout,
        writer: Some(writer),
        finished: false,
    })
}

/// Decrypt an armored OpenPGP message string via `gpg --decrypt`, returning the
/// plaintext bytes. The ciphertext is piped to gpg over its stdin (a background
/// writer thread) and the plaintext streams back over gpg's stdout pipe into
/// memory — nothing touches disk.
pub fn decrypt_armored_via_gpg(armored: &str, homedir: Option<&Path>) -> Result<Vec<u8>> {
    let mut decryptor = decrypt_with_gpg_stdin(armored.as_bytes(), homedir)?;
    let mut plaintext = Vec::new();
    decryptor
        .read_to_end(&mut plaintext)
        .context("read decrypted bytes from gpg")?;
    Ok(plaintext)
}

/// Produce an armored detached OpenPGP signature over `payload` with the local
/// gpg key selected by `signer_fingerprint` (`gpg --local-user`) — in
/// production the KP's offline key (e.g. a yubikey).
pub fn sign_detached_via_gpg(
    payload: &[u8],
    signer_fingerprint: &Fingerprint,
    homedir: Option<&Path>,
) -> Result<String> {
    let mut command = Command::new("gpg");
    command
        .arg("--local-user")
        .arg(signer_fingerprint.to_hex())
        .arg("--armor")
        .arg("--detach-sign");
    if let Some(homedir) = homedir {
        command.env("GNUPGHOME", homedir);
    }
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .context("Failed to run `gpg --detach-sign`; is gpg installed and on PATH?")?;
    // Dropping the `ChildStdin` below signals EOF, making gpg emit the signature.
    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(payload),
        None => Err(io::Error::other("failed to open gpg stdin")),
    };
    // Reap gpg even if the write failed (EPIPE = gpg died early); its exit
    // status is the more useful error, so check it first.
    let output = child
        .wait_with_output()
        .context("wait for `gpg --detach-sign`")?;
    if !output.status.success() {
        anyhow::bail!("`gpg --detach-sign` exited with status {}", output.status);
    }
    write_result.context("write payload to gpg stdin")?;
    String::from_utf8(output.stdout).context("gpg produced a non-UTF8 armored signature")
}

/// A `VerificationHelper` that accepts exactly one signer cert.
struct DetachedSigVerifier<'a> {
    cert: &'a openpgp::Cert,
}

impl VerificationHelper for DetachedSigVerifier<'_> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer
                && results.iter().any(|r| r.is_ok())
            {
                return Ok(());
            }
        }
        anyhow::bail!("no valid signature from the expected signer cert")
    }
}

/// Verify an armored detached OpenPGP `signature` over `payload` was produced
/// by `cert`. Pure Rust (no gpg subprocess), so it runs inside the distroless
/// proxy image.
pub fn verify_detached_signature(
    payload: &[u8],
    signature: &str,
    cert: &PgpPublicCert,
) -> Result<()> {
    let helper = DetachedSigVerifier { cert: &cert.cert };
    let mut verifier = DetachedVerifierBuilder::from_bytes(signature.as_bytes())
        .context("parse detached signature")?
        .with_policy(&*POLICY, None, helper)
        .context("initialize detached verifier")?;
    verifier
        .verify_bytes(payload)
        .context("detached signature verification failed")
}

struct GpgDecryptReader {
    child: Child,
    stdout: ChildStdout,
    /// Writer thread feeding gpg's stdin, present only for the stdin variant.
    writer: Option<std::thread::JoinHandle<()>>,
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
            // into a pipe nobody is reading. This also unblocks the writer
            // thread's `write_all` (gpg closing stdin returns EPIPE).
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(writer) = self.writer.take() {
            // Make sure the stdin writer has flushed or observed gpg closing
            // its pipe before the reader is fully torn down.
            let _ = writer.join();
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

    /// What `sign_detached_via_gpg` produces, minus the gpg keyring.
    pub fn sign_detached_in_process(secret_armored: &str, payload: &[u8]) -> String {
        use openpgp::parse::Parse;
        use openpgp::policy::StandardPolicy;
        use openpgp::serialize::stream::Armorer;
        use openpgp::serialize::stream::Message;
        use openpgp::serialize::stream::Signer;
        use std::io::Write;

        let policy = StandardPolicy::new();
        let cert = openpgp::Cert::from_bytes(secret_armored.as_bytes()).unwrap();
        let keypair = cert
            .keys()
            .secret()
            .with_policy(&policy, None)
            .for_signing()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()
            .unwrap();

        let mut sig = Vec::new();
        let message = Message::new(&mut sig);
        let message = Armorer::new(message)
            .kind(openpgp::armor::Kind::Signature)
            .build()
            .unwrap();
        let mut signer = Signer::new(message, keypair)
            .unwrap()
            .detached()
            .build()
            .unwrap();
        signer.write_all(payload).unwrap();
        signer.finalize().unwrap();
        String::from_utf8(sig).unwrap()
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
    fn pgp_message_recipients_reports_expected_cert() {
        let (public, _secret) = test_utils::mock_pgp_keypair();
        let cert = PgpPublicCert::new(public).unwrap();
        let ciphertext = encrypt_armored(b"share bytes", &cert).unwrap();

        let recipients = pgp_message_recipients(&ciphertext).unwrap();
        assert!(
            !recipients.is_empty(),
            "should report at least one recipient"
        );
        assert!(
            recipients.iter().all(|h| cert_owns_key_handle(&cert, h)),
            "all recipients should belong to the cert"
        );
    }

    #[test]
    fn cert_owns_key_handle_rejects_unrelated_cert() {
        let (public_a, _) = test_utils::mock_pgp_keypair();
        let (public_b, _) = test_utils::mock_pgp_keypair();
        let cert_a = PgpPublicCert::new(public_a).unwrap();
        let cert_b = PgpPublicCert::new(public_b).unwrap();

        let ciphertext = encrypt_armored(b"x", &cert_a).unwrap();
        let recipients = pgp_message_recipients(&ciphertext).unwrap();
        assert!(
            recipients.iter().all(|h| !cert_owns_key_handle(&cert_b, h)),
            "cert_b must not own cert_a's recipients"
        );
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

    #[test]
    fn test_decrypt_armored_via_gpg() {
        let homedir = temp_gnupg_home();
        let (public, secret) = test_utils::mock_pgp_keypair();
        let public_cert = PgpPublicCert::new(public).unwrap();
        let plaintext = b"secret share bytes";
        let ciphertext = encrypt_armored(plaintext, &public_cert).unwrap();

        let secret_key_path = homedir.path().join("secret-key.asc");
        fs::write(&secret_key_path, secret).unwrap();
        test_utils::gpg_import_key(homedir.path(), &secret_key_path);

        let decrypted = decrypt_armored_via_gpg(&ciphertext, Some(homedir.path())).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn verify_detached_signature_accepts_good_rejects_tampered_and_wrong_cert() {
        let (public, secret) = test_utils::mock_pgp_keypair();
        let cert = PgpPublicCert::new(public).unwrap();
        let payload = b"relay submission bytes";
        let sig = test_utils::sign_detached_in_process(&secret, payload);

        verify_detached_signature(payload, &sig, &cert).unwrap();
        assert!(verify_detached_signature(b"other bytes", &sig, &cert).is_err());
        let other = test_utils::mock_pgp_cert();
        assert!(verify_detached_signature(payload, &sig, &other).is_err());
    }

    #[test]
    fn sign_detached_via_gpg_round_trips_through_verify() {
        let homedir = temp_gnupg_home();
        let (public, secret) = test_utils::mock_pgp_keypair();
        let cert = PgpPublicCert::new(public).unwrap();
        let secret_key_path = homedir.path().join("secret-key.asc");
        fs::write(&secret_key_path, secret).unwrap();
        test_utils::gpg_import_key(homedir.path(), &secret_key_path);

        let payload = b"relay submission bytes";
        let sig =
            sign_detached_via_gpg(payload, &cert.fingerprint(), Some(homedir.path())).unwrap();

        verify_detached_signature(payload, &sig, &cert).unwrap();
        assert!(verify_detached_signature(b"tampered", &sig, &cert).is_err());
    }
}
