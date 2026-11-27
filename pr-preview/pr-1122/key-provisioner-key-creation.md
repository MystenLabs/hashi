# Key Provisioner Key Creation

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> How guardian key provisioners create and test OpenPGP keys on a YubiKey before the guardian ceremony.

Each guardian key provisioner (KP) needs one YubiKey-backed OpenPGP certificate
that can encrypt and sign. During the guardian ceremony, Hashi encrypts the KP's
guardian share to that certificate. Later, the KP touches the YubiKey to decrypt
the share and touches it again to sign provisioning requests.

Generate dedicated keys for guardian provisioning. Do not reuse a personal key
or a node-backup key. The private keys remain on the YubiKey; only the armored
public certificate is shared with the guardian operator.

## Create the OpenPGP key

The setup machine must have a physical USB port. Connect only the YubiKey being
configured so a command cannot select the wrong device.

1. Obtain a new [YubiKey 5 Series](https://www.yubico.com/products/yubikey-5-overview/)
   device. Label it so its physical identity can be matched to its public
   certificate and storage record.

2. Install:

   - [`oct`](https://codeberg.org/openpgp-card/openpgp-card-tools), for OpenPGP
     card administration and key generation.
   - [`gpg`](https://gnupg.org/), for testing decryption and signing through the
     YubiKey.
   - [`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/), for
     requiring physical touch before the YubiKey decrypts or signs.

3. Insert the YubiKey and list the available OpenPGP cards:

```sh
oct list
```

The output includes a card identifier such as `0006:26883270`. Use that exact
identifier in the remaining `oct` commands.

4. Change the factory user and administrator PINs:

```sh
oct pin --card 0006:26883270 set-user
oct pin --card 0006:26883270 set-admin
```

The factory user PIN is `123456`; the factory administrator PIN is `12345678`.
Store the replacement PINs in the KP's approved secret store. The user PIN
authorizes routine signing and decryption. The administrator PIN authorizes
card configuration and key generation.

5. Confirm that the card does not already contain keys:

```sh
oct status --card 0006:26883270
```

The Signature, Decryption, and Authentication slots must not show existing key
fingerprints. Stop if any slot is populated unless the existing keys are known
to be disposable. Generating new keys overwrites existing key material, which
cannot be recovered afterward.

6. Generate the OpenPGP keys directly on the YubiKey and export the armored
   public certificate:

```sh
oct admin --card 0006:26883270 generate \
  --userid "Guardian KP" \
  --output guardian-kp1.asc \
  curve25519
```

Use the KP's real name or assigned guardian identifier as the user ID and use a
unique output filename. An email address is not required. `oct` prompts for the
user and administrator PINs. The resulting `.asc` file contains public material
only; the private signing, decryption, and authentication keys remain on the
YubiKey.

7. Require a physical touch every time the signing or decryption key is used:

```sh
ykman openpgp keys set-touch sig on
ykman openpgp keys set-touch enc on
```

Enter the administrator PIN when prompted. Touch policy is configured
separately for each OpenPGP key slot; `sig` controls signing and `enc` controls
decryption. Do not use the `cached` policy, because it permits more operations
for 15 seconds after one touch.

Confirm both policies:

```sh
ykman openpgp keys info sig
ykman openpgp keys info enc
```

Both commands must report a touch policy of `On`.

8. Extract the complete primary-key fingerprint into a Bash variable and record
   its value:

```bash
FINGERPRINT="$(
  gpg --show-keys --with-colons guardian-kp1.asc |
    awk -F: '$1 == "fpr" { print $10; exit }'
)"
printf 'Guardian key fingerprint: %s\n' "$FINGERPRINT"
```

The first `fpr` record is the certificate's primary-key fingerprint. Keep using
the same Bash session for the remaining steps. The fingerprint, card identifier,
physical label, and filename should identify the same device in the KP's
inventory.

## Test the YubiKey

Test both operations Hashi requires before sending the public certificate to the
operator.

9. Import the public certificate into the KP's local GnuPG keyring and connect
   GnuPG to the card:

```sh
gpg --import guardian-kp1.asc
gpg --card-status
```

10. Encrypt and decrypt a test file using the fingerprint extracted in step 8:

```bash
printf 'guardian key test\n' > guardian-kp-test.txt
gpg --encrypt --armor \
  --trust-model always \
  --recipient "$FINGERPRINT" \
  --output guardian-kp-test.txt.asc \
  guardian-kp-test.txt
gpg --decrypt guardian-kp-test.txt.asc
```

GnuPG prompts for the user PIN. Touch the YubiKey when its indicator flashes;
decryption must not complete before that touch. Confirm that the decrypted
output is `guardian key test`.

11. Create and verify a detached signature using the same fingerprint:

```bash
gpg --armor --detach-sign \
  --local-user "$FINGERPRINT" \
  --output guardian-kp-test.sig.asc \
  guardian-kp-test.txt
gpg --verify guardian-kp-test.sig.asc guardian-kp-test.txt
```

Touch the YubiKey when its indicator flashes; signing must not complete before
that touch. Confirm that GnuPG reports a valid signature from the expected
fingerprint, then delete the test plaintext, ciphertext, and signature.

## Provide the public certificate to the operator

Send only the `.asc` public certificate and its fingerprint to the guardian
operator. Do not send either PIN or any local GnuPG private-key material.

The operator assigns each KP one ordered roster entry containing the public
certificate and all three attestation files:

```yaml
kp_roster:
  num_shares: 3
  threshold: 2
  kp_pgp_cert_bundles:
    - cert_path: /secure/kp1.asc
      device_attestation_cert_path: /secure/kp1-device-attestation.pem
      sig_attestation_path: /secure/kp1-sig-attestation.pem
      dec_attestation_path: /secure/kp1-dec-attestation.pem
    - cert_path: /secure/kp2.asc
      device_attestation_cert_path: /secure/kp2-device-attestation.pem
      sig_attestation_path: /secure/kp2-sig-attestation.pem
      dec_attestation_path: /secure/kp2-dec-attestation.pem
    - cert_path: /secure/kp3.asc
      device_attestation_cert_path: /secure/kp3-device-attestation.pem
      sig_attestation_path: /secure/kp3-sig-attestation.pem
      dec_attestation_path: /secure/kp3-dec-attestation.pem
```

Each ordered entry represents one KP, one guardian share, one YubiKey-backed
OpenPGP certificate, and that YubiKey's device, signature-key, and
decryption-key attestations. The KP's local `kp_pgp_cert_path` points to the
same certificate for ceremony and provisioning commands.

Store the YubiKey separately from the public certificate and guardian
configuration. Losing the YubiKey prevents that KP from decrypting and
submitting its guardian share.
