# Key Provisioner Setup

## Setting up your MacBook Neo

## Setting up your YubiKey

Each guardian key provisioner (KP) needs one YubiKey-backed OpenPGP certificate
that can encrypt and sign. During the guardian ceremony, Hashi encrypts the KP's
guardian share to that certificate. Later, the KP touches the YubiKey to decrypt
the share and touches it again to sign provisioning requests.

Generate dedicated keys for guardian provisioning. Do not reuse a personal key
or a node-backup key. The private keys remain on the YubiKey; only the armored
public certificate is shared with the guardian operator.

### Provision the YubiKey

Obtain a new [YubiKey 5 Series](https://www.yubico.com/products/yubikey-5-overview/)
device and label it so its physical identity can be matched to its public
certificate and storage record.

Use a setup machine with a physical USB port. Install
[`oct`](https://codeberg.org/openpgp-card/openpgp-card-tools),
[`gpg`](https://gnupg.org/), and
[`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/), then disconnect
every YubiKey except the device being provisioned.

From the repository root, run the interactive provisioning script:

```sh
./key-provisioner/scripts/provision-yubikey.sh
```

Follow its prompts. The script changes the factory PINs, confirms the OpenPGP
key slots are empty, generates the keys, requires a physical touch for signing
and decryption, and tests both operations. When setup completes, it prints the
public certificate path and primary-key fingerprint to provide to the operator.

### Provide the public certificate to the operator

Send only the `.asc` public certificate and its fingerprint to the guardian
operator. Do not send either PIN or any local GnuPG private-key material.

The operator assigns each KP one ordered roster entry containing exactly one
certificate path:

```yaml
kp_roster:
  num_shares: 3
  threshold: 2
  kp_pgp_cert_paths:
    - /secure/kp1.asc
    - /secure/kp2.asc
    - /secure/kp3.asc
```

Each entry represents one KP, one guardian share, and one YubiKey-backed
OpenPGP certificate. The KP's local `kp_pgp_cert_path` points to the same
certificate for ceremony and provisioning commands.

Store the YubiKey separately from the public certificate and guardian
configuration. Losing the YubiKey prevents that KP from decrypting and
submitting its guardian share.
