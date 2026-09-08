# Key Provisioner Setup

## Setting up 1Password

TBD

## Setting up your MacBook Neo

### Complete macOS Setup Assistant

After turning on the MacBook for the first time, complete macOS Setup Assistant
using the following settings:

1. Select **English** as the language.
2. Select your country or region.
3. Set up the Mac as a new computer. Do not transfer information from another
   Mac or backup.
4. On the Accessibility screen, do not enable any accessibility features; select
   **Not Now**.
5. Connect to Wi-Fi.
6. On the Data & Privacy screen, select **Continue**.
7. Create the local account:
   - Set **Full Name** to `Hashi Guardian Key Provisioner`.
   - Set **Account Name** to `kp`.
   - Generate a random password in 1Password and save it there. The password
     must be at least 12 characters long and contain uppercase letters,
     lowercase letters, numbers, and symbols.
   - Leave **Allow this computer account password to be reset with your Apple
     Account** unchecked.
8. Do not sign in to an Apple Account. Select **Other Sign-In Options**, then
   **Sign In Later in Settings**, and finally **Skip**.
9. Agree to the terms and conditions.
10. Select **Adult** as the age range.
11. Do not enable Location Services. When prompted, select **Don't Use**.
12. Select the time zone manually without enabling Location Services.
13. Do not share analytics, crash data, or usage data with Apple.
14. On the Screen Time screen, select **Set Up Later**.
15. On the Apple Intelligence screen, select **Skip**.
16. Disable **Enable Ask Siri**, then continue.
17. Turn on FileVault.
18. Save the FileVault recovery key in 1Password.
19. Choose your preferred appearance.
20. When asked about automatic macOS updates, select **Only Download
    Automatically**.

### Provision the MacBook Neo

This procedure prepares the MacBook Neo to run Hashi key provisioner operations.
It updates macOS, clones the Hashi repository, installs Determinate Nix, and
applies the nix-darwin configuration that installs the required tooling.

1. Open Terminal and install macOS updates:

   ```sh
   sudo softwareupdate --install --all --restart
   ```

   Enter the `kp` account password when prompted. Updates may take some time.
   Wait for them to finish, including any required restarts, before continuing.
   If the Mac restarts, sign back in and reopen Terminal for the next step.

2. Install the Xcode Command Line Tools:

   ```sh
   xcode-select --install
   ```

   Find the installation pop-up window, select **Install**, and wait for the
   installation to finish before continuing.

3. Clone the Hashi repository into `~/hashi`:

   ```sh
   git clone https://github.com/MystenLabs/hashi.git ~/hashi
   ```

4. Enter the repository directory and run the setup script to install
   Determinate Nix and apply the nix-darwin configuration:

   ```sh
   cd ~/hashi
   ./key-provisioner/scripts/setup-mac.sh
   ```

   Enter the `kp` account password each time `sudo` prompts for it. If macOS
   asks whether to allow Terminal to administer your computer, select **Allow**.
   Setup may take some time.

   When setup finishes, the script prints **Setup complete** and restarts the
   Mac to apply the macOS settings.

5. After the restart, sign back in. When prompted to unlock **Nix Store**, enter
   the `kp` account password and check **Remember this password in my keychain**
   before unlocking it.

   Open **Ghostty** from the Dock and use it instead of macOS Terminal for all
   remaining commands. Ghostty was installed by the nix-darwin configuration.
   If Terminal reopened after the restart, quit it with **Command-Q** rather
   than continuing in the restored session.

   If macOS asks whether to allow Ghostty to modify system settings, access
   files or folders, or grant other permissions needed for provisioning,
   select **Allow** or approve the request.

   In Ghostty, return to the repository directory:

   ```sh
   cd ~/hashi
   ```

Congratulations, your MacBook Neo setup is complete! Continue below to set up
your YubiKey.

## Setting up your YubiKey

Each guardian key provisioner (KP) needs one YubiKey-backed OpenPGP certificate
that can encrypt and sign. During the guardian ceremony, Hashi encrypts the KP's
guardian share to that certificate. Later, the KP touches the YubiKey to decrypt
the share and touches it again to sign provisioning requests.

Generate dedicated keys for guardian provisioning. Do not reuse a personal key
or a node-backup key. The private keys remain on the YubiKey.

### Provision the YubiKey

Obtain a new [YubiKey 5 Series](https://www.yubico.com/products/yubikey-5-overview/) device and label it so its physical identity can
be matched to its public certificate and storage record.
Use firmware **5.7 or later** and keep the factory OpenPGP ATT key and certificate intact.

Use a setup machine with a physical USB port. Install [`oct`](https://codeberg.org/openpgp-card/openpgp-card-tools), [`gpg`](https://gnupg.org/), [`jq`](https://jqlang.org/), and [`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/), then
disconnect every YubiKey except the device being provisioned.

From the repository root, run the interactive provisioning script:

```sh
./key-provisioner/scripts/provision-yubikey.sh
```

Follow its prompts. The script changes the factory PINs, checks the OpenPGP
key slots, generates the keys, automatically enables touch for signing and
decryption, and tests both operations. Empty slots need no confirmation; existing
keys trigger an irreversible-overwrite warning requiring `y` or `yes`.

The user ID only names output files; keys are selected by fingerprint. Choose
an output directory (default `.`). For user ID `jdoe`, the script retains these
five public files in that directory and prints the primary-key fingerprint:

```text
jdoe-kp-pubkey.asc
jdoe-kp-fingerprint.txt
jdoe-kp-pubkey.attestation-device.pem
jdoe-kp-pubkey.attestation-sig.pem
jdoe-kp-pubkey.attestation-dec.pem
```

The text file contains only the fingerprint. The PEMs contain the factory device
signer certificate and the SIG/DEC attestation statements. The four temporary
test files are deleted on exit; the public certificate remains imported in your
normal GnuPG keyring (or the caller's `GNUPGHOME`, if set).

### Provide the public artifacts to the operator

Send all five files to the guardian operator, including for replacement
certificates. Keep the PEMs beside their `.asc` file. Do not send either PIN or
local GnuPG private-key material.

The script only checks that its outputs are nonempty. The CLI and guardian
verify the attestations and reject missing or invalid proofs, binding operations
to the attested SIG/DEC keys rather than just the primary-key fingerprint.
Attestation does not check X.509 expiry, revocation, touch policy, or freshness.

The operator configures exactly one `.asc` certificate path per KP, in any order:

```yaml
kp_roster:
  num_shares: 3
  threshold: 2
  kp_pgp_cert_paths:
    - /secure/kp1.asc
    - /secure/kp2.asc
    - /secure/kp3.asc
```

Each entry represents one KP, one guardian share, and one YubiKey-backed OpenPGP
certificate. New ceremonies assign share IDs by fingerprint order; existing
signed guardian state retains those assignments. The KP's local
`kp_pgp_cert_path` points to the same certificate for ceremony and provisioning
commands.

Store the YubiKey separately from the public certificate and guardian
configuration. Losing the YubiKey prevents that KP from decrypting and
submitting its guardian share.
