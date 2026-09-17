# Key Provisioner Setup

## Setting up 1Password

On your normal development MacBook, **not the MacBook Neo**, open 1Password
and select the **Personal vault in your business 1Password account**.

Use the 1Password password generator to create and save three separate random
passwords. Each must be **at least 12 characters long** and contain **letters,
numbers, and symbols**. Label each saved password clearly:

- **Hashi key provisioner - MacBook Neo login password** — for the local `kp` account.
- **Hashi key provisioner - YubiKey User PIN** — for signing and decryption.
- **Hashi key provisioner - YubiKey Admin PIN** — for administering the YubiKey's
  OpenPGP application.

Despite their names, the YubiKey OpenPGP PINs support letters, numbers, and
symbols; they are not limited to digits. Use a different generated password
for each of the three credentials. You will use these saved passwords during
the setup steps below.

Save the **serial number** printed on the back of the YubiKey you will set up
in the rest of these instructions in the same 1Password vault. Label it
**Hashi key provisioner - YubiKey serial number** so you can identify the
device associated with your saved PINs.

## Okta

On your **normal development MacBook, not the MacBook Neo**, register the same
YubiKey that you will provision in the later sections as an Okta passkey /
security key:

1. Sign in to [mystenlabs.okta.com](https://mystenlabs.okta.com) using your
   existing sign-in method.
2. Open your account menu and select **Settings**. Under **Security Methods**
   (sometimes labeled **Extra Verification**), find **Passkeys** or
   **Security Key or Biometric Authenticator** and select **Set up** or
   **Set up another**. Complete any reauthentication prompts.
3. Follow the browser prompts and choose **Security key**. If the browser
   initially offers another passkey provider, choose the option to use a
   different passkey or another device, then select **Security key**. Store
   the credential on the physical YubiKey, not in 1Password, iCloud Keychain,
   or the Mac's Touch ID.
4. Connect the YubiKey to your development MacBook. If prompted, allow Okta
   to see the key's make and model, and touch the YubiKey when requested.
5. Complete enrollment and confirm that the new key appears in your Okta
   security methods.
6. On the Okta security methods page, label the newly added YubiKey
   **Hashi key provisioner YubiKey**.

Exact labels depend on the browser and your organization's Okta settings.
If security-key enrollment is unavailable, contact your Okta administrator.
See [Okta's enrollment guidance](https://help.okta.com/OIE/en-us/content/topics/identity-engine/authenticators/passkeys-end-user-experience.htm).

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
   - Use the **Hashi key provisioner - MacBook Neo login password** you
     generated and saved in 1Password above.
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

Disconnect every YubiKey except the device being provisioned.

From the repository root, run the interactive provisioning script:

```sh
./key-provisioner/scripts/provision-yubikey.sh
```

Follow its prompts. The script changes the factory PINs, checks the SIG/DEC
slots, generates those keys, enables touch, and tests signing and decryption.
When prompted for the new User PIN and Admin PIN, use the
**Hashi key provisioner - YubiKey User PIN** and
**Hashi key provisioner - YubiKey Admin PIN**, respectively, that you generated
and saved in 1Password above.

Empty SIG/DEC slots need no confirmation; existing keys require `y` or `yes`
before irreversible replacement. The Authentication slot is left unchanged.

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
verify the attestations and reject missing or invalid proofs, comparing complete
public keys and binding operations to the attested SIG/DEC keys.
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
