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

   Quit Terminal completely with **Command-Q**, then reopen it to load the new
   shell environment. Do not continue in a Terminal session restored after the
   restart; the installed tools may not be on its `PATH`.

Congratulations, your MacBook Neo setup is complete! Continue below to set up
your YubiKey.

## Setting up your YubiKey

Each guardian key provisioner (KP) needs one YubiKey-backed OpenPGP certificate
that can encrypt and sign. During the guardian ceremony, Hashi encrypts the KP's
guardian share to that certificate. Later, the KP touches the YubiKey to decrypt
the share and touches it again to sign provisioning requests.

Generate dedicated keys for guardian provisioning. Do not reuse a personal key
or a node-backup key. The private keys remain on the YubiKey; only the armored
public certificate is shared with the guardian operator.

### Provision the YubiKey

Obtain a new [YubiKey 5 Series](https://www.yubico.com/products/yubikey-5-overview/) device and label it so its physical identity can
be matched to its public certificate and storage record.

Use a setup machine with a physical USB port. Install [`oct`](https://codeberg.org/openpgp-card/openpgp-card-tools), [`gpg`](https://gnupg.org/), and [`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/), then
disconnect every YubiKey except the device being provisioned.

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

Each entry represents one KP, one guardian share, and one YubiKey-backed OpenPGP
certificate. The KP's local `kp_pgp_cert_path` points to the same certificate
for ceremony and provisioning commands.

Store the YubiKey separately from the public certificate and guardian
configuration. Losing the YubiKey prevents that KP from decrypting and
submitting its guardian share.
