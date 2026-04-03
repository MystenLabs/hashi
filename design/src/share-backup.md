# Hashi Key Share Backups

TODO: explain rationale for backups...

To prevent this scenario, we ask each Hashi node operator to provide encrypted backups of their key shares to a common S3 bucket.

## Creating an `age` private key

For obvious security reasons we should never let the plaintext key shares leave your local storage. The backups must be encrypted. We will use [`age`](https://github.com/FiloSottile/age) to do so.

### Option 1: Create a private key on a YubiKey (recommended)

We will generate an age private key entirely on a YubiKey, and encrypt the key share with it. This is the recommended course of action, as it will be practically impossible for anyone to decrypt the backup without physical access to the YubiKey. The risk of this is that you also will be unable to decrypt the backup if you lose access to the YubiKey, so to minimize this we recommend obtaining at least two YubiKeys and repeating the procedure for each.

For the initial YubiKey setup, we must use a machine with a physical USB drive. After the initial setup we will be able to encrypt the share to the public key of the YubiKey on any machine including a cloud server without a USB drive.

1. Obtain a new [YubiKey 5 Series](https://www.yubico.com/products/yubikey-5-overview/). There are six models; the YubiKey 5C NFC, 5 NFC, 5C, 5 Nano, 5C Nano, and 5CI. Any of these models will do, though we recommend avoiding the Nano models as they are smaller and easier to lose.

2. Install the required packages:
    - The [`age`](https://github.com/FiloSottile/age) or [`rage`](https://github.com/str4d/rage) package. Either will do, `rage` is simply an implementation of `age` in rust. Both are widely available in package repositories, and `rage` can also be installed with `cargo install`. This must be installed on both the machine with USB access, and the machine containing the key share.
    - The [`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey) package. This is also available on various package repositories, and can also be installed with `cargo install`. This only needs to be installed on the machine with USB access.

3. Generate an `age` private key on the YubiKey:
    - On the machine with physical USB access, insert the YubiKey into the machine's USB port. Ensure no other YubiKeys or smart cards are plugged into the machine.
    - Run `age-plugin-yubikey`. This will start the generation process.
    - Select the YubiKey you plugged in.
    - Select slot 1 for the new private key.
    - Accept the default identity name by pressing enter.
    - Select the default "Once" PIN policy by pressing enter.
    - Select the default "Always" touch policy by pressing enter.
    - Press "y" to confirm generating the identity.
    - Enter the current YubiKey PIN, which should be the default, "123456".
    - You will be prompted to change the default PIN. Enter the current PUK (PIN unblocking key, or admin PIN), which should be the default, "12345678".
    - Enter a new PIN for the YubiKey. It can contain numbers, letters, and symbols, and must be 6, 7, or 8 characters long. This PIN is essential, if you lose it you will not be able to decrypt the key share backup! Be sure to backup this PIN somewhere safe, like in a company password manager. Do not use the default PIN. The value you enter will be set for both the PIN and the PUK.
    - Touch the button on the YubiKey to allow certificate generation.
    - Select the default identity filename by pressing enter. This identify file contains the public key for the private key you generated on the YubiKey, and info telling `age` how to use the private key on the YubiKey. It does not contain the private key.

4. Test encryption and decryption:
    - Obtain your recipient by running `cat <identity-file-name>.txt`. You will see a value like `age1yubikey1qwyxmxdzmw2fgfxv8na6g9xwsqcgn7vcjjte5qp9ehhse9gwpdd8zaejcc8`. Save this value somewhere.
    - Create a test text file, this can contain anything. For example you can run `echo "Testing, 1, 2, 3..." > test.txt`.
    - Encrypt the test file by running this command: `age --recipient <recipient> --armor --output test.txt.age test.txt`.
    - Run this command to decrypt: `age --decrypt --identity <identify file path> hashi-key-share.age`.
    - Enter your PIN.
    - Tap the YubiKey to confirm.
    - Confirm that the output matches the original test file.

5. Store the YubiKey(s) in a secure location, such as in a company safe. Be sure to also save the identity file somewhere.

### Option 2: Create a local private key file

If you do not wish to use a YubiKey, you can also simply generate an `age` private key locally and encrypt with it. Since the private key will be stored in a normal file instead of on a YubiKey, there is a greater risk of unauthorized use of the private key, and it must be carefully stored.

1. Install the required packages:
    - The [`age`](https://github.com/FiloSottile/age) or [`rage`](https://github.com/str4d/rage) package. Either will do, `rage` is simply an implementation of `age` in rust. Both are widely available in package repositories, and `rage` can also be installed with `cargo install`.

2. Generate a new key pair:
    - Run the following command to generate a new public/private key pair and save it to a file: `age-keygen --output hashi-backup-secret-key.txt`.

3. Test encryption and decryption
    - The recipient public key will be printed by the previous command, looking something like `age1zeq3ve2rrz6qdccshxzny0jf7sd0r5qdfrakw0u9fps40svauy6s746j58`. Save this value somewhere.
    - Create a test text file, this can contain anything. For example you can run `echo "Testing, 1, 2, 3..." > test.txt`.
    - Encrypt the test file by running this command: `age --recipient <recipient> --armor --output test.txt.age test.txt`.
    - Run this command to decrypt: `age --decrypt --identity hashi-backup-secret-key.txt test.txt.age`.
    - Confirm that the output matches the key share.

4. Store the private key file in a secure location, such as a company password manager or a USB drive in a safe. We recommend you do not store the private key file in the same location as the encrypted key share backup.

## Backup the key share

1. On the machine that contains the key share, run this command to encrypt it: `age --recipient <recipient> --armor --output hashi-key-share.age <key share file path>`.
2. Store the encrypted backup, `hashi-key-share.age`, in a secure location such as a company password manager or a USB drive in a safe.
