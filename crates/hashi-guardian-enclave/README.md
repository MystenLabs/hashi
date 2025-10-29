# Hashi Guardian Enclave

Static enclave setup code (from nautilus) for building AWS Nitro Enclaves.

## Quick Test (Local)

```bash
# Terminal 1 - Run server (from hashi-guardian-server crate)
cd ../hashi-guardian-server
cargo run

# Terminal 2 - Run client (from hashi-guardian-client crate)
cd ../hashi-guardian-client
cargo run
```

## Enclave Deployment

### Local Build

```bash
make                  # Build enclave image
```

To run the enclave, you need to be on AWS..

### AWS Deployment

Launch EC2 instance with Nitro Enclaves:

```bash
export KEY_PAIR=my-key-pair
./scripts/configure_enclave.sh
```

On the EC2 instance:

```bash
# Clone repo and build
make
make run

# Expose enclave to network
./scripts/expose_enclave.sh
```

### Scripts

- `scripts/configure_enclave.sh` - Launch AWS EC2 with Nitro Enclaves
- `scripts/expose_enclave.sh` - Expose enclave on port 3000 (VSOCK→TCP)
- `scripts/reset_enclave.sh` - Stop enclave & cleanup
- `scripts/update.sh` - Update StageX image digests
