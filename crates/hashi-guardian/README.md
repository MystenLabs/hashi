# Hashi Guardian

## Structure

```
src/
├── enclave/   # Static enclave setup code (from nautilus)
├── shared/    # Shared code between client and server
└── server/    # The Guardian server
└── main.rs    # A client example
```

## Quick Test (Local)

```bash
# Terminal 1 - Run server
cd src/server
cargo run

# Terminal 2 - Run client
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
./enclave/scripts/configure_enclave.sh
```

On the EC2 instance:

```bash
# Clone repo and build
make
make run

# Expose enclave to network
./enclave/scripts/expose_enclave.sh
```

### Scripts

- `configure_enclave.sh` - Launch AWS EC2 with Nitro Enclaves
- `expose_enclave.sh` - Expose enclave on port 3000 (VSOCK→TCP)
- `reset_enclave.sh` - Stop enclave & cleanup
- `update.sh` - Update StageX image digests
