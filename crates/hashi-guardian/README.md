# Hashi Guardian

## Structure

```
src/
├── shared/    # Shared code between client and server
└── server/    # The Guardian server
└── main.rs    # A client example
```

**Note:** Enclave utilities and deployment scripts have been moved to the [hashi-guardian-enclave](https://github.com/MystenLabs/hashi-guardian-enclave) repository.

## Quick Test (Local)

```bash
# Terminal 1 - Run server
cd src/server
cargo run

# Terminal 2 - Run client
cargo run
```

## Enclave Deployment

For enclave build, deployment, and AWS management instructions, see the [hashi-guardian-enclave](https://github.com/MystenLabs/hashi-guardian-enclave) repository.
