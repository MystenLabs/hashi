# Guardian Client

A command-line client for interacting with the Guardian enclave server.

## Overview

The Guardian Client provides a CLI interface to communicate with the Guardian enclave server. It supports all server endpoints including key setup, initialization, attestation retrieval, and S3 configuration.

## Prerequisites

- Rust toolchain installed
- Access to a running Guardian server
- AWS credentials (for S3 configuration)

## Setup

1. Create a `.env` file in the client directory with your AWS credentials:

```env
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_BUCKET_NAME=your_bucket_name
```

## Usage

```bash
cargo run [COMMAND] [BASE_URL]
```

If `BASE_URL` is not provided, it defaults to `http://localhost:3000`.

## Commands

### ping
Test server connectivity.

```bash
cargo run ping http://localhost:3000
```

### configure_s3
Send S3 configuration to the server. Requires AWS credentials in environment variables.

```bash
cargo run configure_s3 http://localhost:3000
```

**Environment Variables Required:**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_BUCKET_NAME`

### setup_new_key
Generate key provisioner encryption keys and request the server to create encrypted shares of a new Bitcoin private key.

```bash
cargo run setup_new_key http://localhost:3000
```

**Output:**
- Generates N encryption key pairs (where N is defined by `SECRET_SHARING_N`)
- Receives encrypted shares from the server
- Receives share commitments for verification

**Note:** In production, you should persist the encrypted shares and commitments securely for later use during initialization.

### get_attestation
Retrieve the enclave's attestation document.

```bash
cargo run get_attestation http://localhost:3000
```

**Output:**
- Attestation document in hex format
- Document length and preview

**Note:** You should verify this attestation document before trusting the enclave. The attestation contains the enclave's public signing key.

### init
Initialize the enclave with encrypted shares and configuration state.

```bash
cargo run init http://localhost:3000
```

**Current Status:** This is a mock implementation demonstrating the structure.

**Production Implementation Steps:**
1. Load encrypted shares from `setup_new_key`
2. Extract the enclave's encryption public key from the attestation
3. Re-encrypt shares for the enclave's public key
4. Send threshold number of shares along with state configuration
5. Repeat for multiple key provisioners until threshold is reached

### help
Display help information.

```bash
cargo run help
# or
cargo run
```

## Architecture

The client is organized with separate functions for each API endpoint:

- `ping()` - Server connectivity check
- `configure_s3()` - S3 configuration
- `setup_new_key()` - Key generation and splitting
- `get_attestation()` - Attestation retrieval
- `init_enclave()` - Enclave initialization

## Workflow

The typical workflow for setting up a new enclave:

1. **Ping** - Verify the server is running
   ```bash
   cargo run ping
   ```

2. **Get Attestation** - Retrieve and verify the attestation
   ```bash
   cargo run get_attestation
   ```

3. **Setup New Key** - Generate and split the Bitcoin key
   ```bash
   cargo run setup_new_key
   ```

4. **Configure S3** - Send S3 credentials (along with share commitments)
   ```bash
   cargo run configure_s3
   ```

5. **Initialize** - Send encrypted shares from multiple key provisioners
   ```bash
   cargo run init
   ```

## Error Handling

The client uses `anyhow::Result` for error propagation and provides context for failures. All errors are logged with descriptive messages.

## Dependencies

Key dependencies:
- `reqwest` - HTTP client for API calls
- `hashi-guardian-shared` - Shared types and constants
- `hpke` - Hybrid Public Key Encryption
- `anyhow` - Error handling
- `tracing` - Logging

## Development

### Building
```bash
cargo build
```

### Running Tests
```bash
cargo test
```

### Checking Code
```bash
cargo check
```

## Security Considerations

1. **Attestation Verification**: Always verify the attestation document before sending sensitive data
2. **Secure Storage**: Encrypted shares and commitments should be stored securely
3. **Network Security**: Use HTTPS in production environments
4. **Credentials**: Never commit `.env` files or expose AWS credentials

## Future Enhancements

- [ ] Implement complete `init` functionality with share re-encryption
- [ ] Add attestation document verification
- [ ] Implement secure storage for shares and commitments
- [ ] Add support for batch operations
- [ ] Implement retry logic with exponential backoff
- [ ] Add progress indicators for long-running operations
