# Hashi Guardian

## Structure

```
src/
├── client/    # A client that shows how to interact with the server
└── server/    # The Guardian server

enclave_utils/  # Enclave stuff
├── aws/
├── system/
└── init/
```

## Quick Test (Local)

```bash
# Terminal 1 - Run server
cd src/server
cargo run

# Terminal 2 - Run client
cd src/client
cargo run
```

## Build for Enclave

**Note:** `enclave_utils` contains Linux-specific code and won't compile on macOS.
The enclave image must be built using Docker with the provided Containerfile:

```bash
# Build enclave image (creates out/nitro.eif)
make

# View PCRs (measurement hashes)
cat out/nitro.pcrs
```

## Enclave Management Scripts

All management scripts are in the `scripts/` directory:

### Setup
- **`configure_enclave.sh`** - Launch AWS EC2 instance with Nitro Enclaves
  - Sets up EC2 instance with enclave support
  - Manages AWS secrets if needed
  - Usage: `export KEY_PAIR=<your-key> && ./scripts/configure_enclave.sh`

### Deployment
- **`expose_enclave.sh`** - Expose enclave endpoints to external traffic
  - Gets enclave ID and CID
  - Sets up VSOCK-to-TCP forwarding on port 3000
  - Run after starting the enclave

### Management
- **`reset_enclave.sh`** - Stop enclave and clean up
  - Terminates all running enclaves
  - Kills socat forwarding processes
  - Use this to start fresh

- **`update.sh`** - Update StageX base image digests in Containerfile

## AWS Deployment Workflow

```bash
# 1. Configure AWS instance
export KEY_PAIR=my-key-pair
./scripts/configure_enclave.sh

# 2. SSH into instance and clone repo
# (follow configure_enclave.sh output for instance IP)

# 3. Build enclave image on instance
make

# 4. Run enclave
make run  # or make run-debug for debug mode

# 5. Expose endpoints
./scripts/expose_enclave.sh

# 6. Test from client
# Use public IP from AWS console
cargo run --bin client http://<PUBLIC_IP>:3000
```

## Adding Network Endpoints

Enclaves don't have direct internet access. To allow the enclave to access external endpoints, you need to configure traffic forwarding in two files:

### 1. `src/server/run.sh` (Inside Enclave)

Add host mappings and traffic forwarders:

```bash
# Add to /etc/hosts section (starting at 127.0.0.64)
echo "127.0.0.64   your-endpoint.com" >> /etc/hosts
echo "127.0.0.65   another-endpoint.com" >> /etc/hosts

# Add corresponding traffic forwarders (starting at port 8101)
python3 /traffic_forwarder.py 127.0.0.64 443 3 8101 &
python3 /traffic_forwarder.py 127.0.0.65 443 3 8102 &
```

**Pattern:** IP addresses start at `127.0.0.64` and increment. Ports start at `8101` and increment.

### 2. `scripts/user-data.sh` (EC2 Init Script)

Add vsock-proxy configuration and processes:

```bash
# Add to vsock-proxy.yaml
echo "- {address: your-endpoint.com, port: 443}" | sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml
echo "- {address: another-endpoint.com, port: 443}" | sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml

# Add vsock-proxy processes (ports must match run.sh)
vsock-proxy 8101 your-endpoint.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &
vsock-proxy 8102 another-endpoint.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &
```

**Important:** Port numbers (8101, 8102, etc.) must match between `run.sh` and `user-data.sh`.

### Example: Adding api.example.com

**In `src/server/run.sh`:**
```bash
echo "127.0.0.67   api.example.com" >> /etc/hosts
python3 /traffic_forwarder.py 127.0.0.67 443 3 8104 &
```

**In `scripts/user-data.sh`:**
```bash
echo "- {address: api.example.com, port: 443}" | sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml
vsock-proxy 8104 api.example.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &
```
