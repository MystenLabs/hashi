# Integration Test with Sui

## Background

Integration tests for Hashi need to spin up test environments including:

1. **Sui network**
2. **Bitcoin network**
3. **Hashi network**

The primary bottleneck has been the Sui network setup, which traditionally required using `TestCluster` from the Sui
repository. Using `TestCluster` has a significant drawback:

```toml
[dependencies]
test-cluster = { git = "https://github.com/MystenLabs/sui.git" }
```

Every pull request requires 30+ minutes. Instead of compiling TestCluster from source, we propose using pre-compiled Sui
binaries.

### Trade-offs

While the binary approach solves compilation time, it comes with limitations:

- **API access**: RPC-only instead of direct internal access
- **Debugging**: Less visibility into Sui internals
- **Features**: Limited to what the binary exposes

For Hashi's integration tests, these trade-offs are acceptable since tests primarily need to:

- Deploy and interact with bridge contracts
- Submit and verify transactions
- Query blockchain state

These operations are fully supported via RPC interfaces.

## Design

### Using `sui start` alone vs `sui genesis` + `sui start`

#### Option A: `sui start --force-regenesis` alone

**Pros:**

- Single command simplicity
- Faster iteration for simple tests
- No intermediate files to manage
- Automatically handles genesis creation

**Cons:**

- Cannot specify custom directory (always uses `~/.sui/sui_config/`)
- Prevents parallel test execution
- No ability to modify genesis configuration
- Mutually exclusive with `--network.config` flag

#### Option B: `sui genesis` + `sui start` (Recommended)

**Pros:**

- Can use custom directories via `--working-dir`
- Enables parallel test execution
- Separates configuration from execution

**Cons:**

- Requires two commands
- Slightly more complex implementation

**Example:**

```bash
sui genesis --working-dir /tmp/test-123
sui start --network.config /tmp/test-123
```

**Decision:** Use `sui genesis` + `sui start` for the flexibility required by parallel testing.

### Configuring Number of Validators

**Current Limitation:** `sui genesis` hardcodes 4 validators. This is not something we can work around by running
multiple processes because:

- All validators must share the same genesis
- `sui start` runs all validators as a coordinated network
- Each validator needs to know about all others for consensus

**Our Approach:**

Add `--num-validators` to `sui genesis`.

```rust
// In the test:
let sui_network = SuiNetworkBuilder::new()
.with_validators(7)
.build()
.await?;

// Inside SuiNetworkBuilder::build():
// When build() is called, it:
// 1. Creates a temp directory
// 2. Runs `sui genesis` with --num-validators flag
// 3. Runs `sui start` with the generated config
// 4. Returns a SuiNetworkHandle managing the running network
```
