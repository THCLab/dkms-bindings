# Overview

Go client for managing KERI based Identifiers. See top level [README](https://github.com/THCLab/dkms-bindings) to get acquainted with more generic overview and client features.

# Installation

Pre-built native libraries for Linux, macOS, and Windows are committed to this
repository and downloaded automatically by `go get`. No Rust toolchain required.

```bash
go get github.com/THCLab/dkms-bindings/bindings/go
```

Then build your application with CGo enabled (the default):

```bash
CGO_ENABLED=1 go build .
```

## Building from source

If you want to build the native library yourself (e.g. to use a local Rust change):

```bash
git clone https://github.com/THCLab/dkms-bindings
cd dkms-bindings/bindings/go
make build
```

## Examples

Five complete examples are provided:

1. **Simple Example** (`examples/simple/main.go`)
   - Basic identifier creation
   - Key generation and management
   - KEL retrieval
   ```bash
   cd examples/simple && go run main.go
   ```

2. **Signing Example** (`examples/signing/main.go`)
   - Data signing and verification
   - CESR-encoded signatures
   - Tamper detection demonstration
   - Real-world signing use cases
   ```bash
   cd examples/signing && go run main.go
   ```

3. **Rotation Example** (`examples/rotation/main.go`)
   - Key rotation workflow
   - Pre-rotation scheme demonstration
   - Key continuity maintenance
   - Security best practices
   ```bash
   cd examples/rotation && go run main.go
   ```

4. **Multisig Example** (`examples/multisig/main.go`)
   - Multi-signature identifier creation
   - Multiple key management (3 current + 3 next keys)
   - Enhanced security through key distribution
   ```bash
   cd examples/multisig && go run main.go
   ```

5. **Credentials Example** (`examples/credentials/main.go`)
   - Verifiable credentials lifecycle
   - Registry creation and management
   - Credential issuance and revocation
   - Status verification and queries
   ```bash
   cd examples/credentials && go run main.go
   ```

   > **Docker note:** The credentials example requires a witness and watcher.
   > The provided `docker-compose.yml` advertises these services at `host.docker.internal`
   > so both the host Go app and containers can reach them.
   >
   > - **macOS / Windows**: Docker Desktop usually adds this entry automatically, but if
   >   you see a DNS lookup error, add it manually:
   >   ```bash
   >   echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts
   >   ```
   > - **Linux**: Docker does not add `host.docker.internal` at all — always add it:
   >   ```bash
   >   echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts
   >   ```
   >
   > These env vars must be set every time you start or restart the witness/watcher
   > containers. Without them the services advertise `http://witness:3232/` in their
   > OOBIs, which is only resolvable inside Docker — your host Go app will get a DNS
   > error. Always start with:
   > ```bash
   > WITNESS_PUBLIC_URL=http://host.docker.internal:3232/ \
   > WATCHER_PUBLIC_URL=http://host.docker.internal:3236/ \
   > docker compose up -d --force-recreate witness watcher
   > ```

See [examples/README.md](./examples/README.md) for detailed examples documentation.

# Memory Management

The Go bindings use CGO to interface with the Rust library. All objects (`Controller`, `Identifier`, `InceptionConfig`, `RotationConfig`) register a GC finalizer on creation, so Rust-side memory is freed automatically when the Go object is collected — no manual cleanup needed.

For deterministic release (e.g. closing a database connection immediately), call `Free()` explicitly. The finalizer will then become a no-op.

# Thread Safety

The underlying Rust implementation uses async/tokio runtime. Each call from Go creates a new runtime instance to handle the async operations. While this works, be aware that heavy concurrent usage may have performance implications.

# Requirements

- Go 1.16 or later
- Rust 1.70 or later (for building the library)
- CGO enabled (set `CGO_ENABLED=1`)
