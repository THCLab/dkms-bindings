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

## Deployment note

The native library path is baked into binaries at link time via `-rpath`. When
deploying to another machine, copy the `.so`/`.dylib` next to your binary or
install it to a system library path:

```bash
# Linux
sudo cp libdkms_go.so /usr/local/lib/ && sudo ldconfig

# macOS
sudo cp libdkms_go.dylib /usr/local/lib/
```

# Usage

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

See [MULTISIG.md](./MULTISIG.md) for detailed multisig documentation.

See [VC_SUPPORT.md](./VC_SUPPORT.md) for verifiable credentials documentation.

## Basic Example

```go
package main

import (
    "crypto/ed25519"
    "fmt"
    "log"

    dkms "github.com/THCLab/dkms-bindings/bindings/go"
)

func main() {
    // Create a controller (backed by PostgreSQL)
    controller, err := dkms.NewController("postgres://user:pass@localhost/mydb", "")
    if err != nil {
        log.Fatal(err)
    }

    // Create public keys (you would typically get these from your key provider)
    currentKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, currentKeyBytes)
    if err != nil {
        log.Fatal(err)
    }

    nextKey, err := dkms.NewPublicKey(dkms.KeyTypeEd25519, nextKeyBytes)
    if err != nil {
        log.Fatal(err)
    }

    // Configure inception
    config := dkms.NewInceptionConfig()
    config.AddCurrentKey(currentKey)
    config.AddNextKey(nextKey)
    config.SetWitnessThreshold(0)

    // Wrap your private key in a Signer
    signer := dkms.NewEd25519Signer(privateKey) // privateKey is ed25519.PrivateKey

    // Create, sign, and finalize the inception event in one step
    identifier, err := controller.InceptAndFinalize(config, signer)
    if err != nil {
        log.Fatal(err)
    }

    // Get identifier ID
    id, err := identifier.GetID()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Identifier:", id)

    // Get KEL
    kel, err := identifier.GetKEL()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("KEL:", kel)
}
```

## Key Features

### Identifier Management

- **Inception**: Create new identifiers with `Controller.InceptAndFinalize(config, signer)` (or step-by-step: `Controller.Incept()` → sign → `Controller.FinalizeInception()`)
- **Publish**: After inception with witnesses, call `Identifier.Publish(signer)` to notify witnesses and collect receipts
- **Rotation**: Rotate keys with `Identifier.Rotate()` and `Identifier.FinalizeRotation()`
  - See `examples/rotation/` for a complete rotation demonstration

### Signing and Verification

- **Sign**: Sign data with `Identifier.Sign()`
- **Verify**: Verify signed data with `Identifier.Verify()`
- See `examples/signing/` for a complete signing and verification demonstration

### Verifiable Credentials

- **Registry**: Create credential registry with `Identifier.InceptRegistryAndPublish(signer)` — creates the registry, publishes the anchoring event to witnesses, and notifies backers
- **Issue**: Issue credentials with `Identifier.IssueAndPublish(vcData, signer)` — returns the VC hash after notifying witnesses and backers
- **Revoke**: Revoke credentials with `Identifier.RevokeAndPublish(vcHash, signer)` — revokes and notifies witnesses and backers
- **Status**: Check credential status with `Identifier.VcState(vcHash)`
- **TEL query**: Query credential state from watcher with `Identifier.QueryTELAndFinalize(registryID, vcHash, signer)`
- See `examples/credentials/` for a complete credentials lifecycle demonstration

### Key Types

The library supports multiple cryptographic algorithms:

- `KeyTypeECDSAsecp256k1`: ECDSA with secp256k1 curve
- `KeyTypeEd25519`: Ed25519 (recommended)
- `KeyTypeEd448`: Ed448
- `KeyTypeX25519`: X25519 for key exchange
- `KeyTypeX448`: X448 for key exchange

### Signature Types

- `SignatureTypeEd25519Sha512`: Ed25519 with SHA-512
- `SignatureTypeECDSAsecp256k1Sha256`: ECDSA secp256k1 with SHA-256
- `SignatureTypeEd448`: Ed448

# A note for consumers

This library requires a third party key provider that derives public private key pairs. It is on the consumer's shoulders to manage key pairs in a secure way. Nowadays various approaches exist to tackle this problem, such as TPM, HSM, or Secure Element.

This library also advocates cryptographic agility, hence it does not enforce the use of any specific cryptographic primitives (one way hash functions and asymmetric key pairs used internally). Most modern algorithms are supported and it is up to the consumer to pick whatever is appropriate. Nevertheless we propose to use `Blake3` hash function and `Ed25519` curve to derive key pairs.

## Glossary

* **Controller** -- manages Identifiers
* **Identifier** -- a KERI identifier with its associated key event log
* **KEL** -- Key Event Log, the complete history of key events for an identifier
* **KERI** -- see https://keri.one/ page

## Interface overview

### Signer interface

All signing is done through the `Signer` interface:

```go
type Signer interface {
    Sign(data []byte) (string, error)
}
```

`NewEd25519Signer(priv ed25519.PrivateKey)` is provided for convenience. For production use (HSM, KMS, Vault), implement `Signer` with your own backend.

### High-level helpers

The recommended API wraps the sign-and-finalize pattern into single calls:

- `controller.InceptAndFinalize(config, signer)`
- `identifier.Publish(signer)` — notify witnesses + collect receipts
- `identifier.InceptRegistryAndPublish(signer)`
- `identifier.IssueAndPublish(vcData, signer)`
- `identifier.RevokeAndPublish(vcHash, signer)`
- `identifier.AddWatcherAndFinalize(watcherOobi, signer)`
- `identifier.QueryKELAndFinalize(aboutID, signer)`
- `identifier.QueryTELAndFinalize(registryID, vcHash, signer)`

### Low-level API

The underlying three-step process is also available if you need more control:

1. **Prepare** — call a method that returns raw event bytes
2. **Sign** — use your external key provider to sign the event bytes
3. **Finalize** — pass the event and signature to the corresponding `Finalize*` method

This approach delegates key management to consumers, allowing them to decide what method is most reasonable, secure, and possible in their environment and use case.

# Memory Management

The Go bindings use CGO to interface with the Rust library. All objects (`Controller`, `Identifier`, `InceptionConfig`, `RotationConfig`) register a GC finalizer on creation, so Rust-side memory is freed automatically when the Go object is collected — no manual cleanup needed.

For deterministic release (e.g. closing a database connection immediately), call `Free()` explicitly. The finalizer will then become a no-op.

# Thread Safety

The underlying Rust implementation uses async/tokio runtime. Each call from Go creates a new runtime instance to handle the async operations. While this works, be aware that heavy concurrent usage may have performance implications.

# Requirements

- Go 1.16 or later
- Rust 1.70 or later (for building the library)
- CGO enabled (set `CGO_ENABLED=1`)

# License

EUPL 1.2 - See the LICENSE file for details.
