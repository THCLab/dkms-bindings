# DKMS Go Bindings - Examples

This directory contains practical examples demonstrating how to use the DKMS Go bindings for KERI-based decentralized key management.

## Available Examples

### 1. Simple Example (`simple/`)

The most basic example showing how to:
- Create a KERI controller
- Generate keys
- Create an identifier (inception)
- Sign and finalize the inception event

**Run:**
```bash
cd simple
go run main.go
```

**Use Case:** Getting started with DKMS, understanding the basic workflow.

---

### 2. Signing Example (`signing/`)

Comprehensive example demonstrating data signing and verification:
- Create a signing identifier
- Sign arbitrary data with cryptographic proof
- Verify signed data authenticity
- Detect tampering attempts
- CESR-encoded signature format

**Run:**
```bash
cd signing
go run main.go
```

**Use Case:** Document signing, API authentication, data integrity verification, message authentication.

**Key Features:**
- ✓ Sign any data with your KERI identifier
- ✓ Verify signatures cryptographically
- ✓ Detect tampering and modifications
- ✓ Self-describing CESR format
- ✓ No certificate authorities needed

---

### 3. Rotation Example (`rotation/`)

Complete key rotation demonstration showing KERI's pre-rotation scheme:
- Create identifier with initial keys
- Pre-commit to next key at inception
- Perform key rotation
- Maintain identifier continuity
- Verify rotation completed successfully

**Run:**
```bash
cd rotation
go run main.go
```

**Use Case:** Key lifecycle management, compromise recovery, cryptographic agility, compliance with rotation policies.

**Key Concepts:**
- **Pre-Rotation:** Next key is committed before rotation
- **Key Continuity:** Identifier remains unchanged after rotation
- **Security:** Prevents unauthorized rotation attacks
- **Forward Security:** Attacker cannot forge rotation without pre-committed key

**Advanced Scenarios:**
- Multisig rotation (changing keys in multi-signature schemes)
- Witness rotation (adding/removing witnesses)
- Delegated rotation (rotating delegated identifier keys)
- Emergency rotation (key recovery scenarios)

---

### 4. Multisig Example (`multisig/`)

Multi-signature identifier management:
- Create identifier requiring multiple signatures
- Configure signature thresholds
- Collect and aggregate signatures
- Finalize events with multiple signers

**Run:**
```bash
cd multisig
go run main.go
```

**Use Case:** Organizational identifiers, joint accounts, DAO governance, multi-party authorization.

---

### 5. Credentials Example (`credentials/`)

Complete verifiable credentials lifecycle demonstration:
- Create credential registry (TEL)
- Issue verifiable credentials
- Verify credential status
- Revoke credentials
- Query credential state

**Run:**
```bash
cd credentials
go run main.go
```

**Use Case:** Educational credentials, identity documents, professional certifications, access control, digital licenses.

**Key Features:**
- ✓ ACDC (Authentic Chained Data Container) format
- ✓ TEL (Transaction Event Log) for credential lifecycle
- ✓ Instant revocation capability
- ✓ Decentralized credential issuance
- ✓ Uses KERI identifiers (not DIDs)
- ✓ Privacy-preserving verification

**Credential Lifecycle:**
- **Registry Creation:** Establish TEL infrastructure
- **Issuance:** Issue credential and record in TEL
- **Verification:** Check credential status and validity
- **Revocation:** Revoke credential when needed
- **Status Queries:** Query credential state at any time

---

## Example Workflow Comparison

| Feature | Simple | Signing | Rotation | Multisig | Credentials |
|---------|--------|---------|----------|----------|-------------|
| Identifier Creation | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Signing | - | ✓ | - | ✓ | - |
| Signature Verification | - | ✓ | - | - | - |
| Key Rotation | - | - | ✓ | - | - |
| Multiple Signers | - | - | - | ✓ | - |
| Witnesses | Optional | Optional | Optional | Yes | Optional |
| Credential Registry | - | - | - | - | ✓ |
| Credential Issuance | - | - | - | - | ✓ |
| Credential Revocation | - | - | - | - | ✓ |

## Common Patterns

### Creating an Identifier

All examples follow this basic pattern:

```go
// 1. Create controller
controller, _ := dkms.NewController(dbPath, "")
defer controller.Free()

// 2. Generate keys
currentPub, currentPriv, _ := ed25519.GenerateKey(rand.Reader)
nextPub, _, _ := ed25519.GenerateKey(rand.Reader)

// 3. Create key prefixes
currentKey, _ := dkms.NewPublicKey(dkms.KeyTypeEd25519, currentPub)
nextKey, _ := dkms.NewPublicKey(dkms.KeyTypeEd25519, nextPub)

// 4. Configure inception
config := dkms.NewInceptionConfig()
defer config.Free()
config.AddCurrentKey(currentKey)
config.AddNextKey(nextKey)

// 5. Create and sign inception event
icpEvent, _ := controller.Incept(config)
signatureBytes := ed25519.Sign(currentPriv, icpEvent)
signature, _ := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, signatureBytes)

// 6. Finalize inception
identifier, _ := controller.FinalizeInception(icpEvent, signature)
defer identifier.Free()
```

### Signing Data

```go
// Sign arbitrary data
data := "Message to sign"
dataSignatureBytes := ed25519.Sign(privateKey, []byte(data))
dataSignature, _ := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, dataSignatureBytes)

// Create signed stream
signedStream, _ := identifier.Sign(data, dataSignature)

// Verify signed stream
isValid, _ := identifier.Verify(signedStream)
```

### Key Rotation

```go
// Configure rotation with new keys
rotationConfig := dkms.NewRotationConfig()
defer rotationConfig.Free()
rotationConfig.AddCurrentKey(preCommittedKey)  // Previous "next" key
rotationConfig.AddNextKey(newNextKey)          // New pre-commitment

// Create rotation event
rotEvent, _ := identifier.Rotate(rotationConfig)

// Sign with new current key
rotSignatureBytes := ed25519.Sign(newCurrentPrivateKey, rotEvent)
rotSignature, _ := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, rotSignatureBytes)

// Finalize rotation
identifier.FinalizeRotation(rotEvent, rotSignature)
```

## Key Concepts

### KERI (Key Event Receipt Infrastructure)

- **Self-Certifying Identifiers:** Identifiers derived from initial public keys
- **Key Event Log (KEL):** Append-only log of all key operations
- **Pre-Rotation:** Next key commitment prevents unauthorized rotation
- **Witnesses:** Distributed witnesses provide KEL redundancy
- **Watchers:** Monitor KEL for duplicity detection

### CESR (Composable Event Streaming Representation)

- Self-describing encoding format
- Includes type information with data
- Enables efficient streaming
- Used for keys, signatures, and events

### Security Properties

1. **Decentralized Trust:** No certificate authorities required
2. **Key Rotation:** Change keys without changing identifier
3. **Non-Repudiation:** Cryptographic proof of signature
4. **Tamper Detection:** Any modification invalidates signature
5. **Forward Security:** Pre-rotation protects against key compromise

## Testing

To run tests for the examples:

```bash
cd ..
go test -v
```

See `example_test.go` for comprehensive integration tests including witness scenarios.

## Prerequisites

- Go 1.16 or later
- DKMS Go bindings library (`libdkms_go.dylib` or `.so`)
- Ed25519 support (included in Go standard library)

## Building from Source

```bash
# Build the DKMS library
cd ..
cargo build --release

# Copy library
cp target/release/libdkms_go.dylib .  # macOS
# or
cp target/release/libdkms_go.so .     # Linux

# Run any example
cd examples/signing
go run main.go
```

## Troubleshooting

### Library Not Found

If you get "library not found" errors:
```bash
export DYLD_LIBRARY_PATH=/path/to/dkms-bindings/bindings/go:$DYLD_LIBRARY_PATH  # macOS
export LD_LIBRARY_PATH=/path/to/dkms-bindings/bindings/go:$LD_LIBRARY_PATH      # Linux
```

### Compilation Errors

Make sure you have the latest Rust toolchain:
```bash
rustup update
cargo clean
cargo build --release
```

## Production Considerations

When using these examples as a basis for production code:

1. **Key Storage:** Use HSM or secure key storage (not in-memory)
2. **Witness Configuration:** Deploy witnesses for KEL availability
3. **Error Handling:** Add comprehensive error handling and logging
4. **Key Backup:** Implement key backup and recovery procedures
5. **Rotation Policy:** Define and enforce key rotation schedules
6. **Monitoring:** Monitor KEL for duplicity and attacks
7. **Testing:** Add extensive unit and integration tests

## Verifiable Credentials API

```go
// Create credential registry
registryID, vcpEvent, _ := issuer.InceptRegistry()
vcpSignature, _ := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, sigBytes)
issuer.FinalizeInceptRegistry(vcpEvent, vcpSignature)

// Issue credential
vcData := []byte(`{"@context": [...], "credentialSubject": {...}}`)
vcHash, issEvent, _ := issuer.Issue(vcData)
issSignature, _ := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, sigBytes)
issuer.FinalizeIssue(issEvent, issSignature)

// Check credential state
state, _ := issuer.VcState(vcHash)
// Returns: VcStateIssued, VcStateRevoked, or VcStateNotIssued

// Revoke credential
revEvent, _ := issuer.Revoke(vcHash)
revSignature, _ := dkms.NewSignature(dkms.SignatureTypeEd25519Sha512, sigBytes)
issuer.FinalizeRevoke(revEvent, revSignature)
```

## Further Reading

- [Main README](../README.md) - Go bindings documentation
- [MULTISIG.md](../MULTISIG.md) - Multi-signature support details
- [VC_SUPPORT.md](../VC_SUPPORT.md) - Verifiable credentials details
- [CGO_VS_WASM.md](../CGO_VS_WASM.md) - Performance comparison
- [KERI Whitepaper](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf)
- [ACDC Specification](https://trustoverip.github.io/tswg-acdc-specification/) - Authentic Chained Data Containers
- [KERI.one](https://keri.one/) - KERI resources and documentation

## Contributing

Found an issue or want to add an example? Please open an issue or pull request!

## License

See the main repository LICENSE file.