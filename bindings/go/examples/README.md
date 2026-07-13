# DKMS Go Bindings - Examples

This directory contains practical examples demonstrating how to use the DKMS Go bindings for KERI based decentralized key management.

All examples read the PostgreSQL connection string from the `DATABASE_URL`
environment variable and are run with `go run .` from the example directory.
See the [bindings README](../README.md) for prerequisites and for running the
whole set at once with `make examples`.

```bash
cd <example>
DATABASE_URL="postgres://postgres:postgres@localhost:5432/keri_go" go run .
```

## Available Examples

### 1. Simple Example (`simple/`)

The most basic example, showing how to:

- Create a KERI controller
- Generate keys
- Create an identifier (inception)
- Sign and finalize the inception event

Use case: getting started with DKMS and understanding the basic workflow.

### 2. Signing Example (`signing/`)

Data signing and verification:

- Create a signing identifier
- Sign arbitrary data with cryptographic proof
- Verify signed data authenticity
- Detect tampering attempts
- CESR-encoded signature format

Use case: document signing, API authentication, data integrity verification, and message authentication.

### 3. Anchor Example (`anchor/`)

Anchoring external data into the KEL and verifying it later:

- Anchor the digest of a payload (the example uses WireGuard public keys) into the identifier's key event log via an interaction event
- Sign and finalize the anchor event
- Verify that a presented payload was anchored
- Reject a payload that was never anchored

Only the Blake3-256 digest of the payload is committed to the KEL, never the
payload itself, so verification is byte-exact. Anchor and verify the same
canonical bytes — the example anchors the raw decoded key rather than its
base64 text.

Use case: committing/timestamping external public keys or documents to a KERI
identity, and later proving the identity attested to exactly those bytes.

### 4. Rotation Example (`rotation/`)

Key rotation using KERI's pre-rotation scheme:

- Create an identifier with initial keys
- Pre-commit to the next key at inception
- Perform a key rotation
- Maintain identifier continuity across the rotation

Use case: key lifecycle management, compromise recovery, and compliance with rotation policies.

### 5. Multisig Example (`multisig/`)

Multi-signature identifier management:

- Create an identifier requiring multiple signatures
- Configure signature thresholds
- Manage multiple current and next keys

Use case: organizational identifiers, joint accounts, and multi-party authorization.

### 6. Credentials Example (`credentials/`)

The full verifiable credential lifecycle:

- Create a credential registry (TEL)
- Issue an ACDC verifiable credential
- Query credential status through a watcher
- Revoke the credential
- Observe the status change from issued to revoked

Use case: educational credentials, identity documents, professional certifications, and access control.

This example needs a witness and a watcher in addition to PostgreSQL. See the
witness and watcher section in the [bindings README](../README.md) for how to
start them and how the OOBIs are configured.

### 7. Restart Example (`restart/`)

Resuming an identifier after a simulated process restart, instead of
incepting a new one:

- Incept an identifier and record its AID and KEL
- Free every in-memory handle (`Identifier`, `Controller`) to simulate the
  process exiting
- Create a new `Controller` against the same Postgres database and call
  `Controller.LoadIdentifier` with just the AID string
- Confirm the resumed identifier has the same AID and an unchanged KEL — no
  new inception event was created
- Perform a rotation on the resumed handle to prove it is live, not just
  read-only

Use case: any long-running service that incepts an identifier once and must
recover the same identifier — not a new one — across process restarts or
redeploys, using durable storage (Postgres) as the source of truth instead of
keeping the `Identifier` handle in memory for the identifier's whole
lifetime.
