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
