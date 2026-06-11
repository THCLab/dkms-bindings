# License

EUPL 1.2

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

# Overview

Language bindings for the [KERIOX](https://github.com/THCLab/keriox) SDK — a higher-level interface for managing [KERI](https://keri.one/) based Identifiers.

With these bindings you can:
- Establish and manage KERI identifiers (inception, rotation, delegation)
- Sign and verify arbitrary data using CESR-encoded envelopes
- Issue, revoke, and verify verifiable credentials (VCs) via TEL
- Use multi-signature identifiers (group-based commitment)
- Manage witnesses and watchers

## Available bindings

| Binding | Status | Platform |
|---------|--------|----------|
| [Kotlin/Android](./bindings/kotlin) | Active (mobile SDK) | Android |
| [Node.js](./bindings/node.js) | Active | Linux, macOS, Windows |
| [WASM](./bindings/wasm) | Active | Web browsers |

---

# Mobile SDK (Kotlin/Android)

Native Android binding for the KERI mobile SDK. No Flutter — the Rust core
(`keri-sdk`) is exposed to Kotlin via [UniFFI](https://mozilla.github.io/uniffi-rs/).
Key traits:
- **keriox-sdk** as the Rust backend
- **rustls** for TLS (no OpenSSL dependency — required for mobile)
- **Redb** for storage (pure Rust, works on Android without mmap)
- **Host-side key management** — private keys never enter Rust memory

## Architecture

```
Android App (Jetpack Compose)
  → KeriMobileSdk (UniFFI-generated Kotlin class)
    → libuniffi_keri.so (Rust cdylib)
      → keriox-sdk → keriox-core + keri-controller + keri-keyprovider
                              ↑
      Host KeyProvider (Kotlin) wired via the UniFFI callback interface
```

### Key management flow

```
App calls sdk.sign(alias, data)
  → Rust: KeriSigner wraps a HostCallbackKeyProvider
    → Kotlin KeyProvider callback (AndroidKeystoreKeyProvider)
      → algorithm-specific backend
        → AndroidKeyStore signs (biometric prompt if cache/window expired)
      → returns signature bytes
    → returns to Rust
  → Rust builds CESR envelope, returns the signed envelope to Kotlin
```

For Ed25519, the seed lives briefly in app memory during a sign call (kept in
a 10-second cache to coalesce inception/rotation bursts), then is zeroized.
For P-256, the private key never leaves the secure element.

## Supported key providers

| Platform          | Backend                       | Algorithm        | Key storage                                       | Per-burst auth                                |
|-------------------|-------------------------------|------------------|---------------------------------------------------|------------------------------------------------|
| Android (API 30+) | `BouncyCastleEd25519Backend`  | `Ed25519`        | seed AES-GCM wrapped under an AndroidKeyStore master key (biometric-gated) | 10-second in-memory seed cache                 |
| Android (API 30+) | `NativeP256Backend`           | `EcdsaSecp256r1` | EC key in TEE/StrongBox; never exits              | 10-second time-bound BiometricPrompt (KeyMint) |
| iOS               | (planned) Keychain + Secure Enclave | both       | TBD                                               | TBD                                            |

Desktop platforms (macOS, Windows, Linux) are intentionally **out of scope**
for the Android binding — use the native [keriox SDK](https://github.com/THCLab/keriox)
or the [Node.js binding](./bindings/node.js) directly.

## Setup

### Prerequisites

- Rust toolchain + `rustup target add aarch64-linux-android x86_64-linux-android`
- `cargo-ndk` (`cargo install cargo-ndk`)
- Android NDK r26+ (`ANDROID_NDK_HOME` set)
- Android SDK with platform 36, build-tools, JDK 17
- A device or emulator running Android 11+ (API 30, required for Ed25519 in
  AndroidKeyStore)

### Build

```bash
cd bindings/kotlin
make rust       # cross-compile libuniffi_keri.so for arm64-v8a + x86_64
make bindgen    # generate Kotlin from the .so
make sdk        # assemble the AAR
make app        # build the example APK
make install    # install on a connected device / emulator
```

Or simply `./gradlew :example-app:installDebug` — the `cargoBuild` Gradle task
shells out to `make rust bindgen` automatically before the Android build.

For full usage, the example app and the public Kotlin API, see the Kotlin
binding's [README](./bindings/kotlin/README.md).

---

# Development overview

Provides [KERIOX](https://github.com/THCLab/keriox) based bindings for various other languages either through FFI layer or other available approaches (ie. WASM).

## Repository structure

```
dkms-bindings/
├── bindings/
│   ├── kotlin/         # Kotlin/Android binding (UniFFI)
│   │   ├── keri-kotlin/        # Rust crate (cdylib) — UniFFI surface
│   │   ├── keri-android-sdk/   # Android library module (KeriSdk AAR)
│   │   └── example-app/        # Jetpack Compose example app
│   ├── node.js/        # Node.js binding (NAPI-RS)
│   └── wasm/           # WASM binding (wasm-bindgen)
├── .github/workflows/
│   ├── ci-nodejs.yml   # Node.js CI
│   └── ci-wasm.yml     # WASM CI
└── README.md
```

## Testing

```bash
# Host key provider tests
cargo test -p keri-keyprovider --features host

# Full SDK mobile feature
cargo check -p keri-sdk --features mobile
```
