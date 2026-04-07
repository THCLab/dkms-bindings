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
| [Dart/Flutter](./bindings/dart) | Active (mobile rewrite) | Android, iOS, macOS, Windows |
| [Node.js](./bindings/node.js) | Active | Linux, macOS, Windows |
| [WASM](./bindings/wasm) | Active | Web browsers |

---

# Mobile SDK (Dart/Flutter)

The Dart binding has been rewritten (branch `mobile-sdk`) with:
- **flutter_rust_bridge v2** (was v1)
- **keriox-sdk** as the Rust backend (was raw keri/controller crates)
- **rustls** for TLS (no OpenSSL dependency — required for mobile)
- **Redb** for storage (pure Rust, works on Android/iOS without mmap)
- **Host-side key management** — private keys never enter Rust memory

## Architecture

```
Flutter App
  → keri/keri.dart (app-facing API)
    → KeriMobileSdk (FRB v2 generated Dart class)
      → libdartkeriox.so / .a (Rust cdylib)
        → keriox-sdk → keriox-core + keri-controller + keri-keyprovider
```

### Key management flow

```
App calls sdk.sign(alias, data)
  → Rust: calls host_sign callback
    → Dart: AndroidKeystoreProvider.sign() or IOSKeychainProvider.sign()
      → Platform keystore signs (biometric prompt if configured)
    → Returns signature bytes to Rust
  → Rust: builds CESR envelope
→ Returns FfiSignedEnvelope to Dart
```

Private keys **never** enter the Rust address space. All signing is delegated to the host platform's keystore.

## Supported key providers

| Platform | Provider | Key Storage | Biometric |
|----------|----------|-------------|-----------|
| Android (API 30+) | `AndroidKeystoreProvider` | Android Keystore (Ed25519, hardware-backed) | BiometricPrompt |
| iOS | `IOSKeychainProvider` | Keychain (Ed25519 seed, encrypted, biometric-gated) | Face ID / Touch ID |
| macOS / Windows | `SoftwareKeyProvider` | In-memory Ed25519 (testing only) | No |

## Setup

### Prerequisites

- Flutter SDK >= 3.24
- Rust stable toolchain
- Android NDK r26+ (for Android builds)
- Xcode 15+ (for iOS builds)
- `cargo-ndk` (`cargo install cargo-ndk`)
- `cargo-lipo` (`cargo install cargo-lipo`)
- `flutter_rust_bridge_codegen` v2 (`cargo install flutter_rust_bridge_codegen`)

### Build

```bash
# Android
cargo ndk -t arm64-v8a -t x86_64 \
  -o bindings/dart/keri/keri_android/android/src/main/jniLibs \
  build --release --manifest-path bindings/dart/Cargo.toml

# iOS
cargo lipo --release --manifest-path bindings/dart/Cargo.toml

# Generate FRB v2 bindings
cd bindings/dart
flutter_rust_bridge_codegen generate
```

### Dart usage

```dart
import 'package:keri/keri.dart';

final sdk = await KeriMobileSdk.init(
  dbPath: appDocumentsPath,
  keyProvider: Platform.isAndroid
    ? AndroidKeystoreProvider()
    : IOSKeychainProvider(),
);

final prefix = await sdk.createIdentifier(
  'my-id',
  IdentifierConfig(witnessUrls: [...], witnessThreshold: 1),
);

final envelope = await sdk.sign('my-id', utf8.encode('hello world'));
final verified = await sdk.verify('my-id', envelope.cesr.codeUnits);

await sdk.rotateKeys('my-id', RotationConfig(newNextPkB64: '...'));
await sdk.inceptRegistry('my-id');
await sdk.issueCredential('my-id', credentialSaid);
```

---

# Development overview

Provides [KERIOX](https://github.com/THCLab/keriox) based bindings for various other languages either through FFI layer or other available approaches (ie. WASM).

## Repository structure

```
dkms-bindings/
├── bindings/
│   ├── dart/           # Flutter/Dart binding (FRB v2)
│   │   ├── src/        # Rust FFI layer (api.rs, types.rs)
│   │   ├── tests/      # Rust integration tests
│   │   └── keri/       # Federated Flutter plugin packages
│   │       ├── keri/                  # App-facing package
│   │       ├── keri_platform_interface/ # Abstract interface
│   │       ├── keri_android/          # Android (Keystore + FFI)
│   │       ├── keri_ios/              # iOS (Keychain + FFI)
│   │       ├── keri_macos/            # macOS (software keys)
│   │       └── keri_windows/          # Windows (software keys)
│   ├── node.js/        # Node.js binding (NAPI-RS)
│   └── wasm/           # WASM binding (wasm-bindgen)
├── .github/workflows/
│   ├── ci-dart.yml     # Dart/Flutter CI (Android + iOS builds)
│   ├── ci-nodejs.yml   # Node.js CI
│   └── ci-wasm.yml     # WASM CI
└── README.md
```

## Testing

```bash
# Rust FFI tests
cargo test --manifest-path bindings/dart/Cargo.toml

# Host key provider tests
cargo test -p keri-keyprovider --features host

# Full SDK mobile feature
cargo check -p keri-sdk --features mobile
```
