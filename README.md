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
                                ↑
        Host key provider (Kotlin / Swift) wired via 5 Dart→host callbacks
```

### Key management flow

```
App calls sdk.sign(alias, data)
  → Rust: KeriSigner wraps a HostCallbackKeyProvider
    → Dart sign closure (registered via sdk.registerKeyProvider)
      → MethodChannel → Kotlin KeriKeyProvider → algorithm-specific backend
        → AndroidKeyStore signs (biometric prompt if cache/window expired)
      → returns signature bytes
    → returns to Rust
  → Rust builds CESR envelope, returns FfiSignedEnvelope to Dart
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
| macOS / Windows   | not implemented yet           | —                | —                                                 | —                                              |

## Setup

### Prerequisites

- Flutter SDK with Dart 3.x
- Rust stable toolchain (edition 2021)
- Android NDK `30.0.14904198` (or compatible r25/r26)
- Android SDK platform 36
- `cargo-ndk` (`cargo install cargo-ndk`)
- `flutter_rust_bridge_codegen` v2.12 (`cargo install flutter_rust_bridge_codegen --version 2.12.0`)

### Build

```bash
# Regenerate the FRB v2 bindings (after editing src/api.rs)
cd bindings/dart
flutter_rust_bridge_codegen generate

# Android .so (arm64-v8a + x86_64)
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/30.0.14904198
cargo ndk -t arm64-v8a -t x86_64 \
  -o keri/keri_android/android/src/main/jniLibs \
  build --release

# Example APK
cd keri/keri/example
flutter build apk --debug
```

Pre-built `libdartkeriox.so` for both Android ABIs is checked into the
repo, so an example APK build does not require Rust.

### Dart usage

```dart
import 'package:flutter/services.dart';
import 'package:keri/keri.dart';
import 'package:path_provider/path_provider.dart';

const _ks = MethodChannel('com.thclab.keri_android/keystore');

Future<KeriMobileSdk> bootSdk() async {
  await RustLib.init();

  final docs = await getApplicationDocumentsDirectory();
  final sdk = await KeriMobileSdk.newInstance(dbPath: '${docs.path}/keri');

  await sdk.registerKeyProvider(
    createKey: (label, algo) async =>
        (await _ks.invokeMethod<Uint8List>('createKey',
            {'label': label, 'algo': algo}))!,
    openKey: (label) async =>
        (await _ks.invokeMethod<Uint8List>('getPublicKey',
            {'label': label}))!,
    sign: (label, msg) async =>
        (await _ks.invokeMethod<Uint8List>('sign',
            {'label': label, 'message': msg}))!,
    deleteKey: (label) async =>
        _ks.invokeMethod('deleteKey', {'label': label}),
    listKeys: () async =>
        (await _ks.invokeMethod<List<dynamic>>('listKeys') ?? [])
            .cast<String>(),
  );
  return sdk;
}

Future<void> demo(KeriMobileSdk sdk) async {
  // Rust mints alias_v1 (current) and alias_v2 (next) via the callbacks.
  final aid = await sdk.createIdentifier(
    alias: 'my-id',
    config: FfiIdentifierConfig(
      witnessUrls: const ['https://witness1.dkms.colossi.network'],
      witnessThreshold: BigInt.from(1),
      watcherUrls: const [],
      algorithm: 'EcdsaSecp256r1',     // or 'Ed25519'
    ),
  );

  final envelope = await sdk.sign(alias: 'my-id', data: utf8.encode('hello'));
  final verified = await sdk.verify(alias: 'my-id', cesr: envelope.cesr.codeUnits);

  // Rust reads the algorithm from the alias's KeyState; no need to repeat it.
  await sdk.rotateKeys(
    alias: 'my-id',
    config: FfiRotationConfig(
      witnessToAdd: const [],
      witnessToRemove: const [],
      witnessThreshold: BigInt.from(1),
    ),
  );

  await sdk.inceptRegistry(alias: 'my-id');
  await sdk.issueCredential(alias: 'my-id', credentialSaid: '...');
}
```

For a fully wired example app (algorithm picker, witness URL inputs,
biometric flows, rotation, KEL inspector, wipe-and-retry button), see
[`bindings/dart/keri/keri/example`](./bindings/dart/keri/keri/example) and
its [README](./bindings/dart/keri/keri/example/README.md).

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
