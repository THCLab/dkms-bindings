# Flutter / Dart bindings for the KERI mobile SDK

This crate exposes the keri-sdk Rust API to Flutter via
[`flutter_rust_bridge`](https://cjycode.com/flutter_rust_bridge/) v2. The Dart
side is a federated plugin under `keri/`:

| Package                          | Role                                                       |
|----------------------------------|------------------------------------------------------------|
| `keri/keri`                      | App-facing Flutter package. End users add this to their `pubspec.yaml`. |
| `keri/keri_platform_interface`   | Pure-Dart interface re-exporting the FRB-generated bindings. |
| `keri/keri_android`              | Android implementation: bundles `libdartkeriox.so` and a Kotlin host key provider (BouncyCastle Ed25519 + native AndroidKeyStore P-256). |
| `keri/keri_ios`                  | iOS stub — Swift host key provider (Keychain + Secure Enclave) planned. |
| `keri/keri/example`              | Working smoke-test app for Android. See its [README](keri/keri/example/README.md). |

Desktop platforms (macOS, Windows, Linux) are intentionally out of scope —
they should consume keriox directly via the native Rust crates or the
Node.js binding rather than going through Flutter.

## Repository layout

```
bindings/dart/
├── Cargo.toml             # Rust crate (keri-dart, cdylib + staticlib + rlib)
├── flutter_rust_bridge.yaml
├── src/
│   ├── api.rs             # FFI surface (KeriMobileSdk: create / rotate / sign / ...)
│   ├── types.rs           # FfiIdentifierConfig, FfiRotationConfig, FfiSignedEnvelope, ...
│   ├── frb_generated.rs   # FRB output (regenerated, do not edit)
│   └── lib.rs
└── keri/                  # Flutter federated plugin
    ├── keri/              # app-facing (+ example/ smoke test)
    ├── keri_platform_interface/
    ├── keri_android/
    └── keri_ios/          # stub
```

## Toolchain

| Tool                          | Pinned version                                       |
|-------------------------------|------------------------------------------------------|
| `flutter`                     | 3.x with Dart 3.x                                    |
| `flutter_rust_bridge_codegen` | `2.12.0`                                             |
| Rust                          | edition 2021, stable                                 |
| `cargo-ndk`                   | latest                                               |
| Android NDK                   | r25b (`30.0.14904198`) or compatible                 |
| Android SDK platform          | 36 (`compileSdk = 36`, `minSdk = 30`)                |
| `tokio`                       | multi-threaded runtime (FRB v2 default)              |

```bash
cargo install flutter_rust_bridge_codegen --version 2.12.0
cargo install cargo-ndk
sdkmanager "ndk;30.0.14904198" "platforms;android-36"
```

## Regenerating the FRB bindings

After editing `src/api.rs` or `src/types.rs`:

```bash
cd bindings/dart
flutter_rust_bridge_codegen generate
```

This runs `cargo expand` under the hood, so the host toolchain must be able to
build `keri-dart`. The output lands in
`keri/keri_platform_interface/lib/src/generated/`.

**If you've already built and `frb_generated.rs` is stale enough to break
`cargo expand`** (you'll see "missing field `xyz`" or "no method named `abc`"
errors against the generated file), stub it out before regenerating:

```bash
echo "// stubbed for codegen bootstrap" > src/frb_generated.rs
flutter_rust_bridge_codegen generate
```

## Building the Android `.so`

```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/30.0.14904198
cargo ndk \
    -t arm64-v8a -t x86_64 \
    -o keri/keri_android/android/src/main/jniLibs \
    build --release
```

Pre-built `libdartkeriox.so` for both ABIs is already checked in under that
path, so a fresh clone can run `flutter build apk` without invoking Rust at
all.

## Building the example APK

```bash
cd keri/keri/example
flutter pub get
flutter build apk --debug
flutter install                # or: flutter run -d <device>
```

The example is the canonical smoke test for the mobile SDK; see its
[README](keri/keri/example/README.md) for the picker, button-by-button
walk-through, and the three subtle bugs (algorithm tracking, transferable vs
NT next-key commitments, P-256 signature wire format) that took the most
debugging.

## Upstream dependency: cesrox

`keri-core` currently requires `cesrox = "2.0.0-beta.7"` (the version that
landed P-256 support). beta.7 is not yet on crates.io. The Cargo manifest
patches cesrox + said to the sibling checkout:

```toml
[patch.crates-io]
cesrox = { path = "../../../cesrox/cesr" }
said   = { path = "../../../cesrox/said" }
```

Drop the patch block once beta.7 is published.

## Other platforms

- **iOS**: `keri_ios` is a stub. A Swift host key provider mirroring the
  Kotlin one (Secure Enclave for P-256, Keychain for the wrapped Ed25519
  seed) is the natural next step.
- **macOS / Windows / Linux**: not provided. Desktop apps should consume
  the native [keriox crates](https://github.com/THCLab/keriox) or the
  [Node.js binding](../node.js) directly — going through Flutter buys
  nothing on those platforms.
