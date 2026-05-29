# keri-kotlin

Native Android binding for the KERI mobile SDK. No Flutter — Rust core
(`keri-sdk`) exposed to Kotlin via [UniFFI 0.31](https://mozilla.github.io/uniffi-rs/),
with the existing Android Keystore + biometric backends from the Flutter
plugin ported over verbatim.

## Layout

- `keri-kotlin/` — Rust crate (`cdylib`). UniFFI procmacros expose
  `KeriMobileSdk` and the `KeyProvider` callback interface.
- `keri-android-sdk/` — Android library module producing the `KeriSdk` AAR.
  Bundles the generated UniFFI Kotlin, the Keystore/Biometric backends and a
  default `AndroidKeystoreKeyProvider` implementation.
- `example-app/` — Jetpack Compose app demonstrating the full identifier
  lifecycle.

## Prerequisites

- Rust toolchain + `rustup target add aarch64-linux-android x86_64-linux-android`
- `cargo install cargo-ndk`
- Android NDK r26+ (`ANDROID_NDK_HOME` set)
- Android SDK with platform 36, build-tools, JDK 17
- A device or emulator running Android 11+ (API 30, required for Ed25519 in
  AndroidKeyStore)

## Build

```bash
make rust       # cross-compile libuniffi_keri.so for arm64-v8a + x86_64
make bindgen    # generate Kotlin from the .so
make sdk        # assemble the AAR
make app        # build the example APK
make install    # install on a connected device / emulator
```

Or simply `./gradlew :example-app:installDebug` — the `cargoBuild` Gradle task
shells out to `make rust bindgen` automatically before the Android build.

## Default endpoints

The example app uses the project's cloud witnesses + watcher out of the box:

- `https://witness1.dkms.colossi.network`
- `https://witness2.dkms.colossi.network`
- `https://witness3.dkms.colossi.network`
- `https://watcher.dkms.colossi.network`

Type a single URL into the "Custom endpoint" field (for example
`http://10.0.2.2:3232` for a local `dkms-bin` running on the host machine) to
override every default.

## Footprint

A per-ABI release APK lands around 18–22 MB vs ~28–32 MB for the equivalent
Flutter example — the Flutter engine and Dart AOT image are gone; the Rust
`.so` (~14 MB) remains the dominant cost.
