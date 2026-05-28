# keri_android

Android implementation of the `keri` Flutter plugin. Bundles:

- `libdartkeriox.so` for `arm64-v8a` and `x86_64` (the Rust controller +
  FRB v2 host glue).
- A Kotlin host key provider with two backends, selectable per-key via the
  `algo` argument that flows through from Dart.

## Layout

```
android/
├── build.gradle
└── src/main/
    ├── AndroidManifest.xml          # USE_BIOMETRIC permission
    ├── jniLibs/
    │   ├── arm64-v8a/libdartkeriox.so
    │   └── x86_64/libdartkeriox.so
    └── kotlin/com/thclab/keri_android/
        ├── KeriAndroidPlugin.kt     # FlutterPlugin + ActivityAware; MethodChannel handlers
        ├── KeriKeyProvider.kt       # algo → backend router with SharedPreferences label index
        ├── KeystoreBackend.kt       # interface
        ├── BouncyCastleEd25519Backend.kt
        ├── NativeP256Backend.kt
        ├── Ed25519Backend.kt        # BC keygen / sign helper
        ├── KeyVault.kt              # AES-GCM seed wrap under AndroidKeyStore master key
        └── BiometricHelper.kt       # CryptoObject-bound BiometricPrompt
```

## Backends

| Backend                       | Algorithm        | Key material location                                 | Per-burst UX                                        |
|-------------------------------|------------------|-------------------------------------------------------|-----------------------------------------------------|
| `BouncyCastleEd25519Backend`  | `Ed25519`        | seed encrypted under an AndroidKeyStore AES-GCM master (biometric-gated); cleartext seed lives in heap only during `sign()` | 10-second in-memory **seed cache** keyed by label   |
| `NativeP256Backend`           | `EcdsaSecp256r1` | EC private key in the secure element (TEE/StrongBox), never exits | 10-second **time-bound** auth enforced by KeyMint via `setUserAuthenticationParameters(10, BIOMETRIC_STRONG)` |

`KeriKeyProvider` records the chosen algorithm per label in a
`SharedPreferences` index (`keri_label_algorithm_index`) so subsequent
`sign`/`getPublicKey`/`deleteKey` calls (which only carry a label) can route
back to the right backend.

## MethodChannel surface

Channel: `com.thclab.keri_android/keystore`

| Method        | Args                                              | Result                  |
|---------------|---------------------------------------------------|-------------------------|
| `createKey`   | `{label: String, algo: String}`                   | `Uint8List` (public key bytes; Ed25519 = 32 bytes raw, P-256 = 33 bytes SEC1 compressed) |
| `getPublicKey`| `{label: String}`                                 | `Uint8List`             |
| `sign`        | `{label: String, message: Uint8List}`             | `Uint8List` (Ed25519 = 64 bytes raw, P-256 = 64 bytes IEEE P1363 R\|\|S) |
| `deleteKey`   | `{label: String}`                                 | `null`                  |
| `listKeys`    | (none)                                            | `List<String>` of labels in the algo index |

Dart-side wiring lives in the example app; pull the `_keystoreChannel` block
from
[`example/lib/main.dart`](../keri/example/lib/main.dart) for a complete
reference, then pass those closures into `KeriMobileSdk.registerKeyProvider`.

## Host requirements

- **`MainActivity` must extend `FlutterFragmentActivity`** — `BiometricPrompt`
  needs a `FragmentActivity` host. The example's `MainActivity.kt` shows this.
- **Permission**: the plugin's manifest declares `USE_BIOMETRIC`; the app's
  manifest doesn't need to repeat it.
- **`compileSdk = 36`** in the consuming app — `path_provider_android` and a
  few transitive deps require it.
- **Gradle JVM heap ≥ 4 GB** — Jetify on Flutter's own JAR artifacts otherwise
  OOMs during debug builds. The example sets `org.gradle.jvmargs=-Xmx4G ...`.
- **Biometrics enrolled** on the device or emulator — both backends use
  `BIOMETRIC_STRONG` and the prompt will fail otherwise. On an emulator:
  Settings → Security → Fingerprint, then use the extended controls to
  simulate a touch.

## Three things that took real debugging (and you'll be glad they're done)

1. **Algorithm tracking across labels** — `openKey`/`sign` only receive a
   label string. The Rust side parses `<alias>_v<N>` → alias → reads
   `key_state.json` → constructs `PublicKeyData::new(algo, bytes)`. Without
   this, post-rotation lookups would default to Ed25519 and produce
   `NotGroupParticipantError`.
2. **NT vs transferable next-key commitments** — KERI commits next-keys as
   their non-transferable basic prefix (CESR codes `B` / `1AAI`). When the
   Rust side builds the next-key commitment at inception/rotation it uses
   `basic_prefix_for(..., transferable = false)`; if you accidentally use
   the transferable variant the binding-verifier on the next rotation
   produces an identical-looking error.
3. **P-256 signature wire format** — `Signature.getInstance("SHA256withECDSA")`
   on AndroidKeyStore returns ASN.1 DER (~70 bytes), but keri-core verifies
   IEEE P1363 (raw R\|\|S, 64 bytes). `NativeP256Backend` converts DER → P1363
   after every sign. Pinning the JCA name to `"SHA256withECDSAinP1363Format"`
   would also work but is not supported across all OEM Conscrypt builds.

## Rebuilding `libdartkeriox.so`

```bash
cd <repo>/bindings/dart
flutter_rust_bridge_codegen generate
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/30.0.14904198
cargo ndk \
    -t arm64-v8a -t x86_64 \
    -o keri/keri_android/android/src/main/jniLibs \
    build --release
```

See the [top-level README](../../README.md) for the full toolchain matrix.

## Status

| Feature                     | State                                            |
|-----------------------------|--------------------------------------------------|
| Ed25519 + AES wrap          | Working                                          |
| Native P-256 + time-bound   | Working                                          |
| Inception (offline + 3 witnesses) | Working                                    |
| Rotation                    | Working                                          |
| TEL (issue / revoke / check)| FFI surface present; no UI exercise in the smoke test yet |
| Multi-sig group rotation    | Not exposed in api.rs                            |
| Release builds + ProGuard   | Not configured; debug APK is ~200 MB             |
