# keri

Flutter package exposing the KERI mobile SDK to Dart. Wraps a Rust
[keri-sdk](https://github.com/THCLab/keriox) controller via
[`flutter_rust_bridge`](https://cjycode.com/flutter_rust_bridge/) v2, with a
host-side key provider so the private signing keys live in
hardware-backed storage (AndroidKeyStore today; Secure Enclave on iOS soon).

The on-device flow is:

```
Dart UI  ⇄  Rust controller (keri-sdk)  ⇄  Host key provider (Kotlin / Swift)
                                                  ↑
                                       biometric prompts, hardware-bound keys
```

## Adding to your app

```yaml
dependencies:
  keri: <version>
```

You also need a platform implementation:

```yaml
dependencies:
  keri_android: <version>      # bundles libdartkeriox.so + Kotlin key provider
```

## Usage

```dart
import 'package:keri/keri.dart';
import 'package:path_provider/path_provider.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();         // boots the Rust runtime
  runApp(const MyApp());
}

Future<KeriMobileSdk> bootSdk() async {
  final docs = await getApplicationDocumentsDirectory();
  final sdk = await KeriMobileSdk.newInstance(dbPath: '${docs.path}/keri');

  // Wire the five host-side callbacks. On Android, keri_android exposes a
  // MethodChannel ('com.thclab.keri_android/keystore') that talks to the
  // built-in key provider. iOS will follow the same pattern.
  await sdk.registerKeyProvider(
    createKey: (label, algo) async { ... },
    openKey:   (label)       async { ... },
    sign:      (label, msg)  async { ... },
    deleteKey: (label)       async { ... },
    listKeys: ()             async { ... },
  );
  return sdk;
}
```

For a fully wired example including the MethodChannel implementation,
biometric prompts, witness URL input, and rotation, see
[`example/`](example) and its [README](example/README.md).

## API surface (`KeriMobileSdk`)

Identifiers and signing:

| Method                    | Purpose                                                |
|---------------------------|--------------------------------------------------------|
| `newInstance(dbPath)`     | Create the SDK rooted at `dbPath`.                     |
| `registerKeyProvider(...)`| Install the host-side `createKey`/`openKey`/`sign`/`deleteKey`/`listKeys` callbacks. Required before any inception or rotation. |
| `createIdentifier(alias, config)` | Mint both current and next signing keys via the host callback, build and sign the inception event, persist `KeyState{current_label, next_label, version, algorithm}`. Returns the AID. |
| `rotateKeys(alias, config)` | Open the previously-committed next-key as the new current, mint a fresh next-next, sign + persist the rotation. The algorithm is reused from the alias's `KeyState`. |
| `loadIdentifier(alias)`   | Look up the saved AID for an alias.                    |
| `listAliases()`           | Enumerate aliases known to the local controller DB.    |
| `sign(alias, data)`       | Sign arbitrary bytes with the alias's current key. Returns `FfiSignedEnvelope { payload, cesr }`. |
| `verify(alias, cesr)`     | Parse a CESR stream produced by `sign` and verify it.  |

Transaction Event Log (TEL) — ACDC credentials:

| Method                                  | Purpose                                       |
|-----------------------------------------|-----------------------------------------------|
| `inceptRegistry(alias)`                 | Create a credential registry for the AID.     |
| `issueCredential(alias, credentialSaid)`| Anchor an issuance event.                     |
| `revokeCredential(alias, credentialSaid)`| Anchor a revocation event.                   |
| `checkCredential(alias, registryId, credentialSaid)` | Resolve current status (Issued / Revoked / Unknown) by querying watchers. |
| `getCredentialStatus(alias, credentialSaid)` | Read the locally-cached status without a network roundtrip. |

Diagnostics (intended for the smoke-test, not production code):

| Method                          | Purpose                                                 |
|---------------------------------|---------------------------------------------------------|
| `showKel(alias)`                | Return AID, state-present flag, event count, `key_state.json` contents, and the resolved algorithm for `<alias>_v1` / `<alias>_v2` labels. |
| `verifyNextBinding(alias)`      | Recompute the Blake3 digest of the current next-key's `BasicPrefix` string and compare against the digest committed in the KEL. Surface for catching algorithm/encoding regressions. |
| `wipe()`                        | Drop the cached `KeriStore` (release redb's `flock`) and `rm -rf` the db path. Idempotent. |

## `FfiIdentifierConfig`

```dart
FfiIdentifierConfig(
  witnessUrls: ['https://witness1.dkms.colossi.network'],
  witnessThreshold: BigInt.from(1),
  watcherUrls: const [],
  algorithm: 'Ed25519',          // or 'EcdsaSecp256r1'
)
```

`witnessUrls` are plain base URLs; Rust fetches each URL's `/introduce`
endpoint to obtain its `LocationScheme`. `algorithm` is persisted in
`KeyState` so rotations don't need to re-specify it.

## Supported algorithms

| Algorithm       | CESR transferable code | Notes                                          |
|-----------------|------------------------|------------------------------------------------|
| `Ed25519`       | `D`                    | software path (BouncyCastle on Android)        |
| `EcdsaSecp256r1`| `1AAJ`                 | hardware-backed (AndroidKeyStore P-256, iOS Secure Enclave) |

Next-key commitments use the corresponding **non-transferable** variant
(`B`/`1AAI`) — KERI hashes the NT BasicPrefix string when committing, then
reveals it as NT during rotation. The SDK handles this transparently; you
just pass `algorithm` once.

## Documentation

- [Smoke-test app walk-through](example/README.md)
- [Top-level bindings README](../../README.md) — toolchain, FRB codegen, Android `.so` build
- [KERI spec / whitepaper](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf)
