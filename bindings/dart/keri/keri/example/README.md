# keri_example — KERI Mobile SDK smoke test (Android)

A Flutter demo that exercises the full Rust → Dart → Kotlin → AndroidKeyStore
pipeline for the KERI mobile SDK. It lets you choose between two signing
backends, create a KERI identifier, rotate its keys, and inspect the KEL.

## Choosing a backend

On launch the app shows a picker:

| Backend                                | Algorithm        | Where private keys live                         | Per-burst auth model                                       |
|----------------------------------------|------------------|-------------------------------------------------|------------------------------------------------------------|
| **Software — BouncyCastle Ed25519**    | `Ed25519`        | seed encrypted under an AndroidKeyStore AES-GCM master key (biometric-gated); plaintext seed lives in app heap only during `sign()` | 10-second in-memory **seed cache** — first sign prompts, rest skip until TTL |
| **Hardware — AndroidKeyStore P-256**   | `EcdsaSecp256r1` | never leaves the secure element (TEE/StrongBox) | 10-second **time-bound biometric auth** enforced by KeyMint |

The choice is per-session (back button on the smoke-test page returns to the
picker) and flows through `FfiIdentifierConfig.algorithm` into Rust — the
Rust side persists it in the alias's `KeyState` JSON so rotations keep the
same algorithm without the caller having to specify it again.

## The smoke-test page

```
┌─────────────────────────────────────────────────┐
│ KERI smoke test — <picked backend>              │
├─────────────────────────────────────────────────┤
│ Bootstrap                                       │
│   [ Init SDK + register key provider ]          │
│   [ Wipe all app data ]                         │
├─────────────────────────────────────────────────┤
│ Witnesses                                       │
│   witness 1 URL: https://witness1.dkms.colossi…│
│   witness 2 URL: https://witness2.dkms.colossi…│
│   witness 3 URL: https://witness3.dkms.colossi…│
│   [+ Add witness]                                │
│   witness threshold: 1                          │
├─────────────────────────────────────────────────┤
│ End-to-end                                      │
│   [ Create identifier (alice) ]                 │
│   [ Rotate keys (alice) ]                       │
│   [ Show KEL ]                                  │
│   [ Verify next-binding ]                       │
├─────────────────────────────────────────────────┤
│ Rust FFI inspection                             │
│   [ listAliases() via Rust ]                    │
├─────────────────────────────────────────────────┤
│ Android Keystore (label=demo)                   │
│   [ Create key ] [ Sign ] [ List ] [ Delete ]   │
└─────────────────────────────────────────────────┘
```

### Buttons

- **Init SDK + register key provider** — opens the Rust `KeriMobileSdk` rooted
  at `<app docs>/keri_smoke/` and registers five Dart→Kotlin callbacks
  (`createKey`/`openKey`/`sign`/`deleteKey`/`listKeys`) with the FRB v2 bridge.
  Idempotent.
- **Wipe all app data** — drops the cached `KeriStore` (releasing redb's
  `flock`), `rm -rf`s `keri_smoke/`, and removes every label from the
  Kotlin label-algorithm index. Lets you re-run the flow many times without
  reinstalling.
- **Witnesses + threshold** — fields fed to `FfiIdentifierConfig.witnessUrls`.
  Defaults to the three `witness*.dkms.colossi.network` deployments. Rust
  fetches each URL's `/introduce` endpoint to obtain its `LocationScheme`.
  Leave all fields empty + threshold 0 to incept offline.
- **Create identifier (alice)** — Rust mints `alice_v1` (current) and
  `alice_v2` (next) by calling the registered `createKey` callback twice,
  builds the inception event, signs it with `alice_v1`, persists everything,
  and saves `KeyState{current_label, next_label, version, algorithm}` next to
  the controller DB.
- **Rotate keys (alice)** — Rust loads `KeyState`, opens `alice_vN` (the
  previously-committed next) via `openKey`, mints `alice_v(N+1)` via
  `createKey`, signs the rotation event, persists the new state, and deletes
  the superseded current key from the keystore.
- **Show KEL** — calls `KeriMobileSdk::show_kel(alias)`, opens a dialog with
  the AID, state-present flag, event count, `key_state.json` contents, and
  the per-version-label algorithm resolution. Useful both as a real KEL
  viewer and as a diagnostic when something goes wrong.
- **Verify next-binding** — recomputes the Blake3 digest of the current
  next-key's `BasicPrefix` string and compares it against the digest stored
  in the KEL. Diagnostic for catching algorithm/encoding mismatches between
  the inception commitment and the rotation reveal.
- **Android Keystore (label=demo)** section — exercises the Kotlin layer
  directly via `MethodChannel`, bypassing Rust. The `Create key` button
  also does a self-test: it calls `createKey` then immediately `getPublicKey`
  and shows whether the two return identical bytes (proves the keystore
  round-trip is stable).

## End-to-end happy paths

### Software Ed25519 (witnesses=1)

1. Pick **Software** on the launch screen
2. **Init SDK**
3. **Create identifier (alice)** → 2 biometric prompts (mint v1, mint v2);
   subsequent inception signatures consume the seed cache silently
4. **Show KEL** → `events: 1`
5. **Rotate keys** → 1–2 biometric prompts; on success, `Show KEL` shows
   `events: 2`

### Hardware P-256 (witnesses=0)

1. Pick **Hardware**
2. Clear all witness URLs, set threshold to 0
3. **Create identifier** → 1 biometric prompt (first sign with v1 unlocks the
   key for the 10s validity window; keygen itself needs no auth)
4. **Show KEL** → `events: 1`
5. **Rotate keys** → 1 biometric prompt
6. **Show KEL** → `events: 2`

### Hardware P-256 (witnesses≥1)

Same as above; works against `witness*.dkms.colossi.network`. Witness
deployments must speak P-256 — older Ed25519-only witnesses will reject the
inception event and the controller will park it in the `PartiallyWitnessed`
escrow (`Show KEL` would show `state present: false, events: 0`).

## Architecture summary

```
Dart UI                       Rust (FRB v2)                  Kotlin
─────────                     ──────────────                 ──────
FfiIdentifierConfig          create_identifier               KeriKeyProvider router
  .algorithm = "Ed25519"     ├─ factory.create(v1)           ├─ "Ed25519"        → BouncyCastleEd25519Backend
  .algorithm = "EcdsaSecp..."├─ factory.create(v2)           │                     (seed wrapped under AndroidKS
                             ├─ basic_prefix_for(..., NT)    │                      AES key, 10s software cache)
                             ├─ resolve witness OOBIs        │
                             ├─ store.create_with_provider   └─ "EcdsaSecp256r1" → NativeP256Backend
                             └─ save KeyState{...,algorithm}                       (EC P-256 in AndroidKeyStore,
                                                                                    10s time-bound auth, sig
                                                                                    converted DER → P1363)
                             rotate_keys
                             ├─ load KeyState
                             ├─ factory.open(next_label)
                             │     → openKey resolves algo
                             │       from KeyState
                             ├─ factory.create(new next)
                             ├─ operations::rotate (signs +
                             │     finalises with NT
                             │     next-key reveal)
                             └─ delete previous current
```

Three things are worth calling out because they took real debugging:

1. **Algorithm tracking** — `openKey` only receives a label string; the Rust
   side resolves the algorithm by parsing the label (`alice_v3` → alias
   `alice`), reading `key_state.json`, and constructing
   `PublicKeyData::new(algo, bytes)`. Without this, the rotation would hash
   the revealed key under the wrong CESR code and `NotGroupParticipantError`.
2. **Transferable vs non-transferable next-key commitment** — KERI commits
   next-keys as their NT variant (`1AAI…` for P-256, `B…` for Ed25519). We
   correspondingly call `basic_prefix_for(..., transferable = false)` when
   building the inception/rotation commitments. Easy to get wrong; the
   binding-verifier symptom is identical to the algorithm bug above.
3. **P-256 signature wire format** — AndroidKeyStore returns ECDSA in ASN.1
   DER, keri-core verifies in IEEE P1363 (raw R||S, 64 bytes). The
   `NativeP256Backend` converts DER → P1363 after every sign. Pinning JCA
   to `"SHA256withECDSAinP1363Format"` doesn't work across all OEMs.

## Running

```bash
# From this directory:
flutter pub get
flutter build apk --debug
flutter install            # or: flutter run -d <device>
```

Prerequisites:

- An Android device or emulator with biometric (fingerprint/face) enrolled —
  the BiometricPrompt errors out otherwise. On a fresh emulator: Settings →
  Security → Fingerprint, add a fingerprint, then use the emulator's
  extended controls to simulate touches.
- The native libraries (`libdartkeriox.so`, etc.) for `arm64-v8a` and
  `x86_64` are checked into `keri_android/android/src/main/jniLibs/`. To
  rebuild them from source:
  ```bash
  cd <repo>/bindings/dart
  flutter_rust_bridge_codegen generate
  ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/<version> \
    cargo ndk -t arm64-v8a -t x86_64 \
    -o keri/keri_android/android/src/main/jniLibs \
    build --release
  ```
