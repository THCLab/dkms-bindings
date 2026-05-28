# keri_ios

iOS implementation of the `keri` Flutter plugin.

**Status: not implemented yet.**

The Swift host key provider mirroring [`keri_android`](../keri_android) is
planned but not started. The intended design:

- A `KeystoreBackend` Swift protocol equivalent to the Kotlin one.
- `SoftwareEd25519Backend`: Ed25519 keygen + signing, seed stored in the
  Keychain under a key whose access control requires biometric auth
  (`SecAccessControlCreateFlags.userPresence` / `.biometryAny`).
- `SecureEnclaveP256Backend`: P-256 keys generated and held inside the
  Secure Enclave; signing uses `SecKeyCreateSignature` with biometric-gated
  access control.

Same `MethodChannel` surface as Android
(`com.thclab.keri_android/keystore` — name TBD on iOS) so the Dart-side
wiring stays identical.

A pre-built static `libdartkeriox.a` (universal lipo) will live under
`ios/Frameworks/` once the Swift side is in place.

In the meantime, the [Android implementation](../keri_android) is the
canonical reference.
