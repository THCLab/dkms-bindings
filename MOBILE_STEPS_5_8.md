# keriox Mobile SDK — Remaining Implementation Steps

This document covers Steps 5–8 of the mobile SDK implementation.
Steps 1–4, 9–11 are already completed on the `mobile-sdk` branch in both
`keriox` and `dkms-bindings` repositories.

## Prerequisites on the target machine

- Flutter SDK >= 3.24 (`flutter --version`)
- Dart SDK >= 3.3
- Rust stable toolchain (`rustup default stable`)
- Android Studio with NDK r26+ (`ndk-build --version`)
- Xcode 15+ (macOS only, for iOS)
- `cargo-ndk` (`cargo install cargo-ndk`)
- `cargo-lipo` (`cargo install cargo-lipo`)
- `flutter_rust_bridge_codegen` v2 (`cargo install flutter_rust_bridge_codegen`)
- Android emulator or physical device (API 30+)
- iOS simulator or physical device

## Repository layout

```
keriox/                          # Rust workspace (branch: mobile-sdk)
  keri_keyprovider/src/host.rs   # HostCallbackKeyProvider (done)
  keriox_sdk/                    # keri-sdk with 'mobile' feature (done)
  components/controller/         # reqwest with rustls (done)

dkms-bindings/                   # Language bindings (branch: mobile-sdk)
  bindings/dart/                 # <-- your working directory
    Cargo.toml                   # FRB v2 + keriox-sdk deps (done)
    src/api.rs                   # KeriMobileSdk FFI API (done)
    src/types.rs                 # FFI-safe DTOs (done)
    tests/test_mobile_sdk.rs     # Unit tests (done)
    keri/                        # Federated Flutter plugin (needs update)
      keri/                      #   App-facing package
      keri_platform_interface/   #   Abstract interface
      keri_android/              #   Android implementation
      keri_ios/                  #   iOS implementation
      keri_macos/                #   macOS implementation
      keri_windows/              #   Windows implementation
```

---

# Step 5: Generate FRB v2 bindings and update Flutter plugin packages

## 5.1 Configure flutter_rust_bridge v2

Create `bindings/dart/flutter_rust_bridge.yaml`:

```yaml
rust_input: src/api.rs
dart_output: keri/keri_platform_interface/lib/src/generated/
c_output: ios/Classes/bridge_generated.h
```

## 5.2 Run code generation

```bash
cd dkms-bindings/bindings/dart
flutter_rust_bridge_codegen generate
```

This produces:
- Dart binding files in `keri/keri_platform_interface/lib/src/generated/`
- A C header for iOS in `keri/keri_ios/ios/Classes/bridge_generated.h`
- Rust side `src/bridge_generated.rs` (auto-generated, git-ignored)

If there are compilation errors in `api.rs` during generation, fix them and
re-run. The FRB v2 codegen validates that all public types are FFI-safe.

## 5.3 Update pubspec.yaml for all 6 packages

### keri/keri/pubspec.yaml (app-facing)
```yaml
name: keri
version: 3.0.0

environment:
  sdk: '>=3.3.0 <4.0.0'
  flutter: '>=3.24.0'

dependencies:
  flutter:
    sdk: flutter
  keri_platform_interface:
    path: ../keri_platform_interface
  uuid: ^4.0.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^4.0.0
```

### keri/keri_platform_interface/pubspec.yaml
```yaml
name: keri_platform_interface
version: 2.0.0

environment:
  sdk: '>=3.3.0 <4.0.0'
  flutter: '>=3.24.0'

dependencies:
  flutter:
    sdk: flutter
  plugin_platform_interface: ^2.1.0
  ffi: ^2.0.1
  flutter_rust_bridge: ^2.12.0
  freezed_annotation: ^2.4.0
  meta: ^1.9.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  freezed: ^2.5.0
  build_runner: ^2.4.0
```

### keri/keri_android/pubspec.yaml
```yaml
name: keri_android
version: 2.0.0

environment:
  sdk: '>=3.3.0 <4.0.0'
  flutter: '>=3.24.0'

dependencies:
  flutter:
    sdk: flutter
  keri_platform_interface:
    path: ../keri_platform_interface
  ffi: ^2.0.1
  flutter_rust_bridge: ^2.12.0

dev_dependencies:
  flutter_test:
    sdk: flutter

flutter:
  plugin:
    implements: keri
    platforms:
      android:
        package: com.thclab.keri_android
        pluginClass: KeriAndroidPlugin
        dartPluginClass: KeriAndroid
```

### keri/keri_android/android/build.gradle
Update to:
```gradle
android {
    compileSdk 34
    defaultConfig {
        minSdk 30  // API 30 required for Ed25519 in Android Keystore
    }
}
dependencies {
    implementation 'androidx.biometric:biometric:1.1.0'
    implementation 'androidx.security:security-crypto:1.1.0-alpha06'
}
```

### keri/keri_ios/pubspec.yaml
```yaml
name: keri_ios
version: 1.0.0

environment:
  sdk: '>=3.3.0 <4.0.0'
  flutter: '>=3.24.0'

dependencies:
  flutter:
    sdk: flutter
  keri_platform_interface:
    path: ../keri_platform_interface
  ffi: ^2.0.1
  flutter_rust_bridge: ^2.12.0

dev_dependencies:
  flutter_test:
    sdk: flutter

flutter:
  plugin:
    implements: keri
    platforms:
      ios:
        pluginClass: KeriIosPlugin
        dartPluginClass: KeriIos
```

### keri/keri_ios/ios/keri_ios.podspec
```ruby
Pod::Spec.new do |s|
  s.name             = 'keri_ios'
  s.version          = '1.0.0'
  s.summary          = 'KERI SDK iOS binding'
  s.static_framework = true
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.vendored_libraries = '**/*.a'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'
end
```

## 5.4 Update the app-facing Dart API

Replace `keri/keri/lib/keri.dart` with:

```dart
import 'package:keri_platform_interface/keri_platform_interface.dart';

export 'package:keri_platform_interface/keri_platform_interface.dart';

class Keri {
  static Future<String> createIdentifier(
    String alias,
    IdentifierConfig config,
    String nextPkB64,
  ) =>
      KeriPlatformInterface.instance.createIdentifier(alias, config, nextPkB64);

  static Future<String> loadIdentifier(String alias) =>
      KeriPlatformInterface.instance.loadIdentifier(alias);

  static Future<List<String>> listAliases() =>
      KeriPlatformInterface.instance.listAliases();

  static Future<SignedEnvelope> sign(String alias, Uint8List data) =>
      KeriPlatformInterface.instance.sign(alias, data);

  static Future<VerifiedPayload> verify(String alias, Uint8List cesr) =>
      KeriPlatformInterface.instance.verify(alias, cesr);

  static Future<void> rotateKeys(String alias, RotationConfig config) =>
      KeriPlatformInterface.instance.rotateKeys(alias, config);

  static Future<String> inceptRegistry(String alias) =>
      KeriPlatformInterface.instance.inceptRegistry(alias);

  static Future<void> issueCredential(String alias, String credentialSaid) =>
      KeriPlatformInterface.instance.issueCredential(alias, credentialSaid);

  static Future<void> revokeCredential(String alias, String credentialSaid) =>
      KeriPlatformInterface.instance.revokeCredential(alias, credentialSaid);

  static Future<CredentialStatus> checkCredential(
    String alias,
    String registryId,
    String credentialSaid,
  ) =>
      KeriPlatformInterface.instance.checkCredential(
          alias, registryId, credentialSaid);

  static Future<CredentialStatus> getCredentialStatus(
    String alias,
    String credentialSaid,
  ) =>
      KeriPlatformInterface.instance.getCredentialStatus(
          alias, credentialSaid);
}
```

## 5.5 Update platform interface

Replace `keri/keri_platform_interface/lib/keri_platform_interface.dart`:

```dart
import 'dart:typed_list';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class IdentifierConfig {
  final List<String> witnessUrls;
  final int witnessThreshold;
  final List<String> watcherUrls;
  const IdentifierConfig({
    this.witnessUrls = const [],
    this.witnessThreshold = 0,
    this.watcherUrls = const [],
  });
}

class RotationConfig {
  final String newNextPkB64;
  final List<String> witnessToAdd;
  final List<String> witnessToRemove;
  final int witnessThreshold;
  const RotationConfig({
    required this.newNextPkB64,
    this.witnessToAdd = const [],
    this.witnessToRemove = const [],
    this.witnessThreshold = 0,
  });
}

class SignedEnvelope {
  final Uint8List payload;
  final String cesr;
  const SignedEnvelope({required this.payload, required this.cesr});
}

class VerifiedPayload {
  final Uint8List payload;
  final String signerId;
  const VerifiedPayload({required this.payload, required this.signerId});
}

enum CredentialStatus { issued, revoked, unknown }

abstract class KeriPlatformInterface extends PlatformInterface {
  KeriPlatformInterface() : super(token: _token);
  static final Object _token = Object();
  static KeriPlatformInterface instance = _DefaultKeriPlatform();

  Future<String> createIdentifier(String alias, IdentifierConfig config, String nextPkB64) =>
      throw UnimplementedError();
  Future<String> loadIdentifier(String alias) =>
      throw UnimplementedError();
  Future<List<String>> listAliases() =>
      throw UnimplementedError();
  Future<SignedEnvelope> sign(String alias, Uint8List data) =>
      throw UnimplementedError();
  Future<VerifiedPayload> verify(String alias, Uint8List cesr) =>
      throw UnimplementedError();
  Future<void> rotateKeys(String alias, RotationConfig config) =>
      throw UnimplementedError();
  Future<String> inceptRegistry(String alias) =>
      throw UnimplementedError();
  Future<void> issueCredential(String alias, String credentialSaid) =>
      throw UnimplementedError();
  Future<void> revokeCredential(String alias, String credentialSaid) =>
      throw UnimplementedError();
  Future<CredentialStatus> checkCredential(String alias, String registryId, String credentialSaid) =>
      throw UnimplementedError();
  Future<CredentialStatus> getCredentialStatus(String alias, String credentialSaid) =>
      throw UnimplementedError();
}

class _DefaultKeriPlatform extends KeriPlatformInterface {}
```

## 5.6 Verification

After generating and updating:
```bash
cd keri/keri
flutter pub get
flutter analyze
```

Fix any analysis errors before proceeding.

---

# Step 6: Implement Android Keystore Ed25519 key provider

## 6.1 Create Kotlin key provider

File: `keri/keri_android/android/src/main/kotlin/com/thclab/keri_android/KeriKeyProvider.kt`

```kotlin
package com.thclab.keri_android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyInfo
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

object KeriKeyProvider {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS_PREFIX = "keri_"

    fun createKey(label: String): ByteArray {
        val alias = "$KEY_ALIAS_PREFIX$label"
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(
                java.security.spec.ECGenParameterSpec("ed25519")
            )
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(30)
            .build()
        kpg.initialize(spec)
        val kp = kpg.generateKeyPair()
        return kp.public.encoded
    }

    fun getPublicKey(label: String): ByteArray {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        val entry = ks.getEntry("$KEY_ALIAS_PREFIX$label", null)
            as KeyStore.PrivateKeyEntry
        return entry.certificate.publicKey.encoded
    }

    fun sign(label: String, message: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        val entry = ks.getEntry("$KEY_ALIAS_PREFIX$label", null)
            as KeyStore.PrivateKeyEntry

        val signature = Signature.getInstance("Ed25519")
        signature.initSign(entry.privateKey)
        signature.update(message)
        return signature.sign()
    }

    fun deleteKey(label: String) {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        ks.deleteEntry("$KEY_ALIAS_PREFIX$label")
    }

    fun listKeys(): List<String> {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE)
        ks.load(null)
        return ks.aliases().toList()
            .filter { it.startsWith(KEY_ALIAS_PREFIX) }
            .map { it.removePrefix(KEY_ALIAS_PREFIX) }
    }
}
```

## 6.2 Create biometric prompt helper

File: `keri/keri_android/android/src/main/kotlin/com/thclab/keri_android/BiometricHelper.kt`

```kotlin
package com.thclab.keri_android

import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executor

class BiometricHelper(private val context: Context) {

    fun authenticateAndSign(
        label: String,
        message: ByteArray,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        val executor: Executor = ContextCompat.getMainExecutor(context)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Sign with KERI key")
            .setSubtitle("Authenticate to sign data")
            .setAllowedAuthenticators(
                BiometricPrompt.Authenticators.BIOMETRIC_STRONG
                    or BiometricPrompt.Authenticators.DEVICE_CREDENTIAL
            )
            .build()

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                try {
                    val signature = KeriKeyProvider.sign(label, message)
                    onSuccess(signature)
                } catch (e: Exception) {
                    onError(e.message ?: "Signing failed")
                }
            }
            override fun onAuthenticationFailed() {
                onError("Authentication failed")
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onError(errString.toString())
            }
        }

        val activity = context as FragmentActivity
        BiometricPrompt(activity, executor, callback).authenticate(promptInfo)
    }
}
```

## 6.3 Update Android plugin Dart implementation

File: `keri/keri_android/lib/keri_android.dart`

```dart
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_list';

import 'package:ffi/ffi.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:keri_platform_interface/keri_platform_interface.dart';

// Import the generated bindings (from Step 5)
// import 'src/generated/bridge_generated.dart';

class KeriAndroid extends KeriPlatformInterface {
  static void registerWith() {
    KeriPlatformInterface.instance = KeriAndroid();
  }

  // Load the shared library
  static final DynamicLibrary _dylib = DynamicLibrary.open('libdartkeriox.so');

  // Replace with generated API class from FRB v2
  // late final _api = KeriDartApi(_dylib);

  @override
  Future<String> createIdentifier(
    String alias,
    IdentifierConfig config,
    String nextPkB64,
  ) async {
    // Call _api.createIdentifier(alias, config, nextPkB64)
    throw UnimplementedError('Wire up after FRB v2 codegen');
  }

  // ... implement all other methods by delegating to _api
  // The key provider callbacks are registered in init() below
}
```

## 6.4 Wire key provider through platform channel

The Android Dart code needs to call Kotlin for key operations and pass
results back to Rust. This is done by registering callbacks:

```dart
class KeriAndroid extends KeriPlatformInterface {
  // ...

  Future<void> init(String dbPath) async {
    // Register key provider callbacks that call Kotlin via MethodChannel
    // _api.registerKeyProvider(
    //   createKey: (label, algo) => _methodChannel.invokeMethod('createKey', {'label': label, 'algo': algo}),
    //   openKey: (label) => _methodChannel.invokeMethod('openKey', {'label': label}),
    //   sign: (label, message) => _methodChannel.invokeMethod('sign', {'label': label, 'message': message}),
    //   deleteKey: (label) => _methodChannel.invokeMethod('deleteKey', {'label': label}),
    //   listKeys: () => _methodChannel.invokeMethod('listKeys'),
    // );
  }
}
```

The Kotlin `MethodChannel` handler calls `KeriKeyProvider` methods directly.

## 6.5 Update AndroidManifest.xml

File: `keri/keri_android/android/src/main/AndroidManifest.xml`

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
  package="com.thclab.keri_android">
  <uses-permission android:name="android.permission.USE_BIOMETRIC" />
</manifest>
```

## 6.6 Test on Android

```bash
cd keri/keri
flutter run -d <android-device-or-emulator>
```

Verify:
- Key creation works (Ed25519 key appears in Android Keystore)
- Biometric prompt appears on sign()
- Sign/verify round-trip succeeds

---

# Step 7: Implement iOS Keychain Ed25519 key provider

## 7.1 Create Swift key provider

File: `keri/keri_ios/ios/Classes/KeriKeyProvider.swift`

```swift
import Foundation
import Security
import LocalAuthentication

@available(iOS 13.0, *)
public class KeriKeyProvider {

    private static let service = "org.humancolossus.keri"

    // Ed25519 is not in Secure Enclave, so we store the encrypted seed
    // in Keychain with biometric-gated access control.

    public static func createKey(label: String) throws -> Data {
        // Generate Ed25519 key pair
        let seed = generateRandomBytes(count: 32)
        let privateKey = try Ed25519PrivateKey.from(seed: seed)
        let publicKey = privateKey.publicKey

        // Encrypt seed with device key
        let encryptedSeed = try encryptSeed(seed, label: label)

        // Store in Keychain with biometric access control
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .biometryAny,
            nil
        )!

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "keri_\(label)",
            kSecValueData as String: encryptedSeed,
            kSecAttrAccessControl as String: access,
        ] as [String: Any]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeriError.keychainError("Failed to store key: \(status)")
        }

        // Also store public key (unencrypted) for quick access
        let pubQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(service).pub",
            kSecAttrAccount as String: "keri_\(label)",
            kSecValueData as String: publicKey.rawBytes,
        ]
        SecItemAdd(pubQuery as CFDictionary, nil)

        return publicKey.rawBytes
    }

    public static func getPublicKey(label: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(service).pub",
            kSecAttrAccount as String: "keri_\(label)",
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeriError.keyNotFound(label)
        }
        return data
    }

    public static func sign(label: String, message: Data) throws -> Data {
        // Authenticate with biometrics first
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw KeriError.biometryNotAvailable
        }

        // Read encrypted seed from Keychain
        let encryptedSeed = try readSeedFromKeychain(label: label)

        // Decrypt seed
        let seed = try decryptSeed(encryptedSeed, label: label)
        defer {
            // Zeroize seed from memory
            seed.withUnsafeMutableBytes { ptr in
                memset(ptr.baseAddress, 0, ptr.count)
            }
        }

        // Sign with Ed25519
        let privateKey = try Ed25519PrivateKey.from(seed: seed)
        let signature = try privateKey.sign(message: message)
        return signature
    }

    public static func deleteKey(label: String) throws {
        let queries: [[String: Any]] = [
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: "keri_\(label)",
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "\(service).pub",
                kSecAttrAccount as String: "keri_\(label)",
            ],
        ]
        for query in queries {
            SecItemDelete(query as CFDictionary)
        }
    }

    public static func listKeys() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(service).pub",
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &result)
        guard let items = result as? [[String: Any]] else { return [] }
        return items.compactMap { item in
            (item[kSecAttrAccount as String] as? String)?
                .replacingOccurrences(of: "keri_", with: "")
        }
    }

    // MARK: - Private helpers

    private static func generateRandomBytes(count: Int) -> Data {
        var bytes = Data(count: count)
        bytes.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
        }
        return bytes
    }

    private static func encryptSeed(_ seed: Data, label: String) throws -> Data {
        // Use CryptoKit or CommonCrypto to encrypt with a device-specific key
        // This is a simplified placeholder — use AES-GCM with a key derived
        // from the device's Secure Enclave via SecKeyCreateDecrypted
        // or use the Security framework's secure enclave key for wrapping.

        // For production: use a Secure Enclave-backed key to wrap the seed.
        // For now: use AES-256-GCM with a key derived from the device UDID.
        fatalError("Implement seed encryption using CryptoKit AES-GCM or Secure Enclave key wrapping")
    }

    private static func decryptSeed(_ data: Data, label: String) throws -> Data {
        // Reverse of encryptSeed
        fatalError("Implement seed decryption")
    }

    private static func readSeedFromKeychain(label: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "keri_\(label)",
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeriError.keyNotFound(label)
        }
        return data
    }
}

enum KeriError: Error {
    case keyNotFound(String)
    case biometryNotAvailable
    case keychainError(String)
}
```

**IMPORTANT:** The `encryptSeed` / `decryptSeed` methods are placeholders.
For production, use one of:
1. **CryptoKit AES-GCM** with a key stored in the Secure Enclave via `SecKeyCreateRandomKey`
2. **SecKeyCreateEncryptedData** / **SecKeyCreateDecryptedData** with a Secure Enclave P-256 key
3. A third-party Ed25519 Swift library (e.g. `swift-ed25519` or `SignalCrypto`)

## 7.2 Update iOS plugin Dart implementation

File: `keri/keri_ios/lib/keri_ios.dart`

```dart
import 'dart:ffi';
import 'dart:io';

import 'package:keri_platform_interface/keri_platform_interface.dart';

class KeriIos extends KeriPlatformInterface {
  static void registerWith() {
    KeriPlatformInterface.instance = KeriIos();
  }

  // On iOS, the Rust code is statically linked into the app binary
  static final DynamicLibrary _dylib = DynamicLibrary.process();

  // Replace with generated API class from FRB v2
  // late final _api = KeriDartApi(_dylib);

  // Implement all methods by delegating to _api
  // Key provider calls go through MethodChannel to Swift
}
```

## 7.3 Test on iOS

```bash
cd keri/keri
flutter run -d <ios-device-or-simulator>
```

Verify:
- Key creation works (encrypted seed in Keychain)
- Face ID / Touch ID prompt appears on sign()
- Sign/verify round-trip succeeds

---

# Step 8: Wire host key provider callbacks through FRB v2

This step connects the Dart-side platform keystores to the Rust
`HostCallbackKeyProvider` via FRB v2's callback mechanism.

## 8.1 FRB v2 callback registration pattern

The Rust `api.rs` already defines `register_key_provider()` which accepts
5 closures. In FRB v2, these closures can be Dart functions.

After running `flutter_rust_bridge_codegen generate`, the generated Dart
API will expose `registerKeyProvider()` with Dart function parameters.

## 8.2 Android wiring

In `keri_android/lib/keri_android.dart`:

```dart
import 'package:flutter/services.dart';

class KeriAndroid extends KeriPlatformInterface {
  static const _channel = MethodChannel('com.thclab.keri_android');

  late final KeriDartApi _api;  // generated by FRB v2

  KeriAndroid() {
    final dylib = DynamicLibrary.open('libdartkeriox.so');
    _api = KeriDartApi(dylib);
  }

  Future<void> init(String dbPath) async {
    _api.registerKeyProvider(
      createKey: (label, algo) async {
        final pk = await _channel.invokeMethod<Uint8List>('createKey', {
          'label': label,
          'algo': algo,
        });
        return pk!;
      },
      openKey: (label) async {
        final pk = await _channel.invokeMethod<Uint8List>('openKey', {
          'label': label,
        });
        return pk!;
      },
      sign: (label, message) async {
        final sig = await _channel.invokeMethod<Uint8List>('sign', {
          'label': label,
          'message': message,
        });
        return sig!;
      },
      deleteKey: (label) async {
        await _channel.invokeMethod('deleteKey', {'label': label});
      },
      listKeys: () async {
        final keys = await _channel.invokeMethod<List>('listKeys');
        return keys!.cast<String>();
      },
    );
  }
}
```

The Kotlin `MethodChannel` handler in the Android plugin:

```kotlin
class KeriAndroidPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "createKey" -> {
                val label = call.argument<String>("label")!!
                val pk = KeriKeyProvider.createKey(label)
                result.success(pk)
            }
            "openKey" -> {
                val label = call.argument<String>("label")!!
                val pk = KeriKeyProvider.getPublicKey(label)
                result.success(pk)
            }
            "sign" -> {
                val label = call.argument<String>("label")!!
                val message = call.argument<ByteArray>("message")!!
                val sig = KeriKeyProvider.sign(label, message)
                result.success(sig)
            }
            "deleteKey" -> {
                val label = call.argument<String>("label")!!
                KeriKeyProvider.deleteKey(label)
                result.success(null)
            }
            "listKeys" -> {
                val keys = KeriKeyProvider.listKeys()
                result.success(keys)
            }
            else -> result.notImplemented()
        }
    }
}
```

**Note on biometric signing:** For the biometric prompt flow, the `sign`
MethodChannel call should use the `BiometricHelper` class instead of
calling `KeriKeyProvider.sign` directly. The biometric prompt is an async
UI operation, so the MethodChannel result must be returned from the
biometric callback, not synchronously.

## 8.3 iOS wiring

Same pattern as Android, but the MethodChannel calls go to Swift.

## 8.4 Desktop wiring (macOS/Windows)

For desktop, use a `SoftwareKeyProvider` in pure Dart:

```dart
import 'package:cryptography/cryptography.dart';

class SoftwareKeyProvider {
  final Ed25519 _ed25519 = Ed25519();
  final Map<String, KeyPair> _keys = {};

  Future<Uint8List> createKey(String label, String algo) async {
    final keyPair = await _ed25519.newKeyPair();
    _keys[label] = keyPair;
    final publicKey = await keyPair.extractPublicKey();
    return publicKey.bytes;
  }

  Future<Uint8List> sign(String label, Uint8List message) async {
    final keyPair = _keys[label]!;
    final signature = await _ed25519.sign(message, keyPair: keyPair);
    return signature.bytes;
  }
}
```

## 8.5 End-to-end verification

After wiring everything:

1. Build the Rust library for your platform
2. Run `flutter pub get` in all packages
3. Run `flutter test` in `keri/keri`
4. Run `flutter run` on a real device
5. Test the full flow:
   - Create identifier (triggers key creation in keystore)
   - Sign data (triggers biometric prompt on mobile)
   - Verify the signature
   - Rotate keys
   - Incept registry, issue credential, check credential status

---

# Build commands reference

## Android
```bash
# Build Rust .so files
cargo ndk -t arm64-v8a -t x86_64 \
  -o bindings/dart/keri/keri_android/android/src/main/jniLibs \
  build --release --manifest-path bindings/dart/Cargo.toml

# Build Flutter
cd bindings/dart/keri/keri_example
flutter build apk
```

## iOS
```bash
# Build Rust .a files
cargo lipo --release --manifest-path bindings/dart/Cargo.toml

# Copy to iOS plugin
cp target/universal/release/libdartkeriox.a \
   bindings/dart/keri/keri_ios/ios/

# Build Flutter
cd bindings/dart/keri/keri_example
flutter build ios
```

## FRB v2 code generation
```bash
cd bindings/dart
flutter_rust_bridge_codegen generate
```

## Run tests
```bash
# Rust tests
cargo test --manifest-path bindings/dart/Cargo.toml

# Flutter tests
cd bindings/dart/keri/keri
flutter test
```
