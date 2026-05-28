# keri_macos

macOS implementation of the `keri` Flutter plugin.

**Status: not implemented yet.** Stub package present so the federated plugin
resolution doesn't complain on macOS hosts.

The natural design is to share the Swift host key provider with `keri_ios`,
substituting macOS Keychain for iOS Keychain and Secure Enclave on Apple
silicon for the hardware-backed P-256 path.
