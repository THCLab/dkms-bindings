# keri_platform_interface

Pure-Dart interface for the `keri` federated plugin. Re-exports the
`flutter_rust_bridge` v2 generated bindings — `KeriMobileSdk`, `RustLib`, the
`Ffi*Config` types — so platform implementations (`keri_android`, future
`keri_ios`, etc.) can depend on a single, generated API surface.

This package contains no platform code. The generated files live under
`lib/src/generated/` and are produced by `flutter_rust_bridge_codegen` against
`bindings/dart/src/api.rs`. See the
[top-level bindings README](../../README.md#regenerating-the-frb-bindings)
for how to regenerate.

End users should depend on [`keri`](../keri) rather than this package
directly.
