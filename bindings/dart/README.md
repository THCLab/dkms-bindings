# Building bindings

## Getting `*.dart` headers
- `cargo install -f flutter_rust_bridge_codegen`
- Follow and proceed with http://cjycode.com/flutter_rust_bridge/tutorial_with_flutter.html#optional-run-generator
- Run `flutter_rust_bridge_codegen --rust-input src/api.rs --dart-output dart-part/lib/bridge_generated.dart --c-output ios/Runner/bridge_generated.h`


## Building Android

- `export ANDROID_NDK_HOME="$HOME/path/to/ndk"`
- `cargo ndk -o ./jniLibs build`

## Building Windows or Linux

- `cargo install cross --git https://github.com/cross-rs/cross`
- `cross build --target aarch64-unknown-linux-gnu` for Linux
- `cross build --target x86_64-pc-windows-gnu` for Windows

See also other (supported targets)[https://github.com/cross-rs/cross#supported-targets].
