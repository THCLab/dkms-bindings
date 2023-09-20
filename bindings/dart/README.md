# Building bindings

## Getting `*.dart` headers

Dart files are already generated and can be found in [`bindings/dart/keri/keri/lib`](https://github.com/THCLab/keri-bindings/tree/master/bindings/dart/keri/keri/lib) folder.
Whenever you make changes to `api.rs`, it's necessary to rerun the code generation.

Install `flutter_rust_bridge_codegen` with 
- `cargo install flutter_rust_bridge_codegen`

For more details checkout [`flutter_rust_bridge` user guide](https://cjycode.com/flutter_rust_bridge/integrate/deps.html)

To generate `.dart` files, run following commands in the `bindings/dart/keri/keri` folder:
- `flutter pub get`
- `flutter_rust_bridge_codegen --rust-input ../../src/api.rs --dart-output ./lib/bridge_generated.dart --c-output ./lib/bridge_generated.h`

## Building Android

In the `bindings/dart` folder run: 
- `export ANDROID_NDK_HOME="$HOME/path/to/ndk"`
- `cargo ndk -o <output_folder> build --release`

## Building Windows or Linux

- `cargo install cross --git https://github.com/cross-rs/cross`
- `cross build --target aarch64-unknown-linux-gnu` for Linux
- `cross build --target x86_64-pc-windows-gnu` for Windows

See also other (supported targets)[https://github.com/cross-rs/cross#supported-targets].
