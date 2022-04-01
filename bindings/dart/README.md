Setup: http://cjycode.com/flutter_rust_bridge/tutorial_with_flutter.html#optional-run-generator

To generate dart bindings: `flutter_rust_bridge_codegen --rust-input src/api.rs --dart-output dart-part/lib/bridge_generated.dart --c-output ios/Runner/bridge_generated.h`

To build so files:

`export ANDROID_NDK_HOME="$HOME/path/to/ndk"`

`cargo ndk -o ./jniLibs build`