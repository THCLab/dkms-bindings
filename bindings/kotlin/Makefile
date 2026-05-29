.PHONY: rust bindgen sdk app install clean

CRATE_DIR := keri-kotlin
SDK_DIR := keri-android-sdk
JNI_DIR := $(SDK_DIR)/src/main/jniLibs
KOTLIN_OUT := $(SDK_DIR)/src/main/java
LIB := $(CRATE_DIR)/target/release/libuniffi_keri.so

# Cross-compile the Rust .so for the two supported Android ABIs.
# Requires `cargo-ndk` and a working Android NDK (set ANDROID_NDK_HOME).
rust:
	cd $(CRATE_DIR) && cargo ndk -t arm64-v8a -t x86_64 \
		-o ../$(JNI_DIR) build --release

# Generate Kotlin bindings from the host-target .so. We do a separate host
# build so uniffi-bindgen can read the metadata regardless of the cross-built
# Android artifacts' readability.
bindgen:
	cd $(CRATE_DIR) && cargo build --release
	cd $(CRATE_DIR) && cargo run --release --bin uniffi-bindgen -- \
		generate --library target/release/libuniffi_keri.so \
		--language kotlin --out-dir ../$(KOTLIN_OUT) \
		--config uniffi.toml

sdk: rust bindgen
	./gradlew :keri-android-sdk:assembleRelease

app: sdk
	./gradlew :example-app:assembleDebug

install: app
	./gradlew :example-app:installDebug

clean:
	cargo clean --manifest-path $(CRATE_DIR)/Cargo.toml
	./gradlew clean || true
	rm -rf $(JNI_DIR) $(KOTLIN_OUT)/uniffi
