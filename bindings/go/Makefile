.PHONY: build clean test install download-lib

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LIB_NAME := libdkms_go.so
    ASSET_NAME := libdkms_go-linux-x86_64.so
endif
ifeq ($(UNAME_S),Darwin)
    LIB_NAME := libdkms_go.dylib
    ASSET_NAME := libdkms_go-macos-aarch64.dylib
endif
ifeq ($(OS),Windows_NT)
    LIB_NAME := dkms_go.dll
    ASSET_NAME := dkms_go-windows-x86_64.dll
endif

# GitHub release settings — used by download-lib
GITHUB_REPO := THCLab/dkms-bindings
VERSION     ?= latest

# Cargo build settings
CARGO := cargo
CARGO_BUILD_FLAGS := --release

# Go settings
GO := go
GO_BUILD_FLAGS := -v

all: build

# Download the pre-built native library for the current platform from GitHub Releases.
# Use this if you don't have Rust installed.
# Override version with: make download-lib VERSION=go-v1.2.3
download-lib:
ifeq ($(VERSION),latest)
	curl -fsSL -o $(LIB_NAME) \
	  https://github.com/$(GITHUB_REPO)/releases/latest/download/$(ASSET_NAME)
else
	curl -fsSL -o $(LIB_NAME) \
	  https://github.com/$(GITHUB_REPO)/releases/download/$(VERSION)/$(ASSET_NAME)
endif
	@echo "Downloaded $(LIB_NAME)"

# Build the Rust library
build-rust:
	$(CARGO) build $(CARGO_BUILD_FLAGS)
	cp target/release/$(LIB_NAME) .

# Build Go bindings
build-go: build-rust
	CGO_ENABLED=1 $(GO) build $(GO_BUILD_FLAGS)

# Build everything
build: build-go

# Clean build artifacts
clean:
	$(CARGO) clean
	rm -f $(LIB_NAME)
	rm -f *.so *.dylib *.dll
	$(GO) clean

# Run tests — requires DATABASE_URL env var
# e.g.: make test DATABASE_URL=postgres://postgres:postgres@localhost/keri_go_test
test: build-rust
	CGO_ENABLED=1 $(GO) test -v .

# Run all examples — requires DATABASE_URL env var
# e.g.: make examples DATABASE_URL=postgres://postgres:postgres@localhost/keri_go
examples: build-rust
	@echo "Running simple example..."
	@cd examples/simple && DATABASE_URL=$(DATABASE_URL) $(GO) run .
	@echo ""
	@echo "Running signing example..."
	@cd examples/signing && DATABASE_URL=$(DATABASE_URL) $(GO) run .
	@echo ""
	@echo "Running anchor example..."
	@cd examples/anchor && DATABASE_URL=$(DATABASE_URL) $(GO) run .
	@echo ""
	@echo "Running rotation example..."
	@cd examples/rotation && DATABASE_URL=$(DATABASE_URL) $(GO) run .
	@echo ""
	@echo "Running multisig example..."
	@cd examples/multisig && DATABASE_URL=$(DATABASE_URL) $(GO) run .
	@echo ""
	@echo "Running credentials example..."
	@cd examples/credentials && DATABASE_URL=$(DATABASE_URL) $(GO) run .
	@echo ""
	@echo "Running restart example..."
	@cd examples/restart && DATABASE_URL=$(DATABASE_URL) $(GO) run .

# Run tests and examples
test-all: test examples

# Install the library to system location (optional)
install: build-rust
ifeq ($(UNAME_S),Linux)
	sudo cp $(LIB_NAME) /usr/local/lib/
	sudo ldconfig
endif
ifeq ($(UNAME_S),Darwin)
	sudo cp $(LIB_NAME) /usr/local/lib/
endif

# Format code
fmt:
	$(CARGO) fmt
	$(GO) fmt ./...

# Run clippy for Rust code
clippy:
	$(CARGO) clippy -- -D warnings

# Check Go code
check-go:
	$(GO) vet ./...

# Run all checks
check: clippy check-go

# Generate documentation
doc:
	$(CARGO) doc --no-deps --open
	$(GO) doc -all

# Help target
help:
	@echo "Available targets:"
	@echo "  build        - Build both Rust library and Go bindings (default)"
	@echo "  build-rust   - Build only the Rust library (requires Rust)"
	@echo "  build-go     - Build Go bindings (includes build-rust)"
	@echo "  download-lib - Download pre-built native library from GitHub Releases"
	@echo "                 Override version: make download-lib VERSION=go-v1.2.3"
	@echo "  clean        - Remove build artifacts"
	@echo "  test         - Run tests"
	@echo "  examples     - Run all examples"
	@echo "  test-all     - Run tests and examples"
	@echo "  install      - Install library to system location"
	@echo "  fmt          - Format Rust and Go code"
	@echo "  clippy       - Run Rust clippy linter"
	@echo "  check-go     - Run Go vet"
	@echo "  check        - Run all linters"
	@echo "  doc          - Generate documentation"
	@echo "  help         - Show this help message"
