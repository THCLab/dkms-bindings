# Overview

Go client for managing KERI based Identifiers. See top level [README](https://github.com/THCLab/dkms-bindings) to get acquainted with more generic overview and client features.

# Installation

Pre-built native libraries for Linux, macOS, and Windows are committed to this
repository and downloaded automatically by `go get`. No Rust toolchain required.

```bash
go get github.com/THCLab/dkms-bindings/bindings/go
```

Then build your application with CGo enabled (the default):

```bash
CGO_ENABLED=1 go build .
```

## Building from source

If you want to build the native library yourself (e.g. to use a local Rust change):

```bash
git clone https://github.com/THCLab/dkms-bindings
cd dkms-bindings/bindings/go
make build
```

## Examples

Five complete examples live under `examples/`:

- `simple`: basic identifier creation, key generation, and KEL retrieval.
- `signing`: data signing and verification with CESR-encoded signatures, including tamper detection.
- `rotation`: the pre-rotation key rotation workflow and key continuity.
- `multisig`: a multi-signature identifier built from multiple current and next keys.
- `credentials`: the full verifiable credential lifecycle, covering registry creation, issuance, status queries, and revocation.

### Prerequisites

- Go 1.16 or later with CGO enabled.
- A Rust toolchain. The `make` targets build the native library before the examples run.
- A running PostgreSQL instance. Every example stores its KEL and TEL events in Postgres and reads the connection string from the `DATABASE_URL` environment variable.
- A witness and a watcher, required only by the `credentials` example. The other four use a witness threshold of zero and need only Postgres.

The repository ships a `docker-compose.yml` that provides Postgres, a witness, and a watcher. Start Postgres with:

```bash
docker compose up -d postgres
```

### Running all examples

The `examples` target builds the native library and then runs all five examples in sequence. The `cargo` command must be on your PATH, so source the Rust environment first:

```bash
source "$HOME/.cargo/env"
make examples DATABASE_URL="postgres://postgres:postgres@localhost:5432/keri_go"
```

A succesful credentials run ends with the credential status changing from issued to revoked.

### Running a single example

Each example is its own package, so run it with `go run .` rather than `go run main.go`, because some examples have more than one source file:

```bash
cd examples/simple
DATABASE_URL="postgres://postgres:postgres@localhost:5432/keri_go" go run .
```

The native library is located through the rpath embedded at build time. If your loader does not pick it up, set `LD_LIBRARY_PATH` to the `bindings/go` directory that holds `libdkms_go.so`.

### Witness and watcher for the credentials example

The `credentials` example incepts an identifier backed by a witness, publishes its events, and uses a watcher to read another identifier's KEL and TEL. It reads the witness and watcher OOBIs from the `WITNESS_OOBI` and `WATCHER_OOBI` environment variables and falls back to the localhost defaults `http://localhost:3232/` and `http://localhost:3236/` when they are not set.

The witness and watcher must be compatible with the keriox version that `keri-sdk` is pinned to in `Cargo.toml`. Two ways to provide them are described below. Either way they must run on ports 3232 (witness) and 3236 (watcher), and the `credentials` example expects the witness identifier `BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC` and the watcher identifier `BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b`. Those identifiers are produced by the fixed seeds shown below, so as long as you use those seeds you do not need to set `WITNESS_OOBI` or `WATCHER_OOBI`.

#### Option A: docker-compose images

The provided `docker-compose.yml` defines `witness` and `watcher` services. This is the simplest path, but it only works when the pinned image tags match the keriox version that `keri-sdk` builds against. If you get a `Missing attachment` error during inception, the images are too old and you must use Option B instead.

When you run the witness and watcher from `docker-compose.yml`, they must advertise a URL the host can reach. Set the public URLs before starting them, otherwise their OOBIs point at the internal `witness` hostname, which is only resolvable inside Docker:

```bash
WITNESS_PUBLIC_URL=http://localhost:3232/ \
WATCHER_PUBLIC_URL=http://localhost:3236/ \
docker compose up -d --force-recreate witness watcher
```

#### Option B: build the witness and watcher from the keriox source

Use this when the compose images do not match the pinned keriox version. You build the two binaries once from a keriox checkout at the same commit `keri-sdk` points to, then run them as local processes.

First, get the commit. If `keri-sdk` in `Cargo.toml` uses `rev = "..."`, that value is the commit. If it uses `branch = "development"`, the exact commit is recorded in `bindings/go/Cargo.lock` next to `name = "keri-sdk"`. Check out that commit:

```bash
git clone https://github.com/THCLab/keriox
cd keriox
git checkout <commit-from-cargo-lock-or-rev>
```

You need a Rust toolchain. If you do not have one, install it with rustup and load it into your shell:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

The keriox workspace needs three local adjustments before it builds in a standalone checkout. They are temporary and reverted afterwards.

1. The root `Cargo.toml` patches `cesrox` to a sibling path you probably do not have. Comment out the two lines under `[patch.crates-io]` so cargo uses the published crate instead:

   ```toml
   # [patch.crates-io]
   # cesrox = { path = "../cesrox/cesr" }
   ```

2. The witness and watcher link OpenSSL. If you do not have the system OpenSSL development files, add the `openssl` crate with its `vendored` feature so OpenSSL is compiled from source. Add this line under `[dependencies]` in both `components/witness/Cargo.toml` and `components/watcher/Cargo.toml` (the vendored build needs a C compiler, `make`, and `perl`):

   ```toml
   openssl = { version = "0.10", features = ["vendored"] }
   ```

   As an alternative to the vendored crate you can install the system packages instead, for example on Debian or Ubuntu `sudo apt-get install -y libssl-dev pkg-config`, and skip this edit.

3. `actix-web` pulls in `cookie` 0.16, which does not compile against the newest `time` crate. Pin `time` to a compatible release:

   ```bash
   cargo update -p time --precise 0.3.36
   ```

Now build both binaries and revert the manifest edits:

```bash
cargo build --release --package witness --package watcher
git checkout -- Cargo.toml components/witness/Cargo.toml components/watcher/Cargo.toml
```

Run them as background processes. The seeds match the ones in `docker-compose.yml` and produce the identifiers the `credentials` example expects. Pick any writable directories for storage:

```bash
WORK=/tmp/keri-rt
mkdir -p "$WORK/wdb" "$WORK/watchdb" "$WORK/wtel"

nohup ./target/release/witness \
  -c components/witness/witness.yml -d "$WORK/wdb" -p 3232 \
  -u http://localhost:3232/ \
  -s ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc \
  --admin-port 9100 > "$WORK/witness.log" 2>&1 &

nohup ./target/release/watcher \
  -c components/watcher/watcher.yml -d "$WORK/watchdb" -t "$WORK/wtel" -p 3236 \
  -u http://localhost:3236/ \
  -s Alntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8 \
  --admin-port 9101 > "$WORK/watcher.log" 2>&1 &
```

Confirm the witness answers and advertises a localhost URL:

```bash
curl -s http://localhost:3232/oobi/BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC
```

Once both are running, run the examples as described above. To stop them later:

```bash
pkill -f 'target/release/witness'
pkill -f 'target/release/watcher'
```

See [examples/README.md](./examples/README.md) for a description of each example.

# Memory Management

The Go bindings use CGO to interface with the Rust library. All objects (`Controller`, `Identifier`, `InceptionConfig`, `RotationConfig`) register a GC finalizer on creation, so Rust-side memory is freed automatically when the Go object is collected. No manual cleanup is needed.

For deterministic release (e.g. closing a database connection immediately), call `Free()` explicitly. The finalizer will then become a no-op.

# Thread Safety

The underlying Rust implementation uses an async tokio runtime. Each call from Go enters that runtime to handle the async operations. While this works, be aware that heavy concurrent usage may have performance implications.

# Requirements

- Go 1.16 or later
- Rust 1.70 or later (for building the library)
- CGO enabled (set `CGO_ENABLED=1`)
