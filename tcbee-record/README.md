# TCBee

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Filtering

By default no filter is enabled, so probes only take the fast no-filter branch.

Use `-p`/`--port` for the fastest filtered mode when you only need one local or remote port:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- -k --port 443
```

For more flexible filtering, use the map-backed filter options:

```shell
--ports 80,443
--src-ports 12345
--dst-ports 443
--ips 10.0.0.1,2001:db8::1
--src-ips 10.0.0.10
--dst-ips 10.0.0.20
```

Ports and IPs are exact matches. `--ports` and `--ips` match either source or destination;
the `src`/`dst` variants require that direction. Values inside the same option are ORed.
Different dimensions are ANDed, so `--ports 80,443 --ips 10.0.0.1` records traffic where
either endpoint port is 80 or 443 and either endpoint IP is `10.0.0.1`.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package tcpprobe --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/tcpprobe` can be
copied to a Linux server or VM and run there.
