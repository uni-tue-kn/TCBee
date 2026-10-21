#!/usr/bin/env bash
# Checks that the default eBPF programs compile to the same code as in a baseline commit.
#
#   testing/bpf_identity.sh BASE      e.g. the commit a branch started from
#
# Builds tcbee-record at BASE (in a temporary worktree) and at the working tree, then compares
# the disassembly and relocations of the default socket and cwnd programs. The baseline build
# uses its own target directory under tcbee-record/target, so only the first run is slow.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
base=${1:?usage: testing/bpf_identity.sh BASE}
progs=sock_sendmsg,sock_recvmsg,cwnd_sock_sendmsg,cwnd_sock_recvmsg

tmp=$(mktemp -d)
cleanup() {
	git -C "$repo" worktree remove --force "$tmp/base" >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT

git -C "$repo" worktree add --detach "$tmp/base" "$base" >/dev/null 2>&1
# Build scripts before the one-line .obj() keep no object; patch them the same way
build_rs="$tmp/base/tcbee-record/tcbee/build.rs"
grep -q '\.obj(' "$build_rs" ||
	sed -i 's|^\( *\)\.source(BPF_SRC)|&\n\1.obj(out.join("tcbee.bpf.o"))|' "$build_rs"

# The newest tcbee.bpf.o under a target directory
object() {
	find "$1" -path '*/build/tcbee-*/out/tcbee.bpf.o' -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2
}

CARGO_TARGET_DIR="$repo/tcbee-record/target/bpf-identity" \
	cargo build --quiet --release --manifest-path "$tmp/base/tcbee-record/Cargo.toml" -p tcbee
cargo build --quiet --release --manifest-path "$repo/tcbee-record/Cargo.toml" -p tcbee

# BTF type ids in the CO-RE relocation notes shift whenever a type is added to the object;
# libbpf resolves the relocations by type name and access path, which are compared.
disasm() {
	llvm-objdump -dr --no-show-raw-insn --disassemble-symbols="$progs" "$1" |
		grep -v 'file format' | sed -E 's/(CO-RE <[a-z_]+>) \[[0-9]+\]/\1 [id]/'
}

disasm "$(object "$repo/tcbee-record/target/bpf-identity")" >"$tmp/base.txt"
disasm "$(object "$repo/tcbee-record/target/release")" >"$tmp/new.txt"
if diff -u "$tmp/base.txt" "$tmp/new.txt"; then
	echo "default programs identical to $base ($(grep -c '^ *[0-9a-f]*:' "$tmp/new.txt") instructions)"
else
	echo "default programs differ from $base" >&2
	exit 1
fi
