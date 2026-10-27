#!/usr/bin/env bash
# Checks that the default eBPF programs compile to the same code as in a baseline commit.
#
#   testing/bpf_identity.sh BASE [PROG,...]
#
# BASE is e.g. the commit a branch started from; the listed programs may differ, for a change
# that alters them on purpose (a new record field). Builds tcbee-record at BASE (in a temporary
# worktree) and at the working tree, then compares the disassembly and relocations of the
# default programs one by one: every program of the baseline object that is not declared with
# "?" (the opt-in programs). The baseline build uses its own target directory under
# tcbee-record/target, so only the first run is slow.
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
base=${1:?usage: testing/bpf_identity.sh BASE [PROG,...]}
expected=",${2:-},"

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
# libbpf resolves the relocations by type name and access path, which are compared. Local
# labels (LBB<function>_<block>) are numbered by the function's place in the object, so
# adding a program renumbers the ones after it; jump offsets are compared instead. For the same
# reason the instruction and relocation addresses are left out: a program that grows moves the
# ones after it in its section.
disasm() {
	llvm-objdump -dr --no-show-raw-insn --disassemble-symbols="$2" "$1" |
		grep -v 'file format' |
		sed -E 's/(CO-RE <[a-z0-9_]+>) \[[0-9]+\]/\1 [id]/; s/<LBB[0-9]+_([0-9]+)>/<LBB_\1>/' |
		sed -E 's/^ *[0-9a-f]+:\t//; s/^\t\t[0-9a-f]+:  /\t\t/; s/^[0-9a-f]{16} </</'
}

base_obj=$(object "$repo/tcbee-record/target/bpf-identity")
new_obj=$(object "$repo/tcbee-record/target/release")
# Function symbols: address, binding, F, section, size, name
progs=$(llvm-objdump -t "$base_obj" | awk '$3 == "F" && $4 !~ /^\?/ { print $6 }')
same=0 instructions=0 failed=0
for prog in $progs; do
	disasm "$base_obj" "$prog" >"$tmp/base.txt"
	disasm "$new_obj" "$prog" >"$tmp/new.txt"
	if diff -u "$tmp/base.txt" "$tmp/new.txt" >"$tmp/diff.txt"; then
		same=$((same + 1))
		instructions=$((instructions + $(grep -c '^ *[a-z]' "$tmp/new.txt" || true)))
	elif [[ $expected == *",$prog,"* ]]; then
		echo "$prog differs, as expected"
	else
		cat "$tmp/diff.txt"
		echo "$prog differs from $base" >&2
		failed=1
	fi
done
if ((failed)); then
	exit 1
fi
echo "default programs identical to $base ($same programs, $instructions lines)"
