#!/usr/bin/env bash
# Regenerates Rust kernel struct bindings from the running kernel's BTF.
#
# Run this script on the machine whose kernel you want to support whenever
# the kernel is updated. Requires: aya-tool, bpftool
#
# Usage: ./scripts/regenerate-bindings.sh

set -euo pipefail

BINDINGS_DIR="tcbee-record/tcbee-common/src/bindings"

# ---- Helpers ----------------------------------------------------------------

require() {
    if ! command -v "$1" &>/dev/null; then
        echo "Error: $1 not found. Install with: $2"
        exit 1
    fi
}

btf_has_struct() {
    local btf_file=$1
    local struct_name=$2
    bpftool btf dump file "$btf_file" 2>/dev/null | grep -q "\"$struct_name\""
}

find_struct_btf() {
    local struct_name=$1
    local module_name=$2

    # Check vmlinux first
    if btf_has_struct /sys/kernel/btf/vmlinux "$struct_name"; then
        echo "/sys/kernel/btf/vmlinux"
        return
    fi

    # Check module BTF if provided
    if [[ -n "$module_name" && -f "/sys/kernel/btf/$module_name" ]]; then
        if btf_has_struct "/sys/kernel/btf/$module_name" "$struct_name"; then
            echo "/sys/kernel/btf/$module_name"
            return
        fi
    fi

    echo ""
}

# ---- Checks -----------------------------------------------------------------

require aya-tool "cargo install aya-tool"
require bpftool  "apt install linux-tools-common  (or distro equivalent)"

if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    echo "Error: /sys/kernel/btf/vmlinux not found."
    echo "Your kernel must be built with CONFIG_DEBUG_INFO_BTF=y."
    exit 1
fi

# ---- vmlinux structs (tcp_sock, sock, inet_connection_sock) -----------------

echo "Generating tcp_sock bindings from vmlinux BTF..."
aya-tool generate \
    tcp_sock \
    sock \
    inet_connection_sock \
    sk_buff \
    > "$BINDINGS_DIR/tcp_sock_generated.rs"
echo "  -> $BINDINGS_DIR/tcp_sock_generated.rs"

# ---- BBR struct -------------------------------------------------------------

echo "Locating BBR struct BTF..."
BBR_BTF=$(find_struct_btf "bbr" "tcp_bbr")

if [[ -z "$BBR_BTF" ]]; then
    echo "  WARNING: struct bbr not found in BTF."
    echo "  BBR may not be loaded. Skipping bbr regeneration."
else
    echo "  Found in: $BBR_BTF"
    aya-tool generate --btf "$BBR_BTF" bbr minmax minmax_sample \
        > "$BINDINGS_DIR/bbr_generated.rs" 2>/dev/null || \
    bpftool btf dump file "$BBR_BTF" format c \
        | grep -A 50 "struct bbr\|struct minmax" \
        > "$BINDINGS_DIR/bbr_structs.h" && \
        bindgen "$BINDINGS_DIR/bbr_structs.h" \
            --no-layout-tests --use-core \
            > "$BINDINGS_DIR/bbr_generated.rs"
    echo "  -> $BINDINGS_DIR/bbr_generated.rs"
fi

# ---- CUBIC struct -----------------------------------------------------------

echo "Locating CUBIC struct BTF..."
CUBIC_BTF=$(find_struct_btf "bictcp" "tcp_cubic")

if [[ -z "$CUBIC_BTF" ]]; then
    echo "  WARNING: struct bictcp not found in BTF."
    echo "  CUBIC may not be loaded. Skipping cubic regeneration."
else
    echo "  Found in: $CUBIC_BTF"
    aya-tool generate --btf "$CUBIC_BTF" bictcp \
        > "$BINDINGS_DIR/cubic_generated.rs" 2>/dev/null || \
    bpftool btf dump file "$CUBIC_BTF" format c \
        | grep -A 30 "struct bictcp" \
        > "$BINDINGS_DIR/cubic_structs.h" && \
        bindgen "$BINDINGS_DIR/cubic_structs.h" \
            --no-layout-tests --use-core \
            > "$BINDINGS_DIR/cubic_generated.rs"
    echo "  -> $BINDINGS_DIR/cubic_generated.rs"
fi

# ---- Summary ----------------------------------------------------------------

echo ""
echo "Done. Review generated files and update the corresponding"
echo "hand-written bindings in $BINDINGS_DIR/ if field offsets have changed."
echo ""
echo "Verify offsets with:"
echo "  pahole -C tcp_sock /sys/kernel/btf/vmlinux"
echo "  pahole -C bbr /sys/kernel/btf/tcp_bbr  (if module)"
