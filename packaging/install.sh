#!/bin/sh
# Installs the TCBee tools from this release folder, or removes them with --uninstall.
#   sudo ./install.sh                     # to /usr/local/bin
#   sudo PREFIX=/opt/tcbee ./install.sh   # to /opt/tcbee/bin
#   sudo ./install.sh --uninstall
set -eu

PREFIX=${PREFIX:-/usr/local}
BINDIR=${BINDIR:-$PREFIX/bin}
DESTDIR=${DESTDIR:-}
FILES="tcbee tcbee-record tcbee-process tcbee-viz tcbee-live"
SRC=$(cd -- "$(dirname -- "$0")" && pwd)

case "${1:-}" in
    "")
        for f in $FILES; do
            if [ -f "$SRC/$f" ]; then
                echo "Installing $DESTDIR$BINDIR/$f"
                install -D -m 755 "$SRC/$f" "$DESTDIR$BINDIR/$f"
            fi
        done
        if [ -z "$DESTDIR" ] && [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
            if [ "$(command -v tcbee || true)" != "$BINDIR/tcbee" ]; then
                echo "Note: $BINDIR is not in the PATH that sudo uses, run 'sudo $BINDIR/tcbee ...'"
            fi
        fi
        ;;
    --uninstall)
        for f in $FILES; do
            rm -f "$DESTDIR$BINDIR/$f"
        done
        echo "Removed the TCBee tools from $DESTDIR$BINDIR"
        ;;
    *)
        echo "Usage: $0 [--uninstall]; PREFIX, BINDIR and DESTDIR set the target" >&2
        exit 2
        ;;
esac
