#!/usr/bin/env bash
# Two-path MPTCP test of tcbee-record. Needs root, iproute2 with `ip mptcp` and a kernel with
# MPTCP. Builds two network namespaces joined by two veth pairs (the paths), records one MPTCP
# and one plain TCP connection with -k -m and checks the recording with check_trace.py.
#
#   sudo testing/mptcp/run.sh [SECONDS]
#
# TCBEE_RECORD overrides the recorder binary. The recording stays in $OUT (default
# /tmp/tcbee-mptcp-test). If the SQLite build of tcbee-process exists (TCBEE_PROCESS, default
# target/release/tcbee-process), the recording is also processed and the database checked.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
RECORD=${TCBEE_RECORD:-$ROOT/tcbee-record/target/release/tcbee-record}
PROCESS=${TCBEE_PROCESS:-$ROOT/target/release/tcbee-process}
OUT=${OUT:-/tmp/tcbee-mptcp-test}
SECONDS_TRAFFIC=${1:-3}
CLIENT=tcbee-mptcp-client
SERVER=tcbee-mptcp-server
MPTCP_PORT=5501
TCP_PORT=5502

cleanup() {
    ip netns pids "$SERVER" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$CLIENT" 2>/dev/null || true
    ip netns del "$SERVER" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

in_client() { ip netns exec "$CLIENT" "$@"; }
in_server() { ip netns exec "$SERVER" "$@"; }

ip netns add "$CLIENT"
ip netns add "$SERVER"
# Path 1: 10.31.1.0/24, path 2: 10.31.2.0/24
for path in 1 2; do
    ip link add "c$path" netns "$CLIENT" type veth peer name "s$path" netns "$SERVER"
    in_client ip addr add "10.31.$path.1/24" dev "c$path"
    in_server ip addr add "10.31.$path.2/24" dev "s$path"
    in_client ip link set "c$path" up
    in_server ip link set "s$path" up
done
in_client ip link set lo up
in_server ip link set lo up
# The second subflow leaves from 10.31.2.1 towards the server address of path 1
in_client ip rule add from 10.31.2.1 table 102
in_client ip route add 10.31.1.0/24 dev c2 table 102
for ns in "$CLIENT" "$SERVER"; do
    ip netns exec "$ns" sysctl -q net.mptcp.enabled=1
    ip netns exec "$ns" ip mptcp limits set subflow 2 add_addr_accepted 2
done
in_client ip mptcp endpoint add 10.31.2.1 dev c2 subflow

in_server python3 "$HERE/traffic.py" serve "$MPTCP_PORT" mptcp &
in_server python3 "$HERE/traffic.py" serve "$TCP_PORT" tcp &
# cleanup() kills them, the shell does not need to report it
disown -a

rm -rf "$OUT"
mkdir -p "$OUT"
"$RECORD" -q -k -m --ports "$MPTCP_PORT,$TCP_PORT" --poll wait -d "$OUT" \
    --duration $((SECONDS_TRAFFIC + 3)) >"$OUT/record.log" 2>&1 &
RECORDER=$!
sleep 1.5

in_client python3 "$HERE/traffic.py" send 10.31.1.2 "$MPTCP_PORT" mptcp "$SECONDS_TRAFFIC" &
SENDER=$!
in_client python3 "$HERE/traffic.py" send 10.31.1.2 "$TCP_PORT" tcp "$SECONDS_TRAFFIC"
wait "$SENDER"
wait "$RECORDER"

TRACE=$(ls -d "$OUT"/tcbee_* | tail -1)
echo "Recording: $TRACE"
DB=()
if [ -x "$PROCESS" ]; then
    "$PROCESS" -s "$TRACE" -o "$OUT/mptcp.sqlite" -f
    DB=("$OUT/mptcp.sqlite")
fi
python3 "$HERE/check_trace.py" "$TRACE" "$MPTCP_PORT" "$TCP_PORT" "${DB[@]}"
