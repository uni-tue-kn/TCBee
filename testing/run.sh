#!/bin/bash
# Run the topology script as root while preserving $DISPLAY and other
# GUI-related environment variables needed by tcbee-live.
exec sudo -E python3 "$(dirname "$0")/topology.py" "$@"
