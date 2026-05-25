#!/bin/bash
sudo mn -c > /dev/null 2>&1
exec sudo -E python3 "$(dirname "$0")/topology.py" --cc bbr
