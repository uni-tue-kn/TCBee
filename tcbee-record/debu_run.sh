#!/bin/bash
RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'  -- -q lo
