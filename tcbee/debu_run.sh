#!/bin/bash
RUST_LOG=debug cargo run --release --config 'target."cfg(all())".runner="sudo -E"'  -- -q lo
