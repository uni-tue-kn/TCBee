#!/bin/bash
# Runs the rust program as sudo, needed privileges
RUST_LOG=debug cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
