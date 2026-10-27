#!/bin/bash
# Processes the latest recording in /tmp/ into ./db.sqlite, replacing an existing file.
RUST_LOG=debug cargo run --release -- --output ./db.sqlite --sqlite --force
