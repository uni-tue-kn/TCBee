#!/bin/bash
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'  -- ens16np0
