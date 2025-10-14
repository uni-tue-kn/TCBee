#!/bin/bash
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'  -- enp52s0f4u1u1 --headers
