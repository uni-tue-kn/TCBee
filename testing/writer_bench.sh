#!/usr/bin/env bash
# Writer throughput on this machine: tmpfs (no disk) against a disk directory, for 1/2/4
# writer threads and the sock, tcp4 and cwnd records (tcbee-record/tcbee/src/writer_bench.rs).
# No root needed, no eBPF: synthetic records through the writer's storage path.
#
#   testing/writer_bench.sh <disk_dir> [secs=60] [out.jsonl]
#
# Runs must be long enough to fill the page cache up to the dirty limit: the steady MB/s are
# taken after that (dirty_plateau_secs). Every result line gets the machine, the build and the
# target's file system; with fio installed, the disk's sequential write bandwidth (O_DIRECT) is
# measured once as the reference for "the disk is saturated".
#
# The writer core limits recording when writer_cores is near 1 per thread. The disk limits it
# when disk_mbps_steady is near the fio bandwidth while writer_cores stays well below 1. The
# CPU cost per MB of the disk run (writer_ns_per_mb, host_ns_per_mb) is the one to use; tmpfs has
# no file page faults, dirty throttling or writeback. Reading the ring buffers adds to the
# writer's CPU and is not included. Short tmpfs runs end at the size cap (size_capped).
set -uo pipefail
disk=$(realpath -e "${1:?usage: $0 <disk_dir> [secs] [out.jsonl]}") || exit 2
secs=${2:-60}
here=$(cd "$(dirname "$0")/.." && pwd)
out=$(realpath -m "${3:-$PWD/writer-bench-$(hostname -s)-$(date +%Y%m%d-%H%M).jsonl}")
tmpfs=${TMPFS_DIR:-/dev/shm}
[[ $(stat -f -c %T "$tmpfs") == tmpfs ]] || { echo "$tmpfs is not tmpfs (set TMPFS_DIR)" >&2; exit 2; }
[[ $(stat -f -c %T "$disk") != tmpfs ]] || { echo "$disk is on tmpfs, give a directory on a disk" >&2; exit 2; }

# build once and run the test binary itself, so that the results belong to the build in the meta line
cd "$here/tcbee-record" || exit 2
bin=$(cargo test --release --bin tcbee-record --no-run --message-format=json 2>/dev/null |
  python3 -c 'import json, sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "tcbee-record" and m["profile"]["test"]:
        print(m["executable"])')
[[ -x $bin ]] || { echo "could not build the test binary" >&2; exit 2; }

# one line describing the machine, the build and the disk, before the results
python3 - "$out" "$disk" "$bin" <<'EOF'
import json, os, platform, shlex, shutil, subprocess, sys, tempfile
out, disk, binary = sys.argv[1:]
sh = lambda c: subprocess.run(c, shell=True, text=True, capture_output=True).stdout.strip()
q = shlex.quote(disk)
src = sh(f"findmnt -no SOURCE -T {q}").split("[")[0]
meta = {"meta": True, "host": platform.node(), "kernel": platform.release(),
        "cpu": sh("lscpu | sed -n 's/^Model name: *//p'"), "cpus": os.cpu_count(),
        "governor": sh("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null"),
        "mem_kb": int(sh("awk '/MemTotal/ {print $2}' /proc/meminfo")),
        "git": sh("git rev-parse --short HEAD"), "dirty": bool(sh("git status --porcelain --untracked-files=no -- .")),
        "test_binary": binary, "disk_dir": disk, "disk_source": src,
        "fs": sh(f"findmnt -no FSTYPE,OPTIONS -T {q}"),
        "disk_model": sh(f"lsblk -sdno NAME,MODEL,ROTA,TRAN {shlex.quote(src)} 2>/dev/null")}
# flexible I/O tester only (another program may be installed as fio)
if shutil.which("fio") and sh("fio --version").startswith("fio-"):
    with tempfile.TemporaryDirectory(dir=disk) as d:
        r = subprocess.run(["fio", "--name=seqwrite", f"--directory={d}", "--rw=write", "--bs=1M", "--size=8G",
                            "--direct=1", "--ioengine=libaio", "--iodepth=32", "--time_based", "--runtime=20",
                            "--output-format=json"], text=True, capture_output=True)
    try:
        job = json.loads(r.stdout)["jobs"][0]
        if job.get("error"):   # e.g. ENOSPC: the bandwidth would be of a partial run
            raise ValueError(f"fio error {job['error']}")
        meta["fio_seq_write_mbps"] = job["write"]["bw_bytes"] / 1e6
    except (ValueError, KeyError, IndexError):
        meta["fio_error"] = (r.stderr or r.stdout)[-300:]
else:
    meta["fio_error"] = "no fio (flexible I/O tester) installed"
open(out, "a").write(json.dumps(meta) + "\n")
print(json.dumps(meta))
EOF
[[ $? == 0 ]] || { echo "could not write the meta line" >&2; exit 2; }

fail=0
for dir in "$tmpfs" "$disk"; do
  for files in 1 2 4; do
    for record in sock tcp4 cwnd; do
      if ! TCBEE_BENCH_DIR=$dir TCBEE_BENCH_SECS=$secs TCBEE_BENCH_FILES=$files TCBEE_BENCH_RECORD=$record \
        TCBEE_BENCH_OUT=$out "$bin" --ignored --nocapture --exact writer::bench::bench_writer_throughput \
        > "$out.run.log" 2>&1; then
        echo "run failed: $dir $files $record (see $out.run.log)" >&2
        fail=1
        cp "$out.run.log" "$out.failed-$(basename "$dir")-$files-$record.log"
      fi
      grep -E ' on .*MB/s|: util|warning:' "$out.run.log"
      sync
      sleep 5   # let writeback of the last run finish before the next one starts
    done
  done
done
rm -f "$out.run.log"
echo "results: $out"
exit $fail
