#!/usr/bin/env python3
"""
TCBee unified testing launcher.

Interactively selects a tool (tcbee-live, tcbee-record, or tcbee-full) and a
scenario, then delegates to topology.py.
"""
import os
import sys
import subprocess
from pathlib import Path

TESTING_DIR = Path(__file__).parent
TOPOLOGY    = TESTING_DIR / "topology.py"
REPO_ROOT   = TESTING_DIR.parent


def menu(title, options):
    """Print a numbered menu and return the value of the chosen option."""
    print(f"\n{title}")
    for i, (label, _) in enumerate(options, 1):
        print(f"  [{i}] {label}")
    while True:
        try:
            n = int(input(">>> "))
            if 1 <= n <= len(options):
                return options[n - 1][1]
            print(f"    Please enter a number between 1 and {len(options)}.")
        except ValueError:
            print("    Please enter a number.")
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)


RECORD_FLAGS = [
    ("-h tcbee-eth0", "headers",       "TCP packet headers on tcbee-eth0"),
    ("-w", "cwnd",          "send_cwnd kernel calls"),
    ("-a", "algorithms",    "CUBIC / BBR algorithm state"),
    ("-t", "tracepoints",   "tcp_probe tracepoint (main TCP metrics)"),
    ("-k", "kernel",        "tcp_sendmsg / tcp_recvmsg (all TCP metrics)"),
    ("-m", "metrics",       "write metrics.json"),
]


def ask_record_args():
    """Return a flag string for tcbee-record, either from a profile or custom."""
    profiles = [
        ("cwnd only             [-w]",           "-w"),
        ("algorithms            [-a]",           "-a"),
        ("tracepoints           [-t]",           "-t"),
        ("kernel functions      [-k]",           "-k"),
        ("full trace            [-h tcbee-eth0 -w -t -k -a -m]", "-h tcbee-eth0 -w -t -k -a -m"),
        ("custom",                               None),
    ]
    choice = menu("Select recording profile:", profiles)

    if choice is not None:
        return choice

    # Custom: toggle each flag
    print("\nToggle flags (y/n):")
    selected = []
    for flag, name, desc in RECORD_FLAGS:
        ans = input(f"  {flag:4}  {name:<14} {desc}? [y/N] ").strip().lower()
        if ans == "y":
            selected.append(flag)

    if not selected:
        print("  No trace mode selected — defaulting to -w (cwnd).")
        selected = ["-w"]

    extra = input("  Extra flags (e.g. -c 2 --tui-update-ms 200), or Enter to skip: ").strip()
    if extra:
        selected.append(extra)

    return " ".join(selected)


def rebuild():
    target = menu("Rebuild which?", [
        ("tcbee-live",        "live"),
        ("tcbee-record",      "record"),
        ("tcbee-process",     "process"),
        ("tcbee-viz",         "viz"),
        ("all",               "all"),
    ])
    dirs = []
    if target in ("live", "all"):
        dirs.append(REPO_ROOT / "tcbee-live")
    if target in ("record", "all"):
        dirs.append(REPO_ROOT / "tcbee-record")
    if target in ("process", "all"):
        dirs.append(REPO_ROOT / "tcbee-process")
    if target in ("viz", "all"):
        dirs.append(REPO_ROOT / "tcbee-viz")
    for d in dirs:
        print(f"\nBuilding {d.name}...")
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=d,
        )
        if result.returncode != 0:
            print(f"  Build failed for {d.name}.")
        else:
            print(f"  Done.")


def main():
    # ── Tool ──────────────────────────────────────────────────────────────────
    tool = menu("Select tool:", [
        ("tcbee-live   (egui window)",          "live"),
        ("tcbee-record (TUI)",                  "record"),
        ("tcbee-full   (record, process, viz)", "full"),
        ("Rebuild Program",                     "rebuild"),
    ])

    if tool == "rebuild":
        rebuild()
        main()
        return

    # ── Scenario ──────────────────────────────────────────────────────────────
    cc, double = menu("Select scenario:", [
        ("CUBIC  —  single stream",                       ("cubic", False)),
        ("CUBIC  —  two streams  (second starts at +30s)", ("cubic", True)),
        ("BBR    —  single stream",                       ("bbr",   False)),
        ("BBR    —  two streams  (second starts at +30s)", ("bbr",   True)),
    ])

    # ── tcbee-record profile ───────────────────────────────────────────────────
    record_args = ""
    if tool in ("record", "full"):
        record_args = ask_record_args()
        if tool == "full":
            print(
                "\n  tcbee-full starts with tcbee-record. Quit the recorder with q\n"
                "  when the capture is complete; processing and visualization then\n"
                "  continue automatically.\n"
            )
        print(
            "\n  The topology adds tcbee-record filters for the selected test flow(s)\n"
            "  automatically.\n"
        )

    # ── Build the topology command ─────────────────────────────────────────────
    cmd = [
        "sudo", "-E", sys.executable, str(TOPOLOGY),
        "--tool", tool,
        "--cc",   cc,
    ]
    if double:
        cmd.append("--double")
    if record_args:
        cmd.append(f"--record-args={record_args}")

    print(f"\nCleaning up any leftover mininet state...")
    subprocess.run(["sudo", "mn", "-c"], capture_output=True)

    print(f"Launching: {' '.join(cmd[3:])}\n")  # skip sudo -E python3
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    if os.geteuid() != 0:
        # Re-exec under sudo -E so DISPLAY is preserved.
        os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
    main()
