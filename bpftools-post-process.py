#!/usr/bin/env python3
# -*- mode: python; indent-tabs-mode: nil; python-indent-level: 4 -*-
# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Post-process bpf tool output and emit CDM metrics.

Runs in the bpf tool's data directory (one per profiler instance).
Dispatches to per-subtool handlers based on which output files exist.

Subtool output files: <subtool>-stdout.txt or <subtool>-stdout.txt.xz

Metrics emitted
---------------
Per TCP flow (src, sport, dst, dport breakouts):

  tcp-window:snd-cwnd      count     avg   segments (MSS units)
  tcp-window:ssthresh      count     avg   segments (MSS units)
  tcp-window:snd-wnd       count     avg   bytes
  tcp-window:srtt          latency   avg   microseconds
  tcp-window:rcv-wnd       count     avg   bytes

  sport/dport from tcp:tcp_probe are local/remote ports from the
  socket's perspective (local = bound port, remote = peer port).
"""

from __future__ import annotations

import lzma
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

TOOLBOX_HOME = os.environ.get("TOOLBOX_HOME")
if TOOLBOX_HOME is None:
    print("This script requires libraries from the toolbox project.")
    print("Set TOOLBOX_HOME to the toolbox directory and retry.")
    sys.exit(1)
sys.path.append(str(Path(TOOLBOX_HOME) / "python"))

from toolbox.metrics import log_sample, finish_samples

FILE_ID = "0"
INTERVAL_MS = 1000  # bin per-event bpftrace data into 1-second CDM samples

SOURCE_TCP_WINDOW = "tcp-window"


def open_maybe_xz(path: str):
    if path.endswith(".xz"):
        return lzma.open(path, "rt")
    return open(path, "r")


def _normalize_addr(addr: str) -> str:
    """Strip IPv4-mapped IPv6 prefix (::ffff:x.x.x.x -> x.x.x.x)."""
    prefix = "::ffff:"
    if addr.lower().startswith(prefix):
        return addr[len(prefix):]
    return addr


def _read_boot_epoch_ms() -> int:
    """Read the boot epoch offset written by bpftools-start (may be xz-compressed)."""
    for path, opener in (
        ("bpftrace-boot-epoch-ms.txt.xz", lzma.open),
        ("bpftrace-boot-epoch-ms.txt",    open),
    ):
        if Path(path).exists():
            try:
                with opener(path, "rt") as f:
                    return int(f.read().strip())
            except (ValueError, OSError):
                pass
    print("WARNING: bpftrace-boot-epoch-ms.txt[.xz] not found or invalid — timestamps will be wrong")
    return 0


def process_tcp_window(log_file: str) -> None:
    print(f"Post-processing tcp-window: {log_file}")

    boot_epoch_ms = _read_boot_epoch_ms()
    print(f"boot_epoch_ms: {boot_epoch_ms}")

    METRICS = ("snd_cwnd", "ssthresh", "snd_wnd", "srtt_us", "rcv_wnd")
    # key: ((src, sport, dst, dport), bin_start_ms) -> {metric: [sum, count]}
    bins: dict[tuple, dict[str, list]] = defaultdict(
        lambda: {m: [0.0, 0] for m in METRICS}
    )

    with open_maybe_xz(log_file) as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Skip bpftrace status/error lines mixed into stdout
            if line.startswith("Attaching") or line.startswith("ERROR") or line.startswith("WARNING") or line.startswith("HINT"):
                continue
            parts = line.split()
            if len(parts) != 10:
                continue

            try:
                nsecs_rt  = int(parts[0])
                src       = _normalize_addr(parts[1])
                sport     = int(parts[2])
                dst       = _normalize_addr(parts[3])
                dport     = int(parts[4])
                snd_cwnd  = int(parts[5])
                ssthresh  = int(parts[6])
                snd_wnd   = int(parts[7])
                srtt_us   = int(parts[8])
                rcv_wnd   = int(parts[9])
            except (ValueError, IndexError):
                continue

            ts_ms = boot_epoch_ms + nsecs_rt // 1_000_000
            bin_start_ms = (ts_ms // INTERVAL_MS) * INTERVAL_MS
            flow = (src, sport, dst, dport)
            b = bins[(flow, bin_start_ms)]
            for metric, val in (
                ("snd_cwnd", snd_cwnd),
                ("ssthresh", ssthresh),
                ("snd_wnd",  snd_wnd),
                ("srtt_us",  srtt_us),
                ("rcv_wnd",  rcv_wnd),
            ):
                b[metric][0] += val
                b[metric][1] += 1

    if not bins:
        print("WARNING: no tcp-window data found in output file")
        return

    CDM_METRICS = [
        ("snd_cwnd", "snd-cwnd", "count",   "avg"),
        ("ssthresh", "ssthresh", "count",   "avg"),
        ("snd_wnd",  "snd-wnd",  "count",   "avg"),
        ("srtt_us",  "srtt",     "latency", "avg"),
        ("rcv_wnd",  "rcv-wnd",  "count",   "avg"),
    ]

    for (flow, bin_start_ms), b in sorted(bins.items()):
        src, sport, dst, dport = flow
        bin_end_ms = bin_start_ms + INTERVAL_MS
        names = {
            "src":   src,
            "sport": str(sport),
            "dst":   dst,
            "dport": str(dport),
        }
        for raw_name, cdm_type, cdm_class, cdm_agg in CDM_METRICS:
            total, count = b[raw_name]
            if count == 0:
                continue
            desc = {
                "source":              SOURCE_TCP_WINDOW,
                "class":               cdm_class,
                "type":                cdm_type,
                "default-aggregation": cdm_agg,
            }
            sample = {
                "begin": bin_start_ms,
                "end":   bin_end_ms,
                "value": total / count,
            }
            log_sample(FILE_ID, desc, names, sample)

    finish_samples()
    print("Post-processing for tcp-window complete")


def process_gro(log_file: str) -> None:
    print(f"Post-processing gro: {log_file}")
    # TODO: implement


def process_tcp_retrans(log_file: str) -> None:
    print(f"Post-processing tcp-retrans: {log_file}")
    # TODO: implement


def process_tcp_drop(log_file: str) -> None:
    print(f"Post-processing tcp-drop: {log_file}")
    # TODO: implement


SUBTOOL_HANDLERS = {
    "tcp-window":  process_tcp_window,
    "gro":         process_gro,
    "tcp-retrans": process_tcp_retrans,
    "tcp-drop":    process_tcp_drop,
}


def main() -> None:
    print("bpftools-post-process")

    files = sorted(os.listdir("."))
    print(f"files to process:\n {' '.join(files)}")

    found_any = False
    for subtool, handler in SUBTOOL_HANDLERS.items():
        pattern = re.compile(rf"^{re.escape(subtool)}-stdout\.txt(\.xz)?$")
        matched = [f for f in files if pattern.match(f)]
        if len(matched) > 1:
            print(f"ERROR: multiple output files for {subtool}: {matched}")
        elif matched:
            found_any = True
            handler(matched[0])

    if not found_any:
        print("WARNING: no bpftools subtool output files found")

    print("bpftools post-processing complete")


if __name__ == "__main__":
    main()
