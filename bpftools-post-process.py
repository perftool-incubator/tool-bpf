#!/usr/bin/env python3
# -*- mode: python; indent-tabs-mode: nil; python-indent-level: 4 -*-
# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""Post-process bpf tool output and emit CDM metrics.

Runs in the bpf tool's data directory (one per profiler instance).
Dispatches to per-subtool handlers based on which output files exist.

Subtool output files follow the naming convention: <subtool>-stdout.txt

Metrics emitted
---------------
Per TCP flow (src, sport, dst, dport breakouts):

  tcp-window:snd-cwnd      throughput   segments (MSS units)
  tcp-window:ssthresh      throughput   segments (MSS units)
  tcp-window:snd-wnd       throughput   bytes
  tcp-window:srtt          latency      microseconds
  tcp-window:rcv-wnd       throughput   bytes

  sport/dport in the tcp:tcp_probe tracepoint are local/remote ports
  from the socket's perspective (local = bound port, remote = peer port).
"""

from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from pathlib import Path

TOOLBOX_HOME = os.environ.get("TOOLBOX_HOME")
if TOOLBOX_HOME:
    sys.path.append(str(Path(TOOLBOX_HOME) / "python"))

from toolbox.cdm_metrics import CDMMetrics
from toolbox.fileio import open_read_text_file

INTERVAL_MS = 1000  # aggregate bpftrace per-event data into 1-second CDM samples

SOURCE_TCP_WINDOW = "tcp-window"

SSTHRESH_UNLIMITED = 2147483647  # INT_MAX: no congestion has set a threshold


def process_tcp_window(log_file: str) -> None:
    print(f"Post-processing tcp-window: {log_file}")

    try:
        fh, _ = open_read_text_file(log_file)
    except FileNotFoundError:
        print(f"ERROR: could not open {log_file}")
        return

    # Accumulate per-interval sums and counts keyed by (flow_tuple, bin_start_ms).
    # flow_tuple = (src, sport, dst, dport)
    # Each value is a dict: metric_name -> [sum, count]
    METRICS = ("snd_cwnd", "ssthresh", "snd_wnd", "srtt_us", "rcv_wnd")
    bins: dict[tuple, dict[str, list]] = defaultdict(
        lambda: {m: [0.0, 0] for m in METRICS}
    )

    for raw_line in fh:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) != 10:
            continue

        try:
            nsecs_rt, src, sport, dst, dport, snd_cwnd, ssthresh, snd_wnd, srtt_us, rcv_wnd = parts
            ts_ms      = int(nsecs_rt) // 1_000_000
            sport      = int(sport)
            dport      = int(dport)
            snd_cwnd   = int(snd_cwnd)
            ssthresh   = int(ssthresh)
            snd_wnd    = int(snd_wnd)
            srtt_us    = int(srtt_us)
            rcv_wnd    = int(rcv_wnd)
        except (ValueError, IndexError):
            continue

        bin_start_ms = (ts_ms // INTERVAL_MS) * INTERVAL_MS
        flow = (src, sport, dst, dport)
        key = (flow, bin_start_ms)

        b = bins[key]
        for metric, val in (
            ("snd_cwnd",  snd_cwnd),
            ("ssthresh",  ssthresh),
            ("snd_wnd",   snd_wnd),
            ("srtt_us",   srtt_us),
            ("rcv_wnd",   rcv_wnd),
        ):
            b[metric][0] += val
            b[metric][1] += 1

    fh.close()

    if not bins:
        print("WARNING: no tcp-window data found in output file")
        return

    metrics = CDMMetrics()

    CDM_METRICS = [
        ("snd_cwnd",  "snd-cwnd", "throughput"),
        ("ssthresh",  "ssthresh", "throughput"),
        ("snd_wnd",   "snd-wnd",  "throughput"),
        ("srtt_us",   "srtt",     "latency"),
        ("rcv_wnd",   "rcv-wnd",  "throughput"),
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

        for raw_name, cdm_type, cdm_class in CDM_METRICS:
            total, count = b[raw_name]
            if count == 0:
                continue
            avg_val = total / count

            desc = {
                "source": SOURCE_TCP_WINDOW,
                "class":  cdm_class,
                "type":   cdm_type,
            }
            sample = {
                "begin": bin_start_ms,
                "end":   bin_end_ms,
                "value": avg_val,
            }
            metrics.log_sample(SOURCE_TCP_WINDOW, desc, names, sample)

    metrics.finish_samples()
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
