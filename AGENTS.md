# Tool-bpf

## Purpose
Kernel-level tracing and performance analysis tool using bpftrace scripts for the crucible framework. Collects TCP congestion control metrics, socket queueing statistics, and network packet micro-bursts during benchmark execution.

## Languages
- Bash: collection scripts (`bpftools-start`, `bpftools-stop`)
- Python: post-processor (`bpftools-post-process.py`)
- bpftrace: BPF tracing scripts (`subtools/tcp-window.bt`, `subtools/tx-burst.bt`)

## Key Files
| File | Purpose |
|------|---------|
| `bpftools-start` | Launches configured subtools with `--subtools`, `--interval`, and `--iface` parameters |
| `bpftools-stop` | Kills running bpftrace collectors, compresses output with xz |
| `bpftools-post-process.py` | Parses raw subtool output into crucible CDM metrics |
| `subtools/tcp-window.bt` | bpftrace script capturing `tcp:tcp_probe` tracepoints |
| `subtools/tx-burst.bt` | bpftrace script capturing `net:net_dev_queue` tracepoints |
| `rickshaw.json` | Rickshaw integration: endpoint allow/block lists, file deployment, post-process script |
| `workshop.json` | Engine image build requirements: bpftrace, libbpf, kernel BTF tools |
| `tool-metadata.json` | Machine-readable description, subtool list, and CDM-indexed status (consumed by `crucible tools list`) |
| `multiplex.json` | Parameter validation rules and `defaults` preset for multiplex (mirrors benchmark `multiplex.json`) |

## Configuration
- `--subtools <list>` — Comma-separated subtools to run (`tcp-window`, `tx-burst`; default: `tcp-window`)
- `--interval <seconds>` — Collection interval (default: `10`)
- `--iface <name>` — Network interface for tx-burst tracing (default: `ens1f0np0`)

## Conventions
- Primary branch is `master`
- Runs as a profiler tool on master/worker/profiler/compute roles, blocked on client/server
- Standard Bash modelines and 4-space indentation
- Python code follows 4-space indentation with standard modelines
