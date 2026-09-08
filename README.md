# tool-bpf

eBPF-based data collection tool for the [crucible](https://github.com/perftool-incubator/crucible) performance testing framework.

Collects kernel-level metrics using [bpftrace](https://github.com/bpftrace/bpftrace) scripts and compiled [libbpf CO-RE](https://github.com/libbpf/libbpf) programs. Runs as a passive profiler alongside benchmarks and emits results in the [CommonDataModel](https://github.com/perftool-incubator/CommonDataModel) format.

## CommonDataModel dependency

The post-processor emits the `disallowed-aggregations` metric descriptor field
for TCP round-trip time. Deployments must use a CommonDataModel version that
supports this field; support was added by [CommonDataModel PR #210](https://github.com/perftool-incubator/CommonDataModel/pull/210).
Older strict metric descriptor mappings may reject the field during ingestion.

## Requirements

- Kernel with `CONFIG_DEBUG_INFO_BTF=y` (provides `/sys/kernel/btf/vmlinux`)
- bpftrace >= 0.20 (for `nsecs(realtime)`)
- Fedora 43+ or equivalent with `bpftrace`, `libbpf`, `libbpf-devel`, `bpftool`, `clang` available via dnf

## Subtools

Subtools are selected with `--subtools <comma-separated-list>` passed to `bpftools-start`. Each subtool is an independent bpftrace script or eBPF program with its own post-processing pipeline.

| Subtool | Source | Metrics |
|---------|--------|---------|
| `tcp-window` | `tcp:tcp_probe` tracepoint | `snd-cwnd`, `ssthresh`, `snd-wnd`, `srtt`, `rcv-wnd` per TCP flow |

### tcp-window

Captures TCP congestion control and flow-control state per connection using the `tcp:tcp_probe` tracepoint, which fires on every segment received by `tcp_rcv_established()`.

IP addresses are read from the sock struct via BTF (`args->skaddr`) rather than from the `saddr`/`daddr` byte arrays in the tracepoint, which carry `sockaddr_in6` layout (family+port prefix) rather than a raw IP address.

**CDM metrics** (breakouts: `src`, `sport`, `dst`, `dport`):

| Metric | Class | Description |
|--------|-------|-------------|
| `snd-cwnd` | throughput | Congestion window (MSS units) |
| `ssthresh` | throughput | Slow-start threshold (MSS units; 2147483647 = no limit) |
| `snd-wnd` | throughput | Receiver-advertised window (bytes) |
| `srtt` | latency | Smoothed RTT (microseconds) |
| `rcv-wnd` | throughput | Local receive window (bytes) |

`sport`/`dport` reflect the socket's local/remote ports respectively (local = bound port, remote = peer port).

## Usage in a run file

```json
"tool-params": [
    {
        "tool": "bpf",
        "params": [
            { "arg": "subtools", "val": "tcp-window" }
        ]
    }
]
```

Multiple subtools:

```json
{ "arg": "subtools", "val": "tcp-window,tx-burst" }
```

## Adding a new subtool

1. Add a bpftrace script `subtools/<name>.bt` that writes space-separated fields to stdout with a `#`-prefixed header line.
2. Add a `case` block in `bpftools-start` to launch it.
3. Add a `files-from-controller` entry in `rickshaw.json` for the `.bt` file.
4. Implement `process_<name>()` in `bpftools-post-process.py` and register it in `SUBTOOL_HANDLERS`.
