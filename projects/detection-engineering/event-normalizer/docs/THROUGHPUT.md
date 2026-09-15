# Local Throughput Evidence

## Question

How quickly does the current Python normalizer convert already-decoded Zeek mappings
into `NormalizedEvent` objects in this development environment?

## Reproduce

From the event-normalizer project directory:

```bash
PYTHONPATH=src python -m event_normalizer.benchmark_cli \
  --events 50000 \
  --rounds 5 \
  --output benchmark.json
```

The workload is generated before timing. It uses reserved `192.0.2.0/24` and
`198.51.100.0/24` documentation ranges, deterministic timestamps, and no network
activity.

## Recorded run

On September 15, 2026, one run used CPython 3.12.14 on Linux x86_64. The environment
reported 9 logical CPUs, while the command itself used one Python process and one
thread. Each of five rounds normalized 50,000 events.

The five observed rates were approximately 163,134, 164,158, 173,767, 181,945, and
176,731 events per second. The median was approximately 173,767 events per second.
The unrounded output is stored in `benchmarks/2026-09-15-local.json`.

## Limits

This result describes one local run, not production capacity. It excludes JSON
decoding, file I/O, ATT&CK mapping, correlation, queueing, storage, and concurrent
traffic. Virtualized CPU allocation and other processes can change later results. The
benchmark records each sample so future runs can be compared without hiding variance.
