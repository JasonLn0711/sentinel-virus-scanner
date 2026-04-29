# Generated Reports

This folder keeps the current Rust-generated evidence artifacts for the safe
Sentinel demo.

| File | Purpose |
| --- | --- |
| [demo-report.json](demo-report.json) | Machine-readable scan result for the safe demo tree. |
| [demo-report.md](demo-report.md) | Human-readable Markdown scan result. |
| [demo-evidence-manifest.json](demo-evidence-manifest.json) | Hashes, safety flags, inputs, report hashes, and reproduction commands. |

Regenerate from the repo root:

```bash
make rust-evidence
```

Keep only the current canonical Rust evidence files here. Store benchmark
scratch output somewhere else until the benchmark workflow is formalized.
