# Product Spec

## Positioning

Sentinel should not be positioned as another antivirus.

The strongest product is:

> A transparent local artifact scanner and evidence generator for
> security-learning projects, repo hygiene, demo labs, and research workflows.

The product should help answer four questions before an artifact is submitted,
shared, zipped, published, or executed:

1. What was scanned?
2. What rule matched?
3. Why did it match?
4. Can someone reproduce the same result?

## Product Identity

- Repo name: `sentinel-virus-scanner`
- Strategic product name: `Sentinel Artifact Scanner`
- Current implementation name: `Sentinel Virus Scanner`
- Product family prefix: `sentinel-`
- Current status: working prototype / product continuation ready for MVP
  hardening

The repo name stays stable for path continuity. The product surface should move
toward `Sentinel Artifact Scanner` because the real value is broader than
consumer antivirus: repo files, datasets, generated reports, evidence bundles,
demo fixtures, student submissions, and research artifacts.

## Product Promise

Sentinel is a local Rust-based scanner that detects known risky file patterns,
generates reproducible scan evidence, and exports machine-readable reports for
other projects.

It should promise:

- local artifact scanning
- explicit rule-match evidence
- reproducible reports
- safe demo fixtures
- project-level preflight checks

It should not promise:

- complete malware detection
- production antivirus replacement
- endpoint detection and response
- live-malware research infrastructure
- automatic cleanup or remediation

## Why This Product Exists

This product is useful if it becomes a reusable evidence layer across projects.

| Project type | Sentinel value |
| --- | --- |
| Cybersecurity teaching projects | Safe demo scanner, EICAR fixtures, reproducible reports |
| Scam-site / phishing research | Scan downloaded HTML, JavaScript, archives, screenshots, and evidence folders |
| AI agent projects | Scan generated files before execution, commit, or submission |
| Paper and research repos | Generate evidence manifests for reproducibility |
| Student / lab submissions | Check risky files before opening or grading |
| Forensic-style demos | Produce transparent scan traces |
| Internal tools | Add lightweight preflight security checks |

## Non-Goal

Do not compete directly with commercial antivirus or EDR products.

That path would require malware feeds, behavioral detection, kernel or endpoint
monitoring, sandboxing, update infrastructure, telemetry, cloud reputation,
exploit detection, and incident-response workflow. Sentinel's defensible path is
local, transparent, reproducible, educational, and research-friendly scanning.

## Product Layers

### Layer 1 - Scanner Engine

The Rust core that performs traversal, hashing, rule matching, heuristics, and
classification.

Future public functions:

```text
scan_path(path, config) -> ScanReport
scan_file(path, config) -> FileScanResult
scan_bytes(bytes, metadata, config) -> FileScanResult
load_rulepack(path) -> RulePack
calculate_hashes(path) -> HashSet
```

### Layer 2 - CLI Product

The command-line interface for users and automation.

Target commands are specified in `docs/cli-spec.md`.

### Layer 3 - Evidence / Integration Layer

The reusable layer for other repos.

It should generate:

- JSON report
- Markdown report
- evidence manifest
- file hash list
- rule match trace
- reproducibility metadata
- scan configuration snapshot

This layer is what turns Sentinel from a scanner demo into a research-grade
support tool.

## Detection Philosophy

Sentinel should not say:

```text
This file is malicious.
```

It should say:

```text
This file matched rule X under rulepack Y. Here is the evidence.
```

That wording is stronger, safer, and more useful for learning, research, and
automation.
