# Sentinel Artifact Scanner

Sentinel Artifact Scanner is a local-first, read-only artifact scanner and
evidence generator for security-learning projects, repo hygiene, demo labs, and
research workflows.

The repo starts from the submitted Network Security Project I Rust baseline, but
this repo is now the product continuation. The course repo remains the archive
for grading evidence and official course materials.

The strategic product is not another antivirus. It is a transparent way to ask:

```text
Before I submit, share, zip, publish, or run this artifact, what exactly is
inside it, what rules matched, and can I reproduce the evidence?
```

## Product Family Name

Use `sentinel-` as the shared first word for future cybersecurity products.

Current product:

- Repo: `sentinel-virus-scanner`
- Strategic product name: `Sentinel Artifact Scanner`
- Current implementation name: `Sentinel Virus Scanner`
- Short name: `Sentinel`

Future products can follow the same family pattern, for example
`sentinel-log-triage`, `sentinel-policy-guard`, or `sentinel-malware-lab`.

## Current Status

- Stage: working prototype / product continuation ready for MVP hardening
- Baseline: Rust signature-based scanner copied from the course submission
- Current version: `0.1.0`
- Primary interface: CLI
- Safety posture: read-only scanning, explicit target path only, no live malware
- Canonical product repo: this folder
- Course archive: `../nycu_114-2_network_security_practices/projects/project-i-virus-scanner/`
- Planning bridge: `../planning-everything-track/data/projects/2026-04-sentinel-virus-scanner-product.md`

## Quick Start

Run the full local verification gate:

```bash
make product-check
```

Run the safe demo:

```bash
make demo
```

Run the scanner manually:

```bash
cd rust
cargo run -- prepare-eicar-demo --target ../demo/demo-tree
cargo run -- scan \
  --target ../demo/demo-tree \
  --signatures ../signatures/malware-signatures.json \
  --json ../reports/demo-report.json \
  --markdown ../reports/demo-report.md
```

The demo scan returns exit code `1` when the generated EICAR safe test file is
detected. That is expected for this controlled demo.

## Repo Map

| Path | Role |
| --- | --- |
| `rust/` | Rust CLI scanner, signature loading, matching engines, reports, tests |
| `signatures/` | Safe JSON signature database and EICAR reference signature |
| `demo/` | Controlled local demo fixtures and runbook |
| `reports/` | Regenerated demo reports and evidence manifest |
| `docs/` | Product overview, architecture, safety, target audience, and bridge notes |
| `Makefile` | Local verification and demo commands |

## Current Capabilities

- JSON signature loading and validation
- MD5 and SHA-256 exact signature matching
- Bloom-filter pre-check before exact hash-map verification
- Aho-Corasick byte-pattern matching across streamed chunks
- Deterministic recursive directory traversal
- Symbolic-link skipping by default
- Heuristic-only suspicious findings for weak local indicators
- JSON and Markdown scan reports
- Reproducibility evidence manifest
- Generated EICAR safe-test demo fixture

## Core Product Promise

Every scan should answer:

1. What was scanned?
2. What rule matched?
3. Why did it match?
4. Can someone reproduce the same result?

## Product Boundary

Sentinel is not a production endpoint antivirus today.

It does not:

- execute scanned files
- delete, quarantine, upload, or mutate files
- scan the whole machine by default
- process live malware
- make enterprise protection claims

Product work should grow from transparent local scanning, explainable evidence,
and controlled teaching or lab workflows before any broader protection claim is
considered.

## Start Here

- Product overview: `docs/repo-overview.md`
- Product spec: `docs/product-spec.md`
- MVP spec: `docs/mvp-spec.md`
- CLI spec: `docs/cli-spec.md`
- Config spec: `docs/config-spec.md`
- Report schema spec: `docs/report-schema-spec.md`
- Rule spec: `docs/rule-spec.md`
- Reusable library API: `docs/reusable-library-api.md`
- Integration use cases: `docs/integration-use-cases.md`
- Target audience: `docs/target-audience.md`
- Product roadmap: `docs/product-roadmap.md`
- Technical architecture: `docs/architecture.md`
- Safety boundary: `docs/safety-boundary.md`
- Cross-repo bridge: `docs/repo-bridge.md`
- External references: `docs/external-references.md`
