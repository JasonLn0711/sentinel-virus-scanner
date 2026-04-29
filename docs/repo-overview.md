# Sentinel Virus Scanner Repo Overview

## Identity

- Product family: `Sentinel`
- Product repo: `sentinel-virus-scanner`
- Strategic product name: `Sentinel Artifact Scanner`
- Current implementation name: `Sentinel Virus Scanner`
- Current product stage: productization seed
- Starting implementation: Rust CLI scanner
- Product posture: local-first, explainable, read-only, evidence oriented

## Why This Repo Exists

The course project proved a working signature-based scanner. This repo turns
that baseline into a product-shaped workspace for artifact scanning, evidence
generation, repo hygiene, teaching labs, and research workflows without changing
the frozen course archive.

The split is intentional:

- Course archive: evidence of what was submitted for Network Security Project I.
- Product repo: future product decisions, implementation, packaging, and demos.
- Planning repo: capacity, schedule, next actions, and cross-repo locators.

## Current Implementation

The scanner is implemented in Rust under `rust/`.

The current code can:

- load and validate JSON signatures
- match MD5 and SHA-256 hashes
- pre-check candidate hashes with a Bloom filter
- verify exact hashes with hash maps
- match byte patterns with an Aho-Corasick automaton
- stream file contents in chunks
- recursively traverse a target directory
- skip symbolic links by default
- emit heuristic-only suspicious findings
- write JSON and Markdown reports
- write a reproducibility evidence manifest
- generate the EICAR safe anti-malware test fixture for demo use

## Important Folders

| Folder | Product meaning |
| --- | --- |
| `rust/` | Scanner engine and CLI |
| `signatures/` | Safe signature data and reference signatures |
| `demo/` | Small controlled fixture tree and repeatable demo workflow |
| `reports/` | Regenerated sample reports and manifest |
| `docs/` | Product, architecture, safety, audience, and bridge docs |

## Product Direction

Sentinel should first become a strong CLI and evidence product before growing
any heavier interface.

Near-term product direction:

1. Stabilize JSON report and evidence-manifest schemas.
2. Make scanner outputs clearer and more actionable.
3. Separate educational demo signatures from reusable rule packs.
4. Improve explainability for why a file was flagged.
5. Add policy modes for repo hygiene, agent output, research packages, and labs.
6. Package the CLI cleanly for local use.

Later product direction can include policy packs, richer triage summaries,
controlled lab integration, or a small local UI, but only after the CLI and
safety story are strong.

## Current Done Conditions

A change is product-ready when:

- `make product-check` passes
- the safety boundary still holds
- generated reports are reproducible
- docs explain any new user-facing behavior
- no official course-only or third-party raw material is copied into this repo

## Naming Decision

Use `sentinel-` as the first word for the cybersecurity product family. It is
short, security-aligned, and already matches the scanner identity from the Rust
baseline. This keeps future products grouped without forcing unrelated projects
under the same name.
