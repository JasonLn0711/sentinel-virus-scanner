# Technical Architecture

## Product Layers

```text
other project / user
  -> Sentinel CLI or library API
  -> scanner engine
  -> rule matcher
  -> report generator
  -> evidence manifest
  -> reusable output for humans and automation
```

## High-Level Flow

```text
target path
  -> deterministic traversal
  -> per-file metadata check
  -> streamed content read
  -> MD5 and SHA-256 hashing
  -> Bloom-filter pre-check
  -> exact hash-map verification
  -> byte-pattern matching
  -> heuristic-only checks
  -> per-file result
  -> JSON / Markdown report
  -> optional evidence manifest
```

## Main Rust Modules

| Module | Responsibility |
| --- | --- |
| `main.rs` | CLI parsing, command dispatch, demo verification |
| `signatures.rs` | JSON signature loading and validation |
| `scanner.rs` | Traversal, per-file scanning, result classification |
| `bloom.rs` | Bloom filter for hash pre-checks |
| `patterns.rs` | Aho-Corasick style byte-pattern matching |
| `reporting.rs` | JSON and Markdown report writing |
| `evidence.rs` | Reproducibility manifest writing |

## Detection Layers

Sentinel currently uses three layers:

1. Exact hash signatures
2. Byte-pattern signatures
3. Heuristic-only suspicious indicators

The first two can produce infected findings when a known signature matches. The
heuristic layer should stay conservative and should not be described as
confirmed malware detection.

## Data Boundaries

Inputs:

- explicit target path
- explicit signature database

Outputs:

- terminal summary
- JSON report
- Markdown report
- optional evidence manifest

No current output requires network access. No current command mutates scanned
files.

## Safety-Critical Defaults

- symbolic links are skipped by default
- scanned files are not executed
- scanned files are not modified
- generated EICAR fixture is ignored by Git
- broad user-home or whole-disk scanning is not a default workflow

## Product Architecture Direction

Keep the engine small and inspectable. Prefer a strong local CLI, stable report
schema, and fixture-based tests before adding packaging, UI, service, or
integration layers.

The architecture should stay boring. Boring is good here because it is testable,
reviewable, and reusable by other repos.
