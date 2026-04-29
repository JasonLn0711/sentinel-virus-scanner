# Rust Implementation

## Purpose

`rust/` is the Rust implementation path for Sentinel Virus Scanner. It contains
the CLI scanner, signature database loader, matching engines, heuristic layer,
report writers, and verification commands used by the product repo.

## Current Local Status

- Rust source and Cargo metadata have been added under `rust/`.
- `Cargo.lock` is included so the binary has reproducible dependency resolution.
- The implementation covers the required scanner behavior:
  - JSON signature loading and validation
  - MD5 and SHA-256 matching
  - Bloom-filter pre-check with exact hash-map verification
  - streamed file reading with Aho-Corasick byte-pattern matching across chunk
    boundaries
  - deterministic directory traversal
  - symbolic-link skipping
  - heuristic-only suspicious findings for process-injection API names,
    executable-magic/file-extension mismatch, and high-entropy byte samples
  - JSON and Markdown report output
  - Rust evidence manifest with SHA-256 hashes and safety flags
  - Rust EICAR demo preparation command for the official 68-byte safe test file
- Verified locally with `rustc 1.95.0`, `cargo 1.95.0`, `cargo fmt --check`,
  `cargo test` with `13` tests, `cargo clippy --all-targets -- -D warnings`,
  signature validation, `prepare-eicar-demo`, `verify-demo`, `write-evidence`,
  and the EICAR demo scan.

## Verification Commands

Run these from `rust/` on a Rust-capable machine:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo run -- validate-signatures --signatures ../signatures/malware-signatures.json
cargo run -- prepare-eicar-demo --target ../demo/demo-tree
cargo run -- verify-demo \
  --target ../demo/demo-tree \
  --signatures ../signatures/malware-signatures.json
cargo run -- scan \
  --target ../demo/demo-tree \
  --signatures ../signatures/malware-signatures.json \
  --json ../reports/demo-report.json \
  --markdown ../reports/demo-report.md
cargo run -- write-evidence \
  --target ../demo/demo-tree \
  --signatures ../signatures/malware-signatures.json \
  --report ../reports/demo-report.json \
  --report ../reports/demo-report.md \
  --output ../reports/demo-evidence-manifest.json
```

Expected scan result:

```text
scanned=5 infected=1 suspicious=1 clean=3 errors=0
```

The scan command returns exit code `1` when the generated EICAR safe test file is found.
That is expected for this demo.

## Product Guidance

Use `reports/demo-report.json` and `reports/demo-report.md` as generated scan
evidence, and `reports/demo-evidence-manifest.json` as the reproducibility
manifest. Product work should keep the scanner read-only, explicit-target, and
safe-demo oriented until a written safety design changes that boundary.
