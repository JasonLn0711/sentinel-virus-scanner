# Sentinel Virus Scanner Rust CLI

This folder contains the Rust scanner, signature loader, matching engines,
heuristic checks, CLI, reports, and verification commands for the product repo.

## Scope

Implemented in the current product seed:

- JSON signature loading and validation.
- MD5 and SHA-256 signature matching.
- Bloom-filter hash pre-check followed by exact hash-map verification.
- Streamed file reading with Aho-Corasick byte-pattern matching across chunk boundaries.
- Deterministic recursive directory traversal.
- Symbolic-link skipping.
- Heuristic-only suspicious findings for process-injection API names,
  executable-magic/file-extension mismatch, and high-entropy byte samples.
- JSON and Markdown report generation.
- Rust evidence-manifest generation with SHA-256 hashes and safety flags.
- Rust EICAR demo preparation command that writes the official 68-byte safe
  anti-malware test file into the nested demo tree.

Still intentionally out of scope:

- Live malware handling.
- Quarantine, deletion, upload, or file mutation.
- Whole-machine scanning.
- Production antivirus claims.

## Commands

From this folder:

```bash
cargo run -- prepare-eicar-demo --target ../demo/demo-tree
cargo run -- scan \
  --target ../demo/demo-tree \
  --signatures ../signatures/malware-signatures.json \
  --json ../reports/demo-report.json \
  --markdown ../reports/demo-report.md
```

Expected demo summary:

```text
Sentinel Virus Scanner scan complete: scanned=5 infected=1 suspicious=1 clean=3 errors=0
```

The scan command returns exit code `1` when the generated EICAR safe test file
is detected. That is expected for the demo.

Validate the signature database only:

```bash
cargo run -- validate-signatures --signatures ../signatures/malware-signatures.json
```

Run Rust tests:

```bash
cargo fmt --check
cargo test
```

Run the Rust lint gate:

```bash
cargo clippy --all-targets -- -D warnings
```

Run the Rust demo verification gate:

```bash
cargo run -- verify-demo \
  --target ../demo/demo-tree \
  --signatures ../signatures/malware-signatures.json
```

Regenerate the Rust evidence manifest:

```bash
cargo run -- write-evidence \
  --target ../demo/demo-tree \
  --signatures ../signatures/malware-signatures.json \
  --report ../reports/demo-report.json \
  --report ../reports/demo-report.md \
  --output ../reports/demo-evidence-manifest.json
```

## Toolchain Note

This workspace now has a user-local Rust toolchain installed. Verified locally:

- `rustc 1.95.0`
- `cargo 1.95.0`
- `cargo fmt --check`
- `cargo test` with `13` tests
- `cargo clippy --all-targets -- -D warnings`
- `cargo run -- validate-signatures --signatures ../signatures/malware-signatures.json`
- `cargo run -- prepare-eicar-demo --target ../demo/demo-tree`
- `cargo run -- verify-demo --target ../demo/demo-tree --signatures ../signatures/malware-signatures.json`
- `cargo run -- write-evidence ...`
- `cargo run -- scan ...` with the expected safe-demo detection summary
