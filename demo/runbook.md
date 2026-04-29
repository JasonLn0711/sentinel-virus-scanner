# Sentinel Demo Runbook

## Purpose

Show that Sentinel Virus Scanner can run a safe, local, read-only scan against a
small fixture tree, detect the generated EICAR safe anti-malware test file, flag
a heuristic-only suspicious fixture, and write reproducible reports.

## Safety Boundary

- Use only the generated EICAR safe test file and benign local fixtures.
- Do not download, store, execute, or analyze live malware.
- Do not scan broad personal directories for the demo.
- Do not delete, quarantine, upload, or mutate scanned files.

## Commands

Run from the repo root:

```bash
make product-check
```

Run only the demo scan:

```bash
make demo
```

Manual command sequence:

```bash
cd rust
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
```

Expected scan summary:

```text
Sentinel Virus Scanner scan complete: scanned=5 infected=1 suspicious=1 clean=3 errors=0
```

The scan command returns exit code `1` when the generated EICAR safe test file
is detected. That is expected for this demo.

## Demo Talk Track

1. State the safety boundary: read-only scanner, explicit target path, generated
   EICAR safe test file only, no live malware.
2. Show `signatures/malware-signatures.json`.
3. Show `rust/src/scanner.rs`, `rust/src/signatures.rs`, and
   `rust/src/reporting.rs`.
4. Run `make product-check`.
5. Open `reports/demo-report.md` and show the infected, suspicious, and clean
   outcomes.
6. Close with the limitation: Sentinel is currently an explainable local scanner
   and lab product seed, not production endpoint protection.
