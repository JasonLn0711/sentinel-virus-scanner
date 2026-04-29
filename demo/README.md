# Sentinel Demo Assets

This folder contains safe local demo fixtures for Sentinel Virus Scanner.

Use `runbook.md` for the repeatable demo sequence.

The official EICAR safe anti-malware test file is generated at demo time by the
Rust command below:

```bash
cd ../rust
cargo run -- prepare-eicar-demo --target ../demo/demo-tree
```

The generated `demo-tree/nested/level-1/level-2/eicar.com.txt` file is ignored
by Git. This lets the demo prove detection without storing a literal EICAR file
in the repository.
