# CLI Spec

This is the target command surface for MVP hardening. Current implementation is
still smaller; this file defines the direction.

## Minimum Useful Commands

```bash
sentinel scan <path>
sentinel scan <path> --json <file>
sentinel scan <path> --markdown <file>
sentinel scan <path> --manifest <file>
sentinel scan <path> --config sentinel.toml
sentinel scan <path> --fail-on high

sentinel rules validate <rules-dir>
sentinel rules list <rules-dir>

sentinel manifest generate <path>
sentinel manifest verify <manifest.json>

sentinel demo prepare-eicar
sentinel demo verify-eicar
sentinel demo clean

sentinel version
```

## Current Compatibility Notes

The current Rust command still exposes:

```bash
cargo run -- validate-signatures --signatures <path>
cargo run -- prepare-eicar-demo --target <dir>
cargo run -- scan --target <dir> --signatures <path> --json <path> --markdown <path>
cargo run -- verify-demo --target <dir> --signatures <path>
cargo run -- write-evidence --target <dir> --signatures <path> --report <path> --output <path>
```

Phase 1 should wrap or rename these commands into the stable product surface
without breaking the safe demo gate.

## Exit-Code Policy

Target policy:

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed and policy passed |
| `1` | Scan completed but policy failed or matched blocked severity |
| `2` | CLI usage or validation error |
| `3` | Scan could not complete |

The current demo returns `1` when EICAR is detected. Phase 1 should distinguish
safe demo matches from policy failures so automation can be clearer.
