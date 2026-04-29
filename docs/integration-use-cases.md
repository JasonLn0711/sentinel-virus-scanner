# Integration Use Cases

## A - Repo Publish Preflight

```bash
sentinel scan . \
  --ignore target \
  --ignore .git \
  --json reports/sentinel-report.json \
  --manifest reports/sentinel-manifest.json
```

Purpose: before pushing or sharing a repo, check for unsafe fixtures, risky
binaries, suspicious scripts, and unexpected artifacts.

## B - AI Agent Output Safety Check

```bash
sentinel scan ./agent-output --policy safe-generated-code
```

Example policy:

```toml
[policy]
block_on = ["high", "critical"]
warn_on = ["medium"]
allow_demo_matches = false
```

Purpose: scan files created by an AI agent before executing, committing, or
submitting them.

## C - Teaching Lab Verification

```bash
sentinel demo prepare-eicar
sentinel scan ./fixtures --json lab-report.json
sentinel verify lab-report.json
```

Purpose: let instructors and students reproduce the same safe scan result.

## D - Research Artifact Package

```bash
sentinel scan ./submission-package \
  --json submission/sentinel-scan.json \
  --manifest submission/evidence-manifest.json
```

Purpose: attach reproducible artifact-scan evidence before creating a
submission package.
