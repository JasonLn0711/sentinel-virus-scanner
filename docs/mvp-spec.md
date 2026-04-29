# MVP Spec

## MVP Goal

Scan local folders with safe signatures, detect EICAR/demo patterns, generate
reproducible evidence reports, and expose a stable engine boundary for other
repos.

## Feature 1 - Local File Scanner

Requirements:

- support file path input
- support directory input
- scan recursively by default
- skip unreadable files safely
- avoid following symbolic links by default
- provide deterministic output ordering
- support configurable ignored folders in a later config-file pass
- support configurable max file size in a later config-file pass

Acceptance criteria:

```text
Given a folder with normal files and an EICAR fixture
When sentinel scan is executed
Then Sentinel reports clean files, matched files, skipped files, and a scan summary
```

## Feature 2 - Signature Rule Engine

Initial rule types:

| Rule type | Purpose |
| --- | --- |
| literal string | Detect known test strings |
| byte pattern | Detect binary patterns |
| hash match | Detect exact files |
| extension rule | Flag risky file types |
| filename pattern | Flag suspicious naming |
| metadata rule | Check size, entropy, permissions, or related metadata |

Current implementation already supports exact hashes, byte patterns, and a small
heuristic layer. MVP hardening should make these rule types explicit and
validated.

## Feature 3 - Report Generation

Outputs:

- terminal summary
- JSON report
- Markdown report
- optional CSV later

Every report must include:

- scanner name and version
- rulepack or signature schema version
- target path
- start and finish timestamps
- scan configuration snapshot
- scan summary
- per-file results
- rule matches with explanation fields

## Feature 4 - Evidence Manifest

The evidence manifest should record:

- scanned file list
- SHA-256 hashes
- rulepack hash
- scanner version
- command used
- config used
- report hash
- generated timestamp
- machine-independent reproducibility metadata

This is the key feature for paper repos, teaching reports, submission packages,
and AI-agent artifact checks.

## Feature 5 - Safe Demo Mode

Keep the EICAR demo workflow.

Target command surface:

```bash
sentinel demo prepare-eicar
sentinel demo verify-eicar
sentinel demo clean
```

The demo should keep generating EICAR at runtime rather than storing the literal
test file in Git.

## Feature 6 - Rulepack Validation

Before scanning, Sentinel should validate rulepacks.

Validation checks:

- duplicate rule IDs
- invalid severity
- missing explanation
- missing test fixture metadata
- unsafe rule name
- broken pattern format
- rule without expected test result

Target command:

```bash
sentinel rules validate ./rules
```
