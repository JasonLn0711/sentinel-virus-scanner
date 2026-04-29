# Product Roadmap

## Phase 0 - Product Split Complete

Goal: separate the product continuation from the submitted course archive.

Done when:

- product repo exists as `sentinel-virus-scanner`
- course-only PDFs and LMS artifacts stay out of the product repo
- product README, target audience, safety, architecture, and bridge docs exist
- `make product-check` passes

## Phase 1 - MVP Hardening

Goal: make Sentinel reusable and reproducible as an artifact scanner.

Candidate work:

- stable command names and help text
- clearer exit-code policy
- report schema documentation
- JSON schema validation for reports and manifests
- config file support
- rulepack validation
- better error messages for unreadable files and invalid signatures
- explicit scan policy summary at the top of each report
- fixture-based regression tests for clean, matched, suspicious, skipped, and
  error cases
- GitHub Actions CI when the repo is published

Done when:

- a new user can run the demo from the README without guessing
- reports explain what happened without opening the source code
- scanner behavior is covered by focused tests
- schemas are stable enough for another repo to consume

## Phase 2 - Library API

Goal: let other projects use Sentinel as a module.

Candidate work:

- split into `sentinel-core`, `sentinel-rules`, `sentinel-report`, and
  `sentinel-manifest` crates
- expose `scan_path`, `scan_file`, `scan_bytes`, and `validate_rulepack`
- keep report schemas compatible with the CLI
- add examples for Rust and Python subprocess integration

Done when:

- another repo can call Sentinel as a Rust dependency
- another repo can call Sentinel through the CLI
- generated reports remain schema compatible

## Phase 3 - Project Policies

Goal: make Sentinel useful across the project ecosystem.

Candidate work:

- `policy.learning-lab.toml`
- `policy.repo-hygiene.toml`
- `policy.agent-output.toml`
- `policy.research-artifact.toml`
- `policy.submission-package.toml`

Done when:

- policies define what to scan, ignore, block, warn, and report
- `sentinel scan <path> --policy <policy>` has predictable behavior

## Phase 4 - YARA Bridge

Goal: make Sentinel compatible with common security-learning workflows.

Candidate work:

- YARA rule import
- YARA-like rule subset
- optional external YARA integration

## Phase 5 - ClamAV Bridge

Goal: compare Sentinel with mature open-source scanner behavior.

Candidate work:

- optional ClamAV scan adapter
- Sentinel report vs. ClamAV result comparison
- educational baseline mode

## Phase 6 - Threat Mapping

Goal: connect selected rule matches to security reasoning without overclaiming.

Candidate work:

- optional MITRE ATT&CK technique hints
- confidence labels
- clear wording that mappings are contextual hints, not intrusion conclusions

## Product Expansion Gate

Goal: decide whether to stay CLI-only or add a second interface.

Only consider a local UI, service mode, or integration after:

- CLI use cases are stable
- safety policy is written and tested
- reports have a stable schema
- target audience has been narrowed by real user feedback

Do not add cloud scanning, file upload, quarantine, deletion, or background
monitoring before a separate safety and threat-model review exists.
