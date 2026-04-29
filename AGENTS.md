# AGENTS.md

This repository is the standalone product home for Sentinel Artifact Scanner.

## Mission

Build Sentinel into a useful, safe, local-first artifact scanner and evidence
generator without disturbing the submitted course archive.

The repo should support:

- product strategy and target-audience notes
- Rust scanner implementation
- safe demo fixtures
- reproducible reports and evidence manifests
- lightweight product-roadmap decisions
- future packaging, benchmark, and release work

## Product Family Rule

Use `sentinel-` as the shared first word for this cybersecurity product family.
This repo owns `sentinel-virus-scanner`. Future cybersecurity products should use
the same prefix only when they share the Sentinel product-family identity.

## Source-Of-Truth Rule

- This repo owns product continuation.
- The course repo owns official course submission evidence:
  `../nycu_114-2_network_security_practices/projects/project-i-virus-scanner/`
- The planning repo owns priority, capacity, deadlines, and locator notes only:
  `../planning-everything-track/`

Do not copy official course PDFs, LMS submission status, grading notes, or raw
third-party course material into this product repo.

## Security Boundary

Sentinel must stay safe by default.

- Use only benign fixtures and the generated EICAR safe anti-malware test file.
- Do not download, store, execute, or analyze live malware in this repo.
- Do not scan broad user directories unless the user explicitly asks and the
  command is read-only and scoped.
- Do not add quarantine, deletion, upload, network submission, or persistence
  behavior without a written safety design first.
- Do not claim production antivirus, EDR, or enterprise protection readiness
  unless that evidence actually exists.

## Product Documentation Routing

- Product overview and repo map: `README.md`, `docs/repo-overview.md`
- Product contract: `docs/product-spec.md`, `docs/mvp-spec.md`
- CLI, config, rules, schemas: `docs/cli-spec.md`, `docs/config-spec.md`,
  `docs/rule-spec.md`, `docs/report-schema-spec.md`
- Target audience: `docs/target-audience.md`
- Product direction: `docs/product-roadmap.md`
- Architecture: `docs/architecture.md`, `docs/rust/README.md`
- Safety policy: `docs/safety-boundary.md`
- Cross-repo relationship: `docs/repo-bridge.md`
- Demo workflow: `demo/runbook.md`
- Generated reports: `reports/`

Prefer small, explicit docs over nested complexity.

## Engineering Defaults

- Use `python3` in commands and examples.
- Keep the CLI read-only unless a design doc explicitly changes that boundary.
- Add tests for scanner behavior, parser behavior, report format changes, and
  safety-relevant changes.
- Keep demo fixtures small and inspectable.
- Keep generated output rebuildable.
- Do not introduce a web app, dashboard, telemetry service, or cloud workflow
  unless the product roadmap explicitly says that is the current phase.

## Completion Git Rule

After completing a prompt task in this repo, update Git before final handoff.

Required closeout:

- Split unrelated changes into separate logical commits.
- Before each commit, verify staged scope with `git diff --cached --stat` and
  `git diff --cached --name-status`.
- Run the smallest relevant validation gate before committing. For scanner or
  product-doc changes, prefer `make product-check` plus `git diff --check`.
- Push the completed branch state to GitHub `main` with `git push origin HEAD:main`
  when `origin/main` is an ancestor of `HEAD`.
- Fetch and re-check ancestry before publishing if remote state may have moved.
- Never force push.
- Never auto-resolve conflicts.
- If the remote is missing, unreachable, divergent, or unsafe to update, stop
  before pushing and report the blocker with the local commit hashes.

## Planning / Agenda Questions

If asked whether to add product work now, check the planning repo first. The
planning repo is the control plane for capacity. If current plans are overloaded,
recommend shrinking or parking product work rather than stealing from sleep,
health, family, or recovery.
