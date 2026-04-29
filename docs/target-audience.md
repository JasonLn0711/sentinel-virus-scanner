# Target Audience

This note treats `TA` as target audience.

## Primary Target Audience

Sentinel Artifact Scanner should first serve security learners and junior
security engineers who need a transparent scanner they can inspect, run locally,
and use to understand detection evidence.

They care about:

- what was scanned
- why a file was flagged
- which signature or heuristic triggered
- whether the demo is safe
- how to reproduce the result
- how scanner internals map to real security concepts

## Secondary Target Audience

1. Course instructors, teaching assistants, and lab maintainers
   - Need a safe scanner demo that avoids live malware.
   - Need evidence artifacts that students can reproduce.
   - Need clear boundaries between demo, report, and implementation.

2. Small security-learning teams
   - Need a local CLI for rule experiments.
   - Need easy-to-read JSON/Markdown reports.
   - Need a safe fixture tree for workshops or internal practice.

3. Early security-tool builders
   - Need an understandable Rust baseline for matching engines, report formats,
     and safety-first CLI design.
   - Need a repo that can grow into packaging, testing, and release workflows.

4. Internal research and product projects
   - Need an artifact preflight scanner before generated files are executed,
     committed, submitted, zipped, or shared.
   - Need reusable evidence manifests for paper, lab, and agent workflows.

## Not The Target Audience Yet

Sentinel is not yet aimed at:

- ordinary consumers who need endpoint protection
- enterprises expecting EDR coverage
- SOC teams needing SIEM integrations
- malware researchers handling live samples
- incident responders making production containment decisions

Those users need stronger detection coverage, update infrastructure,
operational controls, telemetry design, false-positive handling, and legal or
organizational process that this repo does not yet provide.

## Product Promise

Sentinel should promise:

- safe local scanning
- explainable matching evidence
- reproducible reports
- controlled demo behavior
- clear limits

Sentinel should not promise:

- complete malware detection
- production antivirus replacement
- automatic cleanup
- enterprise endpoint monitoring
- protection against active compromise

## First Product Wedge

The strongest first wedge is:

> A transparent, safe, local-first malware-scanning lab and CLI that turns
> rule matches into reproducible evidence.

That wedge is narrow enough to be honest and useful enough to become a real
product line later.
