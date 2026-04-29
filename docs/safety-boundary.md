# Safety Boundary

Sentinel Artifact Scanner is a defensive, read-only scanner product seed. Its
current safe use case is controlled local scanning against benign fixtures,
project artifacts, and the generated EICAR safe anti-malware test file.

## Allowed

- scan explicit local target paths
- use benign demo fixtures
- generate the EICAR safe anti-malware test file for controlled demos
- write JSON and Markdown reports
- write reproducibility evidence manifests
- add tests for parser, matcher, traversal, and report behavior

## Not Allowed In This Repo

- live malware samples
- downloading malware
- executing scanned files
- mutating, deleting, or quarantining scanned files
- uploading files to a service
- background monitoring or persistence
- whole-machine scanning as a default command
- production antivirus or EDR claims without evidence
- unsupported claims that a file is confirmed malware

## Before Adding Riskier Features

Write a design note first if a future change would add:

- quarantine or deletion
- network submission
- live-sample handling
- privileged filesystem access
- background service behavior
- automatic remediation
- large-scale scanning

The note should define the user need, abuse case, failure mode, rollback plan,
and tests before implementation.

## Demo Fixture Rule

The generated EICAR file is safe, but many security products intentionally flag
it. Keep it generated at demo time and ignored by Git.
