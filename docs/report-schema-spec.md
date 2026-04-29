# Report Schema Spec

Draft schemas live in:

- `schemas/sentinel-report.schema.json`
- `schemas/sentinel-manifest.schema.json`

## Report Requirements

Each scan report should preserve:

- scanner identity
- scanner version
- rulepack or signature schema version
- target path
- start and finish timestamps
- scan-engine metadata
- summary counts
- findings
- full per-file results

## File Result Requirements

Each file result should include:

```json
{
  "path": "fixtures/eicar.com",
  "size_bytes": 68,
  "sha256": "...",
  "status": "matched",
  "matches": [
    {
      "rule_id": "demo.eicar.standard",
      "rule_name": "EICAR Standard Anti-Virus Test File",
      "severity": "demo",
      "confidence": "high",
      "evidence_type": "literal_pattern",
      "explanation": "Matched safe EICAR test fixture pattern."
    }
  ],
  "errors": []
}
```

## Current Implementation Gap

The current course-derived report uses `infected` and `critical` for EICAR. MVP
hardening should migrate safe test fixtures toward `matched` / `demo` wording so
the product does not overclaim malware confirmation.

## Summary Requirements

Target summary:

```json
{
  "files_total": 100,
  "files_scanned": 96,
  "files_matched": 2,
  "files_skipped": 4,
  "highest_severity": "medium",
  "policy_result": "passed_with_warnings"
}
```
