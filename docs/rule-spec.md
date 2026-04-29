# Rule Spec

## Severity Model

| Severity | Meaning |
| --- | --- |
| `demo` | Safe test fixture, such as EICAR |
| `info` | Interesting but harmless |
| `low` | Suspicious metadata or extension |
| `medium` | Suspicious pattern requiring review |
| `high` | Known risky signature or unsafe artifact |
| `critical` | Strong match requiring immediate stop |

Avoid saying `malware confirmed` unless a rule and review workflow truly support
that claim.

Preferred wording:

```text
matched_rule
requires_review
known_test_fixture
blocked_by_policy
```

## Example Demo Rule

```toml
[[rules]]
id = "demo.eicar.standard"
name = "EICAR Standard Anti-Virus Test File"
severity = "demo"
confidence = "high"
type = "literal"
pattern = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
description = "Safe anti-malware test fixture."
recommendation = "Use only for scanner testing. Do not treat as real malware."
```

## Example Review Rule

```toml
[[rules]]
id = "script.suspicious.curl-pipe-shell"
name = "Suspicious curl pipe shell pattern"
severity = "medium"
confidence = "medium"
type = "regex"
pattern = "curl\\s+.*\\|\\s*(sh|bash)"
description = "Detects scripts that download remote content and pipe it directly into a shell."
recommendation = "Review source URL, execution context, and whether this is expected."
```

## YARA Direction

Future work can support:

- YARA rule import
- a YARA-like subset
- optional external YARA integration

YARA compatibility is a future bridge for learners and researchers, not a
requirement for the first MVP.
