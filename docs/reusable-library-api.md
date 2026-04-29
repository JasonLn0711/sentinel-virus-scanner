# Reusable Library API

The strongest product path is to make Sentinel reusable by other repos.

Target crate layout:

```text
crates/
  sentinel-core/
  sentinel-cli/
  sentinel-report/
  sentinel-rules/
  sentinel-manifest/
  sentinel-policy/
```

## `sentinel-core`

Reusable scanner engine.

Target functions:

```rust
scan_path()
scan_file()
scan_bytes()
scan_directory()
```

Use case: another project can scan generated artifacts before accepting,
executing, committing, or submitting them.

## `sentinel-rules`

Rule loading, validation, and matching.

Target functions:

```rust
load_rulepack()
validate_rulepack()
match_rules()
explain_match()
```

Use case: a phishing or scam-research repo can define project-specific HTML,
JavaScript, archive, and filename rules.

## `sentinel-report`

Report rendering.

Target functions:

```rust
to_json_report()
to_markdown_report()
to_terminal_summary()
```

Use case: paper and course repos can attach scan evidence to submission
packages.

## `sentinel-manifest`

Reproducibility layer.

Target functions:

```rust
generate_manifest()
verify_manifest()
compare_manifests()
hash_artifact_tree()
```

Use case: research repos can prove what files were scanned and whether they
changed.

## `sentinel-policy`

Optional later layer.

Target functions:

```rust
evaluate_policy()
block_on_high_severity()
warn_on_demo_match()
allow_clean_only()
```

Use case: an AI-agent gateway can block execution when generated files match a
high-severity rule.
