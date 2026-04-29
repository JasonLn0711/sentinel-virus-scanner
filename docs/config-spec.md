# Config Spec

Target file: `sentinel.toml`

See `sentinel.example.toml` for a starter config.

## Fields

```toml
[scan]
recursive = true
follow_symlinks = false
max_file_size_mb = 50
hash_algorithms = ["sha256"]

[ignore]
paths = [
  ".git",
  "target",
  "node_modules",
  ".venv"
]

[rules]
rulepack = "rules/demo-rules.toml"

[report]
json = "reports/sentinel-report.json"
markdown = "reports/sentinel-report.md"
manifest = "reports/evidence-manifest.json"

[policy]
fail_on = "high"
warn_on = "medium"
allow_demo_fixtures = true
```

## Product Intent

Config support should make Sentinel usable as a repeatable preflight check in
other repos without requiring long shell commands.

Config files should be local, explicit, and reviewable. Do not add remote
rulepack fetching before a separate supply-chain safety design exists.
