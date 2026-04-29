use std::fs;
use std::path::Path;

use crate::scanner::{FileResult, Report, SignatureMatch};

pub fn write_json_report(report: &Report, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "could not create report directory {}: {err}",
                parent.display()
            )
        })?;
    }
    let text = serde_json::to_string_pretty(report)
        .map_err(|err| format!("could not serialize JSON report: {err}"))?;
    fs::write(path, format!("{text}\n"))
        .map_err(|err| format!("could not write JSON report {}: {err}", path.display()))
}

pub fn write_markdown_report(report: &Report, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "could not create report directory {}: {err}",
                parent.display()
            )
        })?;
    }
    fs::write(path, render_markdown_report(report))
        .map_err(|err| format!("could not write Markdown report {}: {err}", path.display()))
}

fn render_markdown_report(report: &Report) -> String {
    let mut lines = vec![
        "# Sentinel Virus Scanner Scan Report".to_string(),
        String::new(),
        "## Run Metadata".to_string(),
        String::new(),
        format!("- Tool: `{}`", md(&report.tool)),
        format!("- Target: `{}`", md(&report.target)),
        format!(
            "- Signature schema: `{}`",
            md(&report.signature_schema_version)
        ),
        format!("- Started: `{}`", md(&report.started_at)),
        format!("- Finished: `{}`", md(&report.finished_at)),
        String::new(),
        "## Scan Engine".to_string(),
        String::new(),
        format!("- Hash pre-check: `{}`", report.scan_metadata.hash_filter),
        format!(
            "- Hash filter items: `{}`",
            report.scan_metadata.hash_filter_items
        ),
        format!(
            "- Hash filter bits: `{}`",
            report.scan_metadata.hash_filter_bits
        ),
        format!(
            "- Hash filter policy: `{}`",
            report.scan_metadata.hash_filter_policy
        ),
        format!(
            "- Pattern engine: `{}`",
            report.scan_metadata.pattern_engine
        ),
        format!("- Pattern count: `{}`", report.scan_metadata.pattern_count),
        format!(
            "- Automaton states: `{}`",
            report.scan_metadata.automaton_states
        ),
        format!(
            "- Chunk size bytes: `{}`",
            report.scan_metadata.chunk_size_bytes
        ),
        format!(
            "- Heuristic sample limit bytes: `{}`",
            report.scan_metadata.heuristic_sample_limit_bytes
        ),
        format!(
            "- Heuristic engine: `{}`",
            md(&report.scan_metadata.heuristic_engine)
        ),
        format!(
            "- Heuristic rules: `{}`",
            md(&report.scan_metadata.heuristic_rules.join(", "))
        ),
        format!(
            "- Symlink policy: `{}`",
            report.scan_metadata.symlink_policy
        ),
        String::new(),
        "## Summary".to_string(),
        String::new(),
        "| Metric | Count |".to_string(),
        "| --- | ---: |".to_string(),
        format!("| Files scanned | {} |", report.summary.files_scanned),
        format!("| Infected | {} |", report.summary.infected),
        format!("| Suspicious | {} |", report.summary.suspicious),
        format!("| Clean | {} |", report.summary.clean),
        format!("| Skipped | {} |", report.summary.skipped),
        format!("| Errors | {} |", report.summary.error),
        String::new(),
        "## Findings".to_string(),
        String::new(),
    ];

    if report.findings.is_empty() {
        lines.push("No infected, suspicious, skipped, or error results were found.".to_string());
    } else {
        lines.push("| Path | Status | Severity | Evidence |".to_string());
        lines.push("| --- | --- | --- | --- |".to_string());
        for finding in &report.findings {
            lines.push(format!(
                "| `{}` | {} | {} | {} |",
                md(&finding.path),
                md(&finding.status),
                md(&finding.severity),
                md(&finding_evidence(finding))
            ));
        }
    }

    lines.extend([
        String::new(),
        "## All Results".to_string(),
        String::new(),
        "| Path | Status | Severity | Size | SHA-256 |".to_string(),
        "| --- | --- | --- | ---: | --- |".to_string(),
    ]);
    for result in &report.all_results {
        lines.push(format!(
            "| `{}` | {} | {} | {} | `{}` |",
            md(&result.path),
            md(&result.status),
            md(&result.severity),
            result
                .size_bytes
                .map(|value| value.to_string())
                .unwrap_or_default(),
            md(result.sha256.as_deref().unwrap_or(""))
        ));
    }

    format!("{}\n", lines.join("\n"))
}

fn finding_evidence(finding: &FileResult) -> String {
    let mut evidence = Vec::new();
    for signature_match in &finding.matches {
        evidence.push(match_evidence(signature_match));
    }
    for heuristic in &finding.heuristics {
        evidence.push(format!("{} ({})", heuristic.rule_id, heuristic.evidence));
    }
    if let Some(skip_reason) = &finding.skip_reason {
        evidence.push(format!("skipped: {skip_reason}"));
    }
    if let Some(error) = &finding.error {
        evidence.push(format!("error: {error}"));
    }
    if evidence.is_empty() {
        "-".to_string()
    } else {
        evidence.join("; ")
    }
}

fn match_evidence(signature_match: &SignatureMatch) -> String {
    let mut evidence = format!(
        "{}:{}",
        signature_match.matcher, signature_match.signature_id
    );
    if let Some(offset) = signature_match.pattern_offset {
        evidence.push_str(&format!("@{offset}"));
    }
    evidence
}

fn md(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}
