mod bloom;
mod evidence;
mod patterns;
mod reporting;
mod scanner;
mod signatures;

use evidence::{write_evidence_manifest, EvidenceArgs};
use std::fs;
use std::path::{Path, PathBuf};

use reporting::{write_json_report, write_markdown_report};
use scanner::{scan_directory, Report};
use signatures::load_signature_database;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const EICAR_DEMO_RELATIVE_PATH: &str = "nested/level-1/level-2/eicar.com.txt";
const EICAR_PARTS: &[&[u8]] = &[
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}",
    b"$EICAR-STANDARD-ANTIVIRUS-",
    b"TEST-FILE!$H+H*",
];
const EXPECTED_INFECTED_PATH: &str = EICAR_DEMO_RELATIVE_PATH;
const EXPECTED_SUSPICIOUS_PATH: &str = "suspicious/api-names-fixture.txt";

#[derive(Debug)]
struct ScanArgs {
    target: PathBuf,
    signatures: PathBuf,
    json_report: PathBuf,
    markdown_report: PathBuf,
}

#[derive(Debug)]
struct EvidenceCliArgs {
    target: PathBuf,
    signatures: PathBuf,
    reports: Vec<PathBuf>,
    output: PathBuf,
}

fn main() {
    let exit_code = match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            2
        }
    };
    std::process::exit(exit_code);
}

fn run(args: Vec<String>) -> Result<i32, String> {
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("sentinel-virus-scanner {VERSION}");
            Ok(0)
        }
        Some("validate-signatures") => {
            let signatures = parse_value_arg(&args[1..], "--signatures")
                .map(PathBuf::from)
                .unwrap_or_else(default_signature_path);
            let database = load_signature_database(&signatures)?;
            println!(
                "signature database ok: schema={} signatures={} hash_matchers={} patterns={}",
                database.schema_version,
                database.signatures.len(),
                database.hash_matcher_count(),
                database.patterns.len()
            );
            Ok(0)
        }
        Some("prepare-eicar-demo") => {
            let target = parse_value_arg(&args[1..], "--target")
                .map(PathBuf::from)
                .unwrap_or_else(default_target_path);
            let path = prepare_eicar_demo_fixture(&target)?;
            println!(
                "EICAR demo fixture written: {} bytes={}",
                path.display(),
                eicar_test_bytes().len()
            );
            Ok(0)
        }
        Some("scan") => {
            let scan_args = parse_scan_args(&args[1..])?;
            let database = load_signature_database(&scan_args.signatures)?;
            let report = scan_directory(&scan_args.target, &database)?;
            write_json_report(&report, &scan_args.json_report)?;
            write_markdown_report(&report, &scan_args.markdown_report)?;

            println!(
                "Sentinel Virus Scanner scan complete: scanned={} infected={} suspicious={} clean={} errors={} json={} markdown={}",
                report.summary.files_scanned,
                report.summary.infected,
                report.summary.suspicious,
                report.summary.clean,
                report.summary.error,
                scan_args.json_report.display(),
                scan_args.markdown_report.display()
            );

            if report.summary.infected > 0 {
                Ok(1)
            } else {
                Ok(0)
            }
        }
        Some("verify-demo") => {
            let target = parse_value_arg(&args[1..], "--target")
                .map(PathBuf::from)
                .unwrap_or_else(default_target_path);
            let signatures = parse_value_arg(&args[1..], "--signatures")
                .map(PathBuf::from)
                .unwrap_or_else(default_signature_path);
            prepare_eicar_demo_fixture(&target)?;
            let database = load_signature_database(&signatures)?;
            let report = scan_directory(&target, &database)?;
            verify_expected_demo_report(&report)?;
            println!(
                "Rust demo verification passed: scanned={} infected={} suspicious={} clean={} skipped={} errors={}",
                report.summary.files_scanned,
                report.summary.infected,
                report.summary.suspicious,
                report.summary.clean,
                report.summary.skipped,
                report.summary.error
            );
            Ok(0)
        }
        Some("write-evidence") => {
            let evidence_args = parse_evidence_args(&args[1..]);
            write_evidence_manifest(&EvidenceArgs {
                target: evidence_args.target,
                signatures: evidence_args.signatures,
                reports: evidence_args.reports,
                output: evidence_args.output.clone(),
            })?;
            println!(
                "Rust evidence manifest written: {}",
                evidence_args.output.display()
            );
            Ok(0)
        }
        _ => {
            print_usage();
            Ok(2)
        }
    }
}

fn verify_expected_demo_report(report: &Report) -> Result<(), String> {
    check_value("summary.files_scanned", report.summary.files_scanned, 5)?;
    check_value("summary.infected", report.summary.infected, 1)?;
    check_value("summary.suspicious", report.summary.suspicious, 1)?;
    check_value("summary.clean", report.summary.clean, 3)?;
    check_value("summary.skipped", report.summary.skipped, 0)?;
    check_value("summary.error", report.summary.error, 0)?;

    let metadata = &report.scan_metadata;
    check_string(
        "scan_metadata.hash_filter",
        &metadata.hash_filter,
        "bloom-filter",
    )?;
    check_string(
        "scan_metadata.hash_filter_policy",
        &metadata.hash_filter_policy,
        "precheck-then-exact-hash-map",
    )?;
    check_string(
        "scan_metadata.pattern_engine",
        &metadata.pattern_engine,
        "aho-corasick-byte-automaton",
    )?;
    check_value(
        "scan_metadata.chunk_size_bytes",
        metadata.chunk_size_bytes,
        1_048_576,
    )?;
    check_value(
        "scan_metadata.heuristic_sample_limit_bytes",
        metadata.heuristic_sample_limit_bytes,
        1_048_576,
    )?;
    check_string(
        "scan_metadata.symlink_policy",
        &metadata.symlink_policy,
        "skip",
    )?;
    check_string(
        "scan_metadata.traversal_policy",
        &metadata.traversal_policy,
        "deterministic-rglob-files",
    )?;

    let infected = report_finding(report, EXPECTED_INFECTED_PATH)?;
    let mut matchers = infected
        .matches
        .iter()
        .map(|signature_match| signature_match.matcher.as_str())
        .collect::<Vec<_>>();
    matchers.sort_unstable();
    if matchers != ["hex_pattern", "md5", "sha256"] {
        return Err(format!(
            "{EXPECTED_INFECTED_PATH} matchers were {matchers:?}; expected md5, sha256, and hex_pattern"
        ));
    }
    if !infected
        .matches
        .iter()
        .any(|item| item.pattern_offset.is_some())
    {
        return Err(format!(
            "{EXPECTED_INFECTED_PATH} is missing byte-pattern offset evidence"
        ));
    }

    let suspicious = report_finding(report, EXPECTED_SUSPICIOUS_PATH)?;
    check_string(
        "suspicious fixture status",
        &suspicious.status,
        "suspicious",
    )?;
    if suspicious.heuristics.is_empty() {
        return Err(format!(
            "{EXPECTED_SUSPICIOUS_PATH} is missing heuristic evidence"
        ));
    }

    Ok(())
}

fn prepare_eicar_demo_fixture(target: &Path) -> Result<PathBuf, String> {
    let path = target.join(EICAR_DEMO_RELATIVE_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| format!("could not resolve parent for {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "could not create EICAR demo directory {}: {err}",
            parent.display()
        )
    })?;
    fs::write(&path, eicar_test_bytes()).map_err(|err| {
        format!(
            "could not write EICAR demo fixture {}: {err}",
            path.display()
        )
    })?;
    Ok(path)
}

fn eicar_test_bytes() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(68);
    for part in EICAR_PARTS {
        bytes.extend_from_slice(part);
    }
    bytes
}

fn report_finding<'a>(report: &'a Report, path: &str) -> Result<&'a scanner::FileResult, String> {
    report
        .all_results
        .iter()
        .find(|result| result.path == path)
        .ok_or_else(|| format!("missing scan result for {path}"))
}

fn check_value(label: &str, actual: usize, expected: usize) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label} was {actual}; expected {expected}"))
    }
}

fn check_string(label: &str, actual: &str, expected: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label} was {actual:?}; expected {expected:?}"))
    }
}

fn parse_scan_args(args: &[String]) -> Result<ScanArgs, String> {
    Ok(ScanArgs {
        target: parse_value_arg(args, "--target")
            .map(PathBuf::from)
            .unwrap_or_else(default_target_path),
        signatures: parse_value_arg(args, "--signatures")
            .map(PathBuf::from)
            .unwrap_or_else(default_signature_path),
        json_report: parse_value_arg(args, "--json")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("../reports/demo-report.json")),
        markdown_report: parse_value_arg(args, "--markdown")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("../reports/demo-report.md")),
    })
}

fn parse_evidence_args(args: &[String]) -> EvidenceCliArgs {
    let reports = parse_value_args(args, "--report")
        .into_iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    EvidenceCliArgs {
        target: parse_value_arg(args, "--target")
            .map(PathBuf::from)
            .unwrap_or_else(default_target_path),
        signatures: parse_value_arg(args, "--signatures")
            .map(PathBuf::from)
            .unwrap_or_else(default_signature_path),
        reports: if reports.is_empty() {
            vec![
                PathBuf::from("../reports/demo-report.json"),
                PathBuf::from("../reports/demo-report.md"),
            ]
        } else {
            reports
        },
        output: parse_value_arg(args, "--output")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("../reports/demo-evidence-manifest.json")),
    }
}

fn parse_value_arg(args: &[String], name: &str) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == name {
            return args.get(index + 1).cloned();
        }
        index += 1;
    }
    None
}

fn parse_value_args(args: &[String], name: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index] == name {
            if let Some(value) = args.get(index + 1) {
                values.push(value.clone());
            }
        }
        index += 1;
    }
    values
}

fn default_signature_path() -> PathBuf {
    first_existing(&[
        "signatures/malware-signatures.json",
        "../signatures/malware-signatures.json",
    ])
}

fn default_target_path() -> PathBuf {
    first_existing(&["demo/demo-tree", "../demo/demo-tree"])
}

fn first_existing(candidates: &[&str]) -> PathBuf {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from(candidates[0]))
}

fn print_usage() {
    eprintln!(
        "Usage:\n  sentinel-virus-scanner --version\n  sentinel-virus-scanner validate-signatures --signatures <path>\n  sentinel-virus-scanner prepare-eicar-demo --target <dir>\n  sentinel-virus-scanner scan --target <dir> --signatures <path> --json <path> --markdown <path>\n  sentinel-virus-scanner verify-demo --target <dir> --signatures <path>\n  sentinel-virus-scanner write-evidence --target <dir> --signatures <path> --report <path> --output <path>"
    );
}

#[cfg(test)]
mod tests {
    use super::run;
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn validates_project_signature_database() {
        let code = run(vec![
            "validate-signatures".to_string(),
            "--signatures".to_string(),
            project_root()
                .join("signatures/malware-signatures.json")
                .display()
                .to_string(),
        ])
        .expect("validation should run");

        assert_eq!(code, 0);
    }

    #[test]
    fn scan_demo_tree_returns_detection_code_and_writes_reports() {
        let demo_tree = prepared_temp_demo_tree();
        let output = unique_temp_dir();
        fs::create_dir_all(&output).expect("temp output should be created");
        let json_report = output.join("demo-report.json");
        let markdown_report = output.join("demo-report.md");

        let code = run(vec![
            "scan".to_string(),
            "--target".to_string(),
            demo_tree.display().to_string(),
            "--signatures".to_string(),
            project_root()
                .join("signatures/malware-signatures.json")
                .display()
                .to_string(),
            "--json".to_string(),
            json_report.display().to_string(),
            "--markdown".to_string(),
            markdown_report.display().to_string(),
        ])
        .expect("scan should run");

        let report: Value = serde_json::from_str(
            &fs::read_to_string(&json_report).expect("JSON report should be written"),
        )
        .expect("JSON report should parse");

        assert_eq!(code, 1);
        assert_eq!(report["summary"]["files_scanned"], 5);
        assert_eq!(report["summary"]["infected"], 1);
        assert_eq!(report["summary"]["suspicious"], 1);
        assert_eq!(report["summary"]["clean"], 3);
        assert_eq!(report["scan_metadata"]["chunk_size_bytes"], 1_048_576);
        assert!(markdown_report.is_file());

        let _ = fs::remove_dir_all(output);
        let _ = fs::remove_dir_all(demo_tree.parent().expect("demo tree has a temp parent"));
    }

    #[test]
    fn verifies_expected_project_demo_summary() {
        let demo_tree = prepared_temp_demo_tree();
        let code = run(vec![
            "verify-demo".to_string(),
            "--target".to_string(),
            demo_tree.display().to_string(),
            "--signatures".to_string(),
            project_root()
                .join("signatures/malware-signatures.json")
                .display()
                .to_string(),
        ])
        .expect("demo verification should run");

        assert_eq!(code, 0);
        let _ = fs::remove_dir_all(demo_tree.parent().expect("demo tree has a temp parent"));
    }

    #[test]
    fn writes_rust_evidence_manifest() {
        let demo_tree = prepared_temp_demo_tree();
        let output = unique_temp_dir();
        fs::create_dir_all(&output).expect("temp output should be created");
        let json_report = output.join("demo-report.json");
        let markdown_report = output.join("demo-report.md");
        let evidence_manifest = output.join("demo-evidence-manifest.json");

        let scan_code = run(vec![
            "scan".to_string(),
            "--target".to_string(),
            demo_tree.display().to_string(),
            "--signatures".to_string(),
            project_root()
                .join("signatures/malware-signatures.json")
                .display()
                .to_string(),
            "--json".to_string(),
            json_report.display().to_string(),
            "--markdown".to_string(),
            markdown_report.display().to_string(),
        ])
        .expect("scan should run");
        assert_eq!(scan_code, 1);

        let evidence_code = run(vec![
            "write-evidence".to_string(),
            "--target".to_string(),
            demo_tree.display().to_string(),
            "--signatures".to_string(),
            project_root()
                .join("signatures/malware-signatures.json")
                .display()
                .to_string(),
            "--report".to_string(),
            json_report.display().to_string(),
            "--report".to_string(),
            markdown_report.display().to_string(),
            "--output".to_string(),
            evidence_manifest.display().to_string(),
        ])
        .expect("evidence manifest should be written");
        assert_eq!(evidence_code, 0);

        let manifest: Value = serde_json::from_str(
            &fs::read_to_string(&evidence_manifest).expect("manifest should be written"),
        )
        .expect("manifest should parse");
        assert_eq!(manifest["manifest_type"], "rust-demo-evidence");
        assert_eq!(manifest["safety"]["read_only_scanner"], true);
        assert_eq!(manifest["safety"]["uses_live_malware"], false);
        assert_eq!(
            manifest["demo_tree"]
                .as_array()
                .expect("demo tree array")
                .len(),
            5
        );
        assert_eq!(manifest["reports"][0]["summary"]["infected"], 1);

        let _ = fs::remove_dir_all(output);
        let _ = fs::remove_dir_all(demo_tree.parent().expect("demo tree has a temp parent"));
    }

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("rust folder should have a project parent")
            .to_path_buf()
    }

    fn prepared_temp_demo_tree() -> PathBuf {
        let temp_root = unique_temp_dir();
        let demo_tree = temp_root.join("demo-tree");
        copy_demo_tree(&project_root().join("demo/demo-tree"), &demo_tree);
        let code = run(vec![
            "prepare-eicar-demo".to_string(),
            "--target".to_string(),
            demo_tree.display().to_string(),
        ])
        .expect("EICAR demo fixture should be prepared");
        assert_eq!(code, 0);
        demo_tree
    }

    fn copy_demo_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("destination demo tree should be created");
        for entry in fs::read_dir(source).expect("source demo tree should be readable") {
            let entry = entry.expect("demo tree entry should be readable");
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if source_path.file_name().and_then(|value| value.to_str()) == Some("eicar.com.txt") {
                continue;
            }
            if source_path.is_dir() {
                copy_demo_tree(&source_path, &destination_path);
            } else if source_path.is_file() {
                fs::copy(&source_path, &destination_path)
                    .expect("demo tree fixture should be copied");
            }
        }
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sentinel-virus-scanner-test-{}-{nanos}",
            std::process::id()
        ))
    }
}
