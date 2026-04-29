use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bloom::HashBloomFilter;

#[derive(Debug, Clone, Serialize)]
pub struct SignatureSummary {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub struct HashSignatureMatcher {
    pub signature: SignatureSummary,
    pub matcher_type: String,
}

#[derive(Debug, Clone)]
pub struct PatternSignatureMatcher {
    pub signature: SignatureSummary,
    pub matcher_type: String,
    pub pattern: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignatureDatabase {
    pub schema_version: String,
    pub signatures: Vec<SignatureSummary>,
    pub hash_index: HashMap<String, HashMap<String, Vec<HashSignatureMatcher>>>,
    pub hash_filter: HashBloomFilter,
    pub patterns: Vec<PatternSignatureMatcher>,
}

#[derive(Debug, Deserialize)]
struct RawDatabase {
    schema_version: String,
    signatures: Vec<RawSignature>,
}

#[derive(Debug, Deserialize)]
struct RawSignature {
    id: String,
    name: String,
    category: String,
    severity: String,
    matchers: Vec<RawMatcher>,
    #[allow(dead_code)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMatcher {
    #[serde(rename = "type")]
    matcher_type: String,
    value: String,
}

impl SignatureDatabase {
    pub fn hash_matcher_count(&self) -> usize {
        self.hash_index
            .values()
            .map(|digest_map| digest_map.values().map(Vec::len).sum::<usize>())
            .sum()
    }
}

pub fn load_signature_database(path: &Path) -> Result<SignatureDatabase, String> {
    let text = fs::read_to_string(path).map_err(|err| {
        format!(
            "could not read signature database {}: {err}",
            path.display()
        )
    })?;
    let raw: RawDatabase = serde_json::from_str(&text)
        .map_err(|err| format!("invalid signature database JSON {}: {err}", path.display()))?;
    parse_signature_database(raw)
}

fn parse_signature_database(raw: RawDatabase) -> Result<SignatureDatabase, String> {
    if raw.schema_version.trim().is_empty() {
        return Err("signature database requires a non-empty schema_version".to_string());
    }
    if raw.signatures.is_empty() {
        return Err("signature database requires at least one signature".to_string());
    }

    let mut seen_ids = HashSet::new();
    let mut signatures = Vec::new();
    let mut hash_index: HashMap<String, HashMap<String, Vec<HashSignatureMatcher>>> =
        HashMap::from([
            ("md5".to_string(), HashMap::new()),
            ("sha256".to_string(), HashMap::new()),
        ]);
    let mut patterns = Vec::new();
    let mut bloom_keys = Vec::new();

    for raw_signature in raw.signatures {
        validate_signature(&raw_signature, &mut seen_ids)?;
        let summary = SignatureSummary {
            id: raw_signature.id.trim().to_string(),
            name: raw_signature.name.trim().to_string(),
            category: raw_signature.category.trim().to_string(),
            severity: raw_signature.severity.trim().to_lowercase(),
        };
        signatures.push(summary.clone());

        for raw_matcher in raw_signature.matchers {
            let matcher_type = raw_matcher.matcher_type.trim().to_lowercase();
            let value = raw_matcher.value.trim().to_lowercase();
            match matcher_type.as_str() {
                "md5" | "sha256" => {
                    validate_hash(&summary.id, &matcher_type, &value)?;
                    hash_index
                        .entry(matcher_type.clone())
                        .or_default()
                        .entry(value.clone())
                        .or_default()
                        .push(HashSignatureMatcher {
                            signature: summary.clone(),
                            matcher_type: matcher_type.clone(),
                        });
                    bloom_keys.push(format!("{matcher_type}:{value}"));
                }
                "hex_pattern" => {
                    let compact = value.replace(' ', "");
                    validate_hex_pattern(&summary.id, &compact)?;
                    let pattern = hex::decode(&compact)
                        .map_err(|err| format!("{} has invalid hex_pattern: {err}", summary.id))?;
                    patterns.push(PatternSignatureMatcher {
                        signature: summary.clone(),
                        matcher_type,
                        pattern,
                    });
                }
                other => {
                    return Err(format!(
                        "{} has unsupported matcher type {other:?}; use md5, sha256, or hex_pattern",
                        summary.id
                    ));
                }
            }
        }
    }

    let hash_filter = HashBloomFilter::from_keys(bloom_keys);
    Ok(SignatureDatabase {
        schema_version: raw.schema_version,
        signatures,
        hash_index,
        hash_filter,
        patterns,
    })
}

fn validate_signature(raw: &RawSignature, seen_ids: &mut HashSet<String>) -> Result<(), String> {
    let signature_id = raw.id.trim();
    if signature_id.is_empty() {
        return Err("signature id is required".to_string());
    }
    if !seen_ids.insert(signature_id.to_string()) {
        return Err(format!("duplicate signature id: {signature_id}"));
    }
    if raw.name.trim().is_empty() {
        return Err(format!("{signature_id} requires a non-empty name"));
    }
    if raw.category.trim().is_empty() {
        return Err(format!("{signature_id} requires a non-empty category"));
    }
    if !matches!(
        raw.severity.trim().to_lowercase().as_str(),
        "info" | "low" | "medium" | "high" | "critical"
    ) {
        return Err(format!(
            "{} has invalid severity {}",
            signature_id, raw.severity
        ));
    }
    if raw.matchers.is_empty() {
        return Err(format!("{signature_id} requires at least one matcher"));
    }
    Ok(())
}

fn validate_hash(signature_id: &str, matcher_type: &str, value: &str) -> Result<(), String> {
    let expected = match matcher_type {
        "md5" => 32,
        "sha256" => 64,
        _ => unreachable!("validated caller"),
    };
    if value.len() != expected || !is_hex(value) {
        return Err(format!(
            "{signature_id} {matcher_type} value must be {expected} hex characters"
        ));
    }
    Ok(())
}

fn validate_hex_pattern(signature_id: &str, value: &str) -> Result<(), String> {
    if value.len() < 4 || !value.len().is_multiple_of(2) || !is_hex(value) {
        return Err(format!(
            "{signature_id} hex_pattern must be even-length hex with at least 2 bytes"
        ));
    }
    Ok(())
}

fn is_hex(value: &str) -> bool {
    value.chars().all(|character| character.is_ascii_hexdigit())
}

pub fn severity_rank(value: &str) -> i32 {
    match value {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_signature_database, RawDatabase, RawMatcher, RawSignature};

    #[test]
    fn parses_hash_and_pattern_matchers() {
        let raw = RawDatabase {
            schema_version: "1.0".to_string(),
            signatures: vec![RawSignature {
                id: "sig-test".to_string(),
                name: "Test".to_string(),
                category: "safe".to_string(),
                severity: "critical".to_string(),
                matchers: vec![
                    RawMatcher {
                        matcher_type: "md5".to_string(),
                        value: "0123456789abcdef0123456789abcdef".to_string(),
                    },
                    RawMatcher {
                        matcher_type: "hex_pattern".to_string(),
                        value: "41424344".to_string(),
                    },
                ],
                notes: None,
            }],
        };
        let database = parse_signature_database(raw).expect("database should parse");
        assert_eq!(database.signatures.len(), 1);
        assert_eq!(database.hash_matcher_count(), 1);
        assert_eq!(database.patterns.len(), 1);
    }
}
