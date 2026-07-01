//! SARIF 2.1.0 report emitter.
//!
//! Emits a [Static Analysis Results Interchange Format][sarif] 2.1.0 log so
//! `zk-guard scan --format sarif` can be uploaded to GitHub code scanning
//! (via `github/codeql-action/upload-sarif`) or any other SARIF-aware
//! consumer. See `docs/sarif.md` for the field mapping and a GitHub Actions
//! example.
//!
//! Unlike [`crate::json`] (which serializes [`ScanResult`] verbatim), SARIF
//! needs the *rule registry* too: every rule becomes a `reportingDescriptor`
//! under `tool.driver.rules`, and every [`Finding`] becomes a `result` that
//! references its descriptor by `ruleId` (stable) and `ruleIndex` (position
//! in that array). The renderer therefore takes both the scan result and the
//! metadata of every rule that ran.
//!
//! Determinism (per CLAUDE.md design principle 5): the descriptor array
//! follows registry order, the result array follows finding order, and every
//! struct's field order is fixed by its declaration — the same inputs always
//! render to the same string.
//!
//! [sarif]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;
use zkguard_core::{Confidence, Finding, RuleMetadata, ScanResult, Severity};

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "zk-guard";
const INFORMATION_URI: &str = "https://github.com/ThirdChildren/ZK_Guard";
const DRIVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors that can occur while rendering SARIF.
///
/// Mirrors [`crate::json::JsonReportError`]: kept as its own type so callers
/// in `zkguard-cli` can match on report-crate errors without depending on
/// `serde_json` directly. `ScanResult`/`RuleMetadata` cannot actually
/// trigger a serialization failure today, but a `Result` is kept rather than
/// unwrapping internally in case the schema grows.
#[derive(Debug)]
pub struct SarifReportError(serde_json::Error);

impl std::fmt::Display for SarifReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to render SARIF report: {}", self.0)
    }
}

impl std::error::Error for SarifReportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Renders `result` as a pretty-printed SARIF 2.1.0 log string.
///
/// `rules` is the metadata of every rule that ran (typically
/// `zkguard_rules::registry()` mapped to metadata); each becomes a
/// `reportingDescriptor`. Findings whose `rule_id` is not present in `rules`
/// still emit a `result` (with a stable `ruleId`) but omit `ruleIndex`.
///
/// # Errors
///
/// Returns [`SarifReportError`] if serialization fails (currently
/// unreachable for these types, but kept as a `Result` regardless).
pub fn render(result: &ScanResult, rules: &[RuleMetadata]) -> Result<String, SarifReportError> {
    let index_of: HashMap<&str, usize> = rules
        .iter()
        .enumerate()
        .map(|(i, m)| (m.rule_id.as_str(), i))
        .collect();

    let descriptors: Vec<Descriptor<'_>> = rules.iter().map(Descriptor::from_metadata).collect();
    let results: Vec<SarifResult<'_>> = result
        .findings
        .iter()
        .map(|f| SarifResult::from_finding(f, index_of.get(f.rule_id.as_str()).copied()))
        .collect();

    let log = Sarif {
        schema: SCHEMA,
        version: SARIF_VERSION,
        runs: [Run {
            tool: Tool {
                driver: Driver {
                    name: TOOL_NAME,
                    version: DRIVER_VERSION,
                    information_uri: INFORMATION_URI,
                    rules: descriptors,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&log).map_err(SarifReportError)
}

/// SARIF `level` for a finding severity (`error`/`warning`/`note`).
fn level_for(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub code-scanning `security-severity` score (a numeric string) for a
/// finding severity. Drives GitHub's own severity bucketing on upload.
fn security_severity_for(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.0",
        Severity::High => "8.0",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

fn confidence_str(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

/// Normalizes a source path into a repository-relative SARIF URI: forward
/// slashes, no leading `./`. Absolute paths are left as-is (best-effort).
fn uri_for(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    normalized
        .strip_prefix("./")
        .unwrap_or(&normalized)
        .to_string()
}

/// Composes a self-contained `result.message.text` from a finding.
fn message_for(finding: &Finding) -> String {
    let mut text = if finding.why_it_matters.is_empty() {
        finding.title.clone()
    } else {
        finding.why_it_matters.clone()
    };
    if !finding.evidence.is_empty() {
        text.push_str("\n\nEvidence: ");
        text.push_str(&finding.evidence);
    }
    if !finding.remediation.is_empty() {
        text.push_str("\n\nRemediation: ");
        text.push_str(&finding.remediation);
    }
    text
}

#[derive(Serialize)]
struct Sarif<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [Run<'a>; 1],
}

#[derive(Serialize)]
struct Run<'a> {
    tool: Tool<'a>,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct Tool<'a> {
    driver: Driver<'a>,
}

#[derive(Serialize)]
struct Driver<'a> {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<Descriptor<'a>>,
}

#[derive(Serialize)]
struct Descriptor<'a> {
    id: &'a str,
    name: &'a str,
    #[serde(rename = "shortDescription")]
    short_description: Text<'a>,
    #[serde(rename = "fullDescription")]
    full_description: Text<'a>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: Configuration,
    properties: DescriptorProperties,
}

impl<'a> Descriptor<'a> {
    fn from_metadata(meta: &'a RuleMetadata) -> Self {
        Self {
            id: &meta.rule_id,
            name: &meta.title,
            short_description: Text { text: &meta.title },
            full_description: Text {
                text: &meta.description,
            },
            default_configuration: Configuration {
                level: level_for(meta.default_severity),
            },
            properties: DescriptorProperties {
                security_severity: security_severity_for(meta.default_severity),
                confidence: confidence_str(meta.default_confidence),
                tags: ["security"],
            },
        }
    }
}

#[derive(Serialize)]
struct Text<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct Configuration {
    level: &'static str,
}

#[derive(Serialize)]
struct DescriptorProperties {
    #[serde(rename = "security-severity")]
    security_severity: &'static str,
    confidence: &'static str,
    tags: [&'static str; 1],
}

#[derive(Serialize)]
struct SarifResult<'a> {
    #[serde(rename = "ruleId")]
    rule_id: &'a str,
    #[serde(rename = "ruleIndex", skip_serializing_if = "Option::is_none")]
    rule_index: Option<usize>,
    level: &'static str,
    message: OwnedText,
    locations: [Location; 1],
}

impl<'a> SarifResult<'a> {
    fn from_finding(finding: &'a Finding, rule_index: Option<usize>) -> Self {
        Self {
            rule_id: &finding.rule_id,
            rule_index,
            level: level_for(finding.severity),
            message: OwnedText {
                text: message_for(finding),
            },
            locations: [Location {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: uri_for(&finding.file),
                    },
                    region: Region {
                        // SARIF requires startLine >= 1; findings without a
                        // known line (or with a 0) anchor to line 1.
                        start_line: finding.line.filter(|&l| l >= 1).unwrap_or(1),
                    },
                },
            }],
        }
    }
}

#[derive(Serialize)]
struct OwnedText {
    text: String,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: u32,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value;
    use zkguard_core::{Confidence, Finding, RuleMetadata, ScanResult, Severity};

    use super::*;

    fn sample_rules() -> Vec<RuleMetadata> {
        vec![RuleMetadata::new(
            "NOIR-PUBLIC-001",
            "Public input declared but unused in a constraint-relevant expression",
            Severity::High,
            Confidence::Medium,
            "Detects `pub` parameters of `fn main` that never reach a constraint.",
        )]
    }

    fn sample_result() -> ScanResult {
        ScanResult {
            findings: vec![Finding::new(
                "NOIR-PUBLIC-001",
                "Public input declared but unused in a constraint-relevant expression",
                Severity::High,
                Confidence::Medium,
                PathBuf::from("src/main.nr"),
            )
            .with_line(10)
            .with_evidence("pub claimed_total: Field")
            .with_why_it_matters("A public input that never reaches an assert is not bound.")
            .with_remediation("Bind every public input to at least one constraint.")],
            files_scanned: 1,
            rules_run: vec!["NOIR-PUBLIC-001".to_string()],
        }
    }

    #[test]
    fn renders_wellformed_sarif_2_1_0() {
        let out = render(&sample_result(), &sample_rules()).expect("render");
        let v: Value = serde_json::from_str(&out).expect("valid json");

        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].is_string());
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "zk-guard");
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        let descriptor = &v["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(descriptor["id"], "NOIR-PUBLIC-001");
        assert_eq!(descriptor["defaultConfiguration"]["level"], "error");
        assert_eq!(descriptor["properties"]["security-severity"], "8.0");
    }

    #[test]
    fn result_maps_finding_fields() {
        let out = render(&sample_result(), &sample_rules()).expect("render");
        let v: Value = serde_json::from_str(&out).expect("valid json");
        let result = &v["runs"][0]["results"][0];

        assert_eq!(result["ruleId"], "NOIR-PUBLIC-001");
        assert_eq!(result["ruleIndex"], 0);
        assert_eq!(result["level"], "error");
        assert!(result["message"]["text"]
            .as_str()
            .expect("message text")
            .contains("bound"));
        let region = &result["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 10);
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/main.nr"
        );
    }

    #[test]
    fn missing_line_defaults_to_one() {
        let mut r = sample_result();
        r.findings[0].line = None;
        let out = render(&r, &sample_rules()).expect("render");
        let v: Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            1
        );
    }

    #[test]
    fn empty_result_has_empty_results_array() {
        let out = render(&ScanResult::new(), &[]).expect("render");
        let v: Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(v["runs"][0]["results"], serde_json::json!([]));
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"],
            serde_json::json!([])
        );
    }

    #[test]
    fn level_mapping_covers_all_severities() {
        assert_eq!(level_for(Severity::Critical), "error");
        assert_eq!(level_for(Severity::High), "error");
        assert_eq!(level_for(Severity::Medium), "warning");
        assert_eq!(level_for(Severity::Low), "note");
        assert_eq!(level_for(Severity::Info), "note");
    }

    #[test]
    fn uri_normalizes_separators_and_dot_prefix() {
        assert_eq!(uri_for(Path::new("./src/main.nr")), "src/main.nr");
        assert_eq!(uri_for(Path::new("a/b/c.nr")), "a/b/c.nr");
    }

    #[test]
    fn finding_with_unknown_rule_omits_rule_index() {
        let mut r = sample_result();
        r.findings[0].rule_id = "NOT-REGISTERED".to_string();
        let out = render(&r, &sample_rules()).expect("render");
        let v: Value = serde_json::from_str(&out).expect("valid json");
        assert!(v["runs"][0]["results"][0].get("ruleIndex").is_none());
    }

    #[test]
    fn output_is_deterministic() {
        let (r, rules) = (sample_result(), sample_rules());
        assert_eq!(
            render(&r, &rules).expect("a"),
            render(&r, &rules).expect("b")
        );
    }
}
