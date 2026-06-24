//! JSON report emitter.
//!
//! Serializes a [`ScanResult`] using its existing `serde` implementation
//! (defined in `zkguard-core`), so the field names and lowercase
//! severity/confidence strings already match CLAUDE.md's "Reporting
//! schema" without any remapping here. This module's only job is to fix
//! *how* that serialization is exposed to callers (pretty-printed, stable
//! field order via `serde`'s struct field declaration order) so CI tooling
//! parsing this output has one stable contract to depend on.
//!
//! Per CLAUDE.md design principle 6 ("all scanner output must be
//! machine-readable and human-readable") this is the machine-readable
//! half; [`crate::markdown`] and [`crate::human`] are the human-readable
//! halves.

use zkguard_core::ScanResult;

/// Errors that can occur while rendering JSON.
///
/// Kept as its own type (rather than returning `serde_json::Error`
/// directly) so callers in `zkguard-cli` can match on report-crate errors
/// without taking a direct `serde_json` dependency, and so this crate's
/// public API does not leak its serialization library choice. The standard
/// `serde_json::to_string_pretty` failure modes (a type that isn't really
/// representable, e.g. non-finite floats or maps with non-string keys) do
/// not apply to `ScanResult`'s field set today, but a `Result` is kept
/// rather than `unwrap`-ing internally so this stays true if the schema
/// grows.
#[derive(Debug)]
pub struct JsonReportError(serde_json::Error);

impl std::fmt::Display for JsonReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to render JSON report: {}", self.0)
    }
}

impl std::error::Error for JsonReportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Renders `result` as a pretty-printed JSON string.
///
/// Pretty-printing (rather than compact JSON) is the deliberate default:
/// CI log viewers and `--output report.json` files are both easier to
/// diff/read pretty-printed, and JSON parsers used by CI tooling do not
/// care about whitespace. Deterministic per CLAUDE.md design principle 5:
/// the same `ScanResult` always renders to the same string, since
/// `Finding`'s field order is fixed by its struct declaration and this
/// function performs no extra sorting beyond what `result` already
/// contains.
///
/// # Errors
///
/// Returns [`JsonReportError`] if serialization fails (see that type's
/// docs for why this is currently unreachable for `ScanResult` but kept as
/// a `Result` regardless).
pub fn render(result: &ScanResult) -> Result<String, JsonReportError> {
    serde_json::to_string_pretty(result).map_err(JsonReportError)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use zkguard_core::{Confidence, Finding, Severity};

    use super::*;

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
    fn renders_stable_field_names_and_lowercase_enums() {
        let json = render(&sample_result()).expect("render");

        assert!(json.contains("\"rule_id\": \"NOIR-PUBLIC-001\""));
        assert!(json.contains("\"severity\": \"high\""));
        assert!(json.contains("\"confidence\": \"medium\""));
        assert!(json.contains("\"file\":"));
        assert!(json.contains("\"line\": 10"));
        assert!(json.contains("\"evidence\":"));
        assert!(json.contains("\"why_it_matters\":"));
        assert!(json.contains("\"remediation\":"));
        assert!(json.contains("\"files_scanned\": 1"));
        assert!(json.contains("\"rules_run\":"));
    }

    #[test]
    fn round_trips_back_into_scan_result() {
        let original = sample_result();
        let json = render(&original).expect("render");
        let back: ScanResult = serde_json::from_str(&json).expect("parse");
        assert_eq!(back, original);
    }

    #[test]
    fn empty_result_renders_empty_findings_array() {
        let json = render(&ScanResult::new()).expect("render");
        assert!(json.contains("\"findings\": []"));
    }

    #[test]
    fn output_is_deterministic_across_calls() {
        let result = sample_result();
        let first = render(&result).expect("render");
        let second = render(&result).expect("render");
        assert_eq!(first, second);
    }
}
