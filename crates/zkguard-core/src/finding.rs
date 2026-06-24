//! The [`Finding`] type: the only artifact that crosses from analysis
//! (`zkguard-noir`, `zkguard-rules`) into reporting (`zkguard-report`), per
//! `docs/architecture.md`'s data flow section.
//!
//! Field set and names match CLAUDE.md's "Reporting schema" exactly, and
//! the field-to-source mapping in `docs/rule-taxonomy.md`'s "Finding field
//! mapping" table.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::confidence::Confidence;
use crate::severity::Severity;

/// A single, self-contained scanner result.
///
/// Every field is mandatory because every consumer (JSON report, Markdown
/// report, CI gate) must be able to render a finding without falling back
/// to "unknown" placeholders. Optional precision is limited to `line` /
/// `column`, since not every rule can pinpoint a column (or even a line)
/// for every match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, e.g. `"NOIR-PUBLIC-001"`. Never reused across
    /// rules (see `docs/rule-taxonomy.md`).
    pub rule_id: String,
    /// Short human-readable title, usually copied from the rule's
    /// metadata (see [`crate::RuleMetadata::title`]).
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Path to the source file containing the matched pattern.
    pub file: PathBuf,
    /// 1-based line of the matched expression/statement, if known.
    pub line: Option<u32>,
    /// 1-based column of the matched expression/statement, if known.
    pub column: Option<u32>,
    /// The literal (or closely paraphrased) matched source snippet.
    pub evidence: String,
    /// Why this pattern is a security concern, independent of this specific
    /// occurrence.
    pub why_it_matters: String,
    /// Concrete, actionable guidance for resolving or documenting the
    /// finding.
    pub remediation: String,
}

impl Finding {
    /// Convenience constructor so call sites (future rule implementations
    /// in `zkguard-rules`, Step 4+) don't have to spell out a 10-field
    /// struct literal every time. Takes the two fields with no sensible
    /// default ([`Severity`], [`Confidence`]) plus identity fields up
    /// front; everything else is set via the `with_*` setters below.
    ///
    /// This is intentionally a thin builder, not a generic builder
    /// pattern with required-field tracking — see CLAUDE.md principle on
    /// avoiding premature complexity. Rule implementations are free to
    /// construct `Finding { .. }` literals directly instead if preferred.
    #[must_use]
    pub fn new(
        rule_id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        file: impl Into<PathBuf>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            title: title.into(),
            severity,
            confidence,
            file: file.into(),
            line: None,
            column: None,
            evidence: String::new(),
            why_it_matters: String::new(),
            remediation: String::new(),
        }
    }

    /// Sets the 1-based line number.
    #[must_use]
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Sets the 1-based column number.
    #[must_use]
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }

    /// Sets the matched source evidence.
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = evidence.into();
        self
    }

    /// Sets the "why it matters" explanation.
    #[must_use]
    pub fn with_why_it_matters(mut self, why_it_matters: impl Into<String>) -> Self {
        self.why_it_matters = why_it_matters.into();
        self
    }

    /// Sets the remediation guidance.
    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = remediation.into();
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_finding() -> Finding {
        Finding::new(
            "NOIR-PUBLIC-001",
            "Public input declared but unused in a constraint-relevant expression",
            Severity::High,
            Confidence::Medium,
            "src/main.nr",
        )
        .with_line(3)
        .with_column(5)
        .with_evidence("pub claimed_total: Field")
        .with_why_it_matters(
            "A public input that never reaches an assert/constrain is not bound by the proof.",
        )
        .with_remediation("Bind every public input to at least one constraint.")
    }

    #[test]
    fn builder_sets_all_fields() {
        let finding = sample_finding();
        assert_eq!(finding.rule_id, "NOIR-PUBLIC-001");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Medium);
        assert_eq!(finding.file, PathBuf::from("src/main.nr"));
        assert_eq!(finding.line, Some(3));
        assert_eq!(finding.column, Some(5));
        assert!(!finding.evidence.is_empty());
        assert!(!finding.why_it_matters.is_empty());
        assert!(!finding.remediation.is_empty());
    }

    /// Exit criterion from the Step 3 prompt: serde JSON round-trip for
    /// `Finding` produces the lowercase severity/confidence strings stated
    /// in CLAUDE.md's reporting schema.
    #[test]
    fn json_round_trip_uses_lowercase_severity_and_confidence() {
        let finding = sample_finding();
        let json = serde_json::to_string(&finding).expect("serialize");

        assert!(json.contains("\"severity\":\"high\""));
        assert!(json.contains("\"confidence\":\"medium\""));

        let back: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, finding);
    }
}
