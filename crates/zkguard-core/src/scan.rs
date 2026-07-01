//! [`ScanResult`]: the aggregate produced by one scan run, consumed by
//! `zkguard-report` (Step 6) and `zkguard-cli` (Step 6) for exit-code
//! decisions.

use serde::{Deserialize, Serialize};

use crate::finding::Finding;
use crate::severity::Severity;
use crate::skipped::SkippedFile;
use crate::suppression::SuppressedFinding;

/// All findings from one scan run, plus minimal run metadata.
///
/// Deliberately does not include timing, environment info, or a run ID —
/// those are reporting/CLI concerns to add only if a concrete consumer
/// needs them (Step 6+), not speculative metadata fields.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    /// Number of source files visited during this scan, regardless of
    /// whether any rule produced a finding for them. Populated by the
    /// discovery/orchestration layer (`zkguard-noir` / `zkguard-cli`,
    /// Step 4+), not by individual rules.
    pub files_scanned: u32,
    /// Stable rule IDs that were executed during this scan (e.g.
    /// `["NOIR-PUBLIC-001"]`), regardless of whether they produced any
    /// findings. Lets a report distinguish "rule ran, found nothing" from
    /// "rule did not run." Rules disabled via `zkguard.toml` are not listed.
    pub rules_run: Vec<String>,
    /// Number of findings that were detected but suppressed (via an inline
    /// directive or a `zkguard.toml` `[[suppress]]` entry) and therefore
    /// excluded from [`Self::findings`]. Reported in every format so a
    /// suppressed finding is never silently invisible. `#[serde(default)]`
    /// keeps older JSON (without this field) parseable.
    #[serde(default)]
    pub suppressed_count: u32,
    /// The suppressed findings themselves, populated only when the caller
    /// asked for them (`--show-suppressed`); otherwise empty and omitted
    /// from JSON. `suppressed_count` is authoritative for the *count*
    /// regardless of whether this list is populated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressed: Vec<SuppressedFinding>,
    /// Files that discovery located but could not read (unreadable or
    /// non-UTF-8), so the scan is partial rather than aborted. A warning, not
    /// a finding: never affects the exit code. Omitted from JSON when empty,
    /// and `#[serde(default)]` keeps older JSON parseable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<SkippedFile>,
}

impl ScanResult {
    /// Empty result for a scan that ran zero rules over zero files. Useful
    /// as a starting accumulator for the orchestration layer added in
    /// Step 4+.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of findings, irrespective of severity.
    #[must_use]
    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }

    /// Counts findings at exactly the given severity.
    #[must_use]
    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    /// Returns `true` if any finding has at least the given severity (per
    /// [`Severity`]'s most-severe-first ordering, "at least as severe"
    /// means `finding.severity <= severity` is false — concretely,
    /// `Critical` is "at least as severe as" `High`). Useful for a future
    /// CLI `--fail-on` threshold (Step 6), included now only as a small
    /// query helper, not a CLI feature.
    #[must_use]
    pub fn has_finding_at_or_above(&self, severity: Severity) -> bool {
        self.findings.iter().any(|f| f.severity <= severity)
    }

    /// Returns findings sorted most-severe-first (`Critical` ... `Info`),
    /// using [`Severity`]'s natural `Ord` (which is already most-severe
    /// first; see that type's doc comment). Does not mutate `self`.
    #[must_use]
    pub fn sorted_by_severity(&self) -> Vec<Finding> {
        let mut sorted = self.findings.clone();
        sorted.sort_by_key(|f| f.severity);
        sorted
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::confidence::Confidence;

    fn finding(rule_id: &str, severity: Severity) -> Finding {
        Finding::new(rule_id, "title", severity, Confidence::Medium, "main.nr")
    }

    #[test]
    fn counts_by_severity() {
        let result = ScanResult {
            findings: vec![
                finding("R1", Severity::High),
                finding("R2", Severity::High),
                finding("R3", Severity::Low),
            ],
            files_scanned: 2,
            rules_run: vec!["R1".to_string(), "R2".to_string(), "R3".to_string()],
            ..Default::default()
        };

        assert_eq!(result.total_findings(), 3);
        assert_eq!(result.count_by_severity(Severity::High), 2);
        assert_eq!(result.count_by_severity(Severity::Low), 1);
        assert_eq!(result.count_by_severity(Severity::Critical), 0);
    }

    #[test]
    fn sorts_most_severe_first() {
        let result = ScanResult {
            findings: vec![
                finding("R1", Severity::Low),
                finding("R2", Severity::Critical),
                finding("R3", Severity::Medium),
            ],
            files_scanned: 1,
            rules_run: vec![],
            ..Default::default()
        };

        let sorted = result.sorted_by_severity();
        let severities: Vec<Severity> = sorted.iter().map(|f| f.severity).collect();
        assert_eq!(
            severities,
            [Severity::Critical, Severity::Medium, Severity::Low]
        );
    }

    #[test]
    fn has_finding_at_or_above_threshold() {
        let result = ScanResult {
            findings: vec![finding("R1", Severity::Medium)],
            files_scanned: 1,
            rules_run: vec![],
            ..Default::default()
        };

        assert!(result.has_finding_at_or_above(Severity::Medium));
        assert!(result.has_finding_at_or_above(Severity::Low));
        assert!(!result.has_finding_at_or_above(Severity::High));
    }

    #[test]
    fn default_is_empty() {
        let result = ScanResult::new();
        assert_eq!(result.total_findings(), 0);
        assert_eq!(result.files_scanned, 0);
        assert!(result.rules_run.is_empty());
    }

    #[test]
    fn json_round_trip() {
        let result = ScanResult {
            findings: vec![finding("R1", Severity::High)],
            files_scanned: 1,
            rules_run: vec!["R1".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let back: ScanResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, result);
    }

    #[test]
    fn suppressed_fields_default_to_empty_and_are_omitted_when_absent() {
        // Older JSON without the new fields still deserializes (serde default).
        let legacy = r#"{"findings":[],"files_scanned":0,"rules_run":[]}"#;
        let parsed: ScanResult = serde_json::from_str(legacy).expect("deserialize legacy");
        assert_eq!(parsed.suppressed_count, 0);
        assert!(parsed.suppressed.is_empty());
        assert!(parsed.skipped.is_empty());

        // Empty `suppressed`/`skipped` lists are omitted from serialization.
        let json = serde_json::to_string(&ScanResult::new()).expect("serialize");
        assert!(!json.contains("\"suppressed\""));
        assert!(!json.contains("\"skipped\""));
        assert!(json.contains("\"suppressed_count\":0"));
    }
}
