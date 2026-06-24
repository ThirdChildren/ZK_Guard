//! [`ScanResult`]: the aggregate produced by one scan run, consumed by
//! `zkguard-report` (Step 6) and `zkguard-cli` (Step 6) for exit-code
//! decisions.

use serde::{Deserialize, Serialize};

use crate::finding::Finding;
use crate::severity::Severity;

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
    /// "rule did not run."
    pub rules_run: Vec<String>,
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
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let back: ScanResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, result);
    }
}
