//! Human/terminal report emitter.
//!
//! The default `zk-guard scan` output: a concise per-finding block (most
//! severe first) followed by a one-line-per-severity summary footer. Kept
//! readable without a color/terminal-styling dependency, per the Step 6
//! task's "Keep it readable without color deps, or use a tiny one only if
//! justified" — plain text is sufficient for the MVP and keeps this crate's
//! dependency footprint at zero beyond `zkguard-core`.
//!
//! Pure formatting only, same constraints as [`crate::markdown`] and
//! [`crate::json`]: no I/O, fully deterministic for a given `ScanResult`.

use zkguard_core::{Confidence, Severity};

use zkguard_core::ScanResult;

/// Renders `result` for a terminal: one block per finding, then a summary
/// footer with counts by severity.
#[must_use]
pub fn render(result: &ScanResult) -> String {
    let mut out = String::new();
    let sorted = result.sorted_by_severity();

    if sorted.is_empty() {
        out.push_str("No findings.\n\n");
    } else {
        for finding in &sorted {
            out.push_str(&format!(
                "[{}] {} ({})\n",
                severity_label(finding.severity),
                finding.title,
                finding.rule_id
            ));
            out.push_str(&format!(
                "  location:   {}{}\n",
                finding.file.display(),
                location_suffix(finding.line, finding.column)
            ));
            out.push_str(&format!(
                "  confidence: {}\n",
                confidence_label(finding.confidence)
            ));
            out.push_str(&format!("  evidence:   {}\n", finding.evidence));
            out.push_str(&format!("  why:        {}\n", finding.why_it_matters));
            out.push_str(&format!("  fix:        {}\n", finding.remediation));
            out.push('\n');
        }
    }

    out.push_str(&render_summary(result));
    out
}

/// One-line-per-severity summary footer, plus a total line. Always
/// rendered, even for a clean scan, so a CI log clearly states "the scan
/// ran and scanned N files" rather than producing no output at all.
fn render_summary(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("Summary:\n");
    out.push_str(&format!("  files scanned: {}\n", result.files_scanned));
    out.push_str(&format!("  rules run:     {}\n", result.rules_run.len()));
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        out.push_str(&format!(
            "  {:<10} {}\n",
            format!("{}:", severity_label(severity)),
            result.count_by_severity(severity)
        ));
    }
    out.push_str(&format!("  total:     {}\n", result.total_findings()));
    out
}

fn location_suffix(line: Option<u32>, column: Option<u32>) -> String {
    match (line, column) {
        (Some(line), Some(column)) => format!(":{line}:{column}"),
        (Some(line), None) => format!(":{line}"),
        (None, _) => String::new(),
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use zkguard_core::Finding;

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
    fn renders_finding_block_and_summary() {
        let text = render(&sample_result());

        assert!(text.contains("[HIGH] Public input declared but unused"));
        assert!(text.contains("NOIR-PUBLIC-001"));
        assert!(text.contains("src/main.nr:10"));
        assert!(text.contains("confidence: medium"));
        assert!(text.contains("evidence:   pub claimed_total: Field"));
        assert!(text.contains("Summary:"));
        assert!(text.contains("total:     1"));
    }

    #[test]
    fn clean_scan_prints_no_findings_and_zero_summary() {
        let result = ScanResult {
            findings: vec![],
            files_scanned: 4,
            rules_run: vec!["NOIR-PUBLIC-001".to_string()],
        };
        let text = render(&result);

        assert!(text.starts_with("No findings.\n"));
        assert!(text.contains("files scanned: 4"));
        assert!(text.contains("total:     0"));
    }

    #[test]
    fn output_is_deterministic() {
        let result = sample_result();
        assert_eq!(render(&result), render(&result));
    }
}
