//! Markdown report emitter.
//!
//! Renders a [`ScanResult`] as GitHub-flavored Markdown: a summary table of
//! finding counts by severity, followed by one section per finding (most
//! severe first, per [`ScanResult::sorted_by_severity`]) covering every
//! field CLAUDE.md's "Reporting schema" requires. Intended to be readable
//! directly on GitHub (e.g. as a PR comment or an uploaded CI artifact
//! rendered by the GitHub UI), per the `cli-reporting-engineer` charter's
//! "Markdown reports must be readable in GitHub."
//!
//! Pure formatting only: no filesystem access, no network calls, fully
//! deterministic for a given `ScanResult` (CLAUDE.md design principles 5
//! and 6). Writing the rendered string to a file or stdout is the caller's
//! (`zkguard-cli`'s) responsibility.

use zkguard_core::{Confidence, Severity};

use zkguard_core::ScanResult;

/// Renders `result` as a single Markdown document.
#[must_use]
pub fn render(result: &ScanResult) -> String {
    let mut out = String::new();

    out.push_str("# zk-guard scan report\n\n");
    render_summary(&mut out, result);

    let sorted = result.sorted_by_severity();
    if sorted.is_empty() {
        out.push_str("No findings reached the configured failure threshold.\n");
        render_skipped(&mut out, result);
        render_suppressed(&mut out, result);
        return out;
    }

    out.push_str("## Findings\n\n");
    for (idx, finding) in sorted.iter().enumerate() {
        out.push_str(&format!(
            "### {}. {} ({})\n\n",
            idx + 1,
            finding.title,
            finding.rule_id
        ));
        out.push_str("| Field | Value |\n");
        out.push_str("|---|---|\n");
        out.push_str(&format!("| Rule ID | `{}` |\n", finding.rule_id));
        out.push_str(&format!(
            "| Severity | {} |\n",
            severity_label(finding.severity)
        ));
        out.push_str(&format!(
            "| Confidence | {} |\n",
            confidence_label(finding.confidence)
        ));
        out.push_str(&format!(
            "| Location | `{}{}` |\n",
            finding.file.display(),
            location_suffix(finding.line, finding.column)
        ));
        out.push('\n');

        out.push_str("**Evidence**\n\n");
        out.push_str("```\n");
        out.push_str(&finding.evidence);
        out.push_str("\n```\n\n");

        out.push_str("**Why it matters**\n\n");
        out.push_str(&finding.why_it_matters);
        out.push_str("\n\n");

        out.push_str("**Remediation**\n\n");
        out.push_str(&finding.remediation);
        out.push_str("\n\n");
    }

    render_skipped(&mut out, result);
    render_suppressed(&mut out, result);
    out
}

/// Renders a "## Skipped files" table, only when discovery skipped something
/// (unreadable/non-UTF-8). These are warnings, not findings.
fn render_skipped(out: &mut String, result: &ScanResult) {
    if result.skipped.is_empty() {
        return;
    }
    out.push_str("## Skipped files\n\n");
    out.push_str("Discovery could not read these files; they were skipped ");
    out.push_str("(the scan is partial). This is a warning, not a finding.\n\n");
    out.push_str("| File | Kind | Reason |\n");
    out.push_str("|---|---|---|\n");
    for skip in &result.skipped {
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            skip.path.display(),
            skip_kind_label(skip.kind),
            skip.reason,
        ));
    }
    out.push('\n');
}

fn skip_kind_label(kind: zkguard_core::SkipKind) -> &'static str {
    match kind {
        zkguard_core::SkipKind::NonUtf8 => "non-utf8",
        zkguard_core::SkipKind::Unreadable => "unreadable",
        zkguard_core::SkipKind::OtherIo => "io-error",
    }
}

/// Renders a "## Suppressed findings" table, only when the caller populated
/// `result.suppressed` (`--show-suppressed`). The count alone is always in
/// the summary.
fn render_suppressed(out: &mut String, result: &ScanResult) {
    if result.suppressed.is_empty() {
        return;
    }
    out.push_str("## Suppressed findings\n\n");
    out.push_str("| Rule ID | Location | Suppressed by | Reason |\n");
    out.push_str("|---|---|---|---|\n");
    for s in &result.suppressed {
        out.push_str(&format!(
            "| `{}` | `{}{}` | {} | {} |\n",
            s.finding.rule_id,
            s.finding.file.display(),
            location_suffix(s.finding.line, s.finding.column),
            suppression_source(s.suppressed_by),
            s.reason,
        ));
    }
    out.push('\n');
}

fn suppression_source(kind: zkguard_core::SuppressionKind) -> &'static str {
    match kind {
        zkguard_core::SuppressionKind::Inline => "inline directive",
        zkguard_core::SuppressionKind::Config => "`zkguard.toml`",
    }
}

/// Renders the "## Summary" section: total findings plus a per-severity
/// breakdown table. Always emitted, even for a clean scan (an empty table
/// with all-zero counts is still useful signal: "the scan ran and found
/// nothing," distinct from a missing report).
fn render_summary(out: &mut String, result: &ScanResult) {
    out.push_str("## Summary\n\n");
    out.push_str(&format!("- Files scanned: **{}**\n", result.files_scanned));
    out.push_str(&format!(
        "- Rules run: **{}** ({})\n",
        result.rules_run.len(),
        if result.rules_run.is_empty() {
            "none".to_string()
        } else {
            result
                .rules_run
                .iter()
                .map(|id| format!("`{id}`"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    ));
    out.push_str(&format!(
        "- Total findings: **{}**\n",
        result.total_findings()
    ));
    if result.suppressed_count > 0 {
        out.push_str(&format!("- Suppressed: **{}**\n", result.suppressed_count));
    }
    if !result.skipped.is_empty() {
        out.push_str(&format!(
            "- Skipped (unreadable/non-UTF-8): **{}**\n",
            result.skipped.len()
        ));
    }
    out.push('\n');

    out.push_str("| Severity | Count |\n");
    out.push_str("|---|---|\n");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        out.push_str(&format!(
            "| {} | {} |\n",
            severity_label(severity),
            result.count_by_severity(severity)
        ));
    }
    out.push('\n');
}

/// Formats `file:line:column` (or just `file`/`file:line` when location
/// precision is unavailable), matching `Finding`'s "line/column optional"
/// contract from `zkguard-core`.
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
#[allow(clippy::expect_used)]
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
            ..Default::default()
        }
    }

    #[test]
    fn renders_summary_and_finding_sections() {
        let md = render(&sample_result());

        assert!(md.starts_with("# zk-guard scan report\n"));
        assert!(md.contains("## Summary"));
        assert!(md.contains("Total findings: **1**"));
        assert!(md.contains("## Findings"));
        assert!(md.contains("NOIR-PUBLIC-001"));
        assert!(md.contains("src/main.nr:10"));
        assert!(md.contains("pub claimed_total: Field"));
        assert!(md.contains("Why it matters"));
        assert!(md.contains("Remediation"));
    }

    #[test]
    fn clean_scan_has_no_findings_section() {
        let result = ScanResult {
            findings: vec![],
            files_scanned: 3,
            rules_run: vec!["NOIR-PUBLIC-001".to_string()],
            ..Default::default()
        };
        let md = render(&result);

        assert!(md.contains("Total findings: **0**"));
        assert!(!md.contains("## Findings"));
        assert!(md.contains("No findings reached the configured failure threshold."));
    }

    #[test]
    fn findings_are_sorted_most_severe_first() {
        let result = ScanResult {
            findings: vec![
                Finding::new("R-LOW", "low title", Severity::Low, Confidence::Low, "a.nr"),
                Finding::new(
                    "R-CRIT",
                    "critical title",
                    Severity::Critical,
                    Confidence::High,
                    "b.nr",
                ),
            ],
            files_scanned: 2,
            rules_run: vec![],
            ..Default::default()
        };
        let md = render(&result);

        let crit_idx = md.find("R-CRIT").expect("R-CRIT present");
        let low_idx = md.find("R-LOW").expect("R-LOW present");
        assert!(
            crit_idx < low_idx,
            "critical finding must be rendered before low finding"
        );
    }

    #[test]
    fn location_without_line_omits_suffix() {
        assert_eq!(location_suffix(None, None), "");
        assert_eq!(location_suffix(Some(5), None), ":5");
        assert_eq!(location_suffix(Some(5), Some(2)), ":5:2");
    }

    #[test]
    fn output_is_deterministic() {
        let result = sample_result();
        assert_eq!(render(&result), render(&result));
    }
}
