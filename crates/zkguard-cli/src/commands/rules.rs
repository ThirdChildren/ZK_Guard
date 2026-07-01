//! `zk-guard rules list` command implementation.
//!
//! Reads the same `zkguard_rules::registry()` used by `zk-guard scan`, so
//! the two commands can never disagree about which rules exist (per
//! `zkguard-rules`' registry module doc). This module only renders that
//! list; it contains no rule logic.

use std::io::Write;

use crate::cli::{OutputFormat, RulesListArgs};
use crate::exit_code;

pub fn run(args: &RulesListArgs, stdout: &mut impl Write, stderr: &mut impl Write) -> i32 {
    let rules = zkguard_rules::registry();
    let metadata: Vec<_> = rules.iter().map(|rule| rule.metadata().clone()).collect();

    let rendered = match args.format {
        OutputFormat::Human => render_human(&metadata),
        OutputFormat::Markdown => render_markdown(&metadata),
        OutputFormat::Json => render_json(&metadata),
        OutputFormat::Sarif => {
            // SARIF encodes *scan results*, not the rule registry; there is
            // no meaningful SARIF representation of `rules list`.
            let _ = writeln!(
                stderr,
                "error: --format sarif is only supported by `zk-guard scan`, not `rules list`"
            );
            return exit_code::USAGE_ERROR;
        }
    };

    let _ = write!(stdout, "{rendered}");
    exit_code::SUCCESS
}

fn render_human(metadata: &[zkguard_core::RuleMetadata]) -> String {
    let mut out = String::new();
    if metadata.is_empty() {
        out.push_str("No rules registered.\n");
        return out;
    }

    let id_width = metadata
        .iter()
        .map(|m| m.rule_id.len())
        .max()
        .unwrap_or(0)
        .max("RULE_ID".len());

    out.push_str(&format!(
        "{:<id_width$}  {:<10}  {:<10}  TITLE\n",
        "RULE_ID", "SEVERITY", "CONFIDENCE"
    ));
    for rule in metadata {
        out.push_str(&format!(
            "{:<id_width$}  {:<10}  {:<10}  {}\n",
            rule.rule_id,
            severity_label(rule.default_severity),
            confidence_label(rule.default_confidence),
            rule.title,
        ));
        out.push_str(&format!("{:<id_width$}  {}\n", "", rule.description));
    }
    out
}

fn render_markdown(metadata: &[zkguard_core::RuleMetadata]) -> String {
    let mut out = String::new();
    out.push_str("# zk-guard rule registry\n\n");
    if metadata.is_empty() {
        out.push_str("No rules registered.\n");
        return out;
    }
    out.push_str("| Rule ID | Title | Severity | Confidence | Description |\n");
    out.push_str("|---|---|---|---|---|\n");
    for rule in metadata {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            rule.rule_id,
            rule.title,
            severity_label(rule.default_severity),
            confidence_label(rule.default_confidence),
            rule.description,
        ));
    }
    out
}

fn render_json(metadata: &[zkguard_core::RuleMetadata]) -> String {
    serde_json::to_string_pretty(metadata).unwrap_or_else(|err| {
        format!("{{\"error\": \"failed to serialize rule registry: {err}\"}}")
    })
}

fn severity_label(severity: zkguard_core::Severity) -> &'static str {
    match severity {
        zkguard_core::Severity::Critical => "critical",
        zkguard_core::Severity::High => "high",
        zkguard_core::Severity::Medium => "medium",
        zkguard_core::Severity::Low => "low",
        zkguard_core::Severity::Info => "info",
    }
}

fn confidence_label(confidence: zkguard_core::Confidence) -> &'static str {
    match confidence {
        zkguard_core::Confidence::High => "high",
        zkguard_core::Confidence::Medium => "medium",
        zkguard_core::Confidence::Low => "low",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn human_output_lists_noir_public_001() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &RulesListArgs {
                format: OutputFormat::Human,
            },
            &mut out,
            &mut err,
        );

        assert_eq!(code, exit_code::SUCCESS);
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("NOIR-PUBLIC-001"));
        assert!(text.contains("high"));
        assert!(text.contains("medium"));
    }

    #[test]
    fn json_output_is_parseable_array() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(
            &RulesListArgs {
                format: OutputFormat::Json,
            },
            &mut out,
            &mut err,
        );

        let text = String::from_utf8(out).expect("utf8");
        let parsed: Vec<zkguard_core::RuleMetadata> =
            serde_json::from_str(&text).expect("valid json array");
        assert_eq!(parsed[0].rule_id, "NOIR-PUBLIC-001");
    }

    #[test]
    fn sarif_format_is_rejected_as_usage_error() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &RulesListArgs {
                format: OutputFormat::Sarif,
            },
            &mut out,
            &mut err,
        );

        assert_eq!(code, exit_code::USAGE_ERROR);
        assert!(out.is_empty());
        assert!(String::from_utf8(err).expect("utf8").contains("sarif"));
    }

    #[test]
    fn markdown_output_has_table() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(
            &RulesListArgs {
                format: OutputFormat::Markdown,
            },
            &mut out,
            &mut err,
        );

        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("| Rule ID |"));
        assert!(text.contains("NOIR-PUBLIC-001"));
    }
}
