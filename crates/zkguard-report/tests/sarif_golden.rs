//! Golden test for the SARIF 2.1.0 emitter.
//!
//! Pins the exact pretty-printed SARIF output for a fixed, minimal input (one
//! rule, one finding) against a checked-in golden file. This catches any
//! accidental change to field names, ordering, level/severity mapping, or
//! path normalization — the parts a SARIF consumer (GitHub code scanning)
//! depends on. The only value substituted into the golden is the tool
//! `version` (the crate version), so the test does not break on a version
//! bump.

#![allow(clippy::expect_used)]

use std::path::PathBuf;

use zkguard_core::{Confidence, Finding, RuleMetadata, ScanResult, Severity};
use zkguard_report::sarif;

fn fixed_input() -> (ScanResult, Vec<RuleMetadata>) {
    let rules = vec![RuleMetadata::new(
        "NOIR-PUBLIC-001",
        "Public input declared but unused in a constraint-relevant expression",
        Severity::High,
        Confidence::Medium,
        "Detects `pub` parameters of `fn main` that never reach a constraint.",
    )];
    let result = ScanResult {
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
    };
    (result, rules)
}

#[test]
fn sarif_output_matches_golden() {
    let (result, rules) = fixed_input();
    let rendered = sarif::render(&result, &rules).expect("render SARIF");

    let golden = include_str!("golden/noir_public_001.sarif")
        .replace("{VERSION}", env!("CARGO_PKG_VERSION"));

    // include_str! keeps the trailing newline from the file; the renderer
    // does not emit one, so compare against the trimmed golden.
    assert_eq!(
        rendered,
        golden.trim_end_matches('\n'),
        "SARIF output drifted from golden; if intentional, update \
         crates/zkguard-report/tests/golden/noir_public_001.sarif"
    );
}
