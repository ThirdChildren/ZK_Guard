//! Black-box CLI integration tests for the `zk-guard` binary.
//!
//! These tests run the actual compiled binary (via `assert_cmd`) against
//! the checked-in fixture projects, exercising the full
//! discovery -> rules -> report -> exit-code pipeline exactly as a real
//! user or CI job would invoke it. This complements (does not replace) the
//! unit tests inside `crates/zkguard-cli/src/commands/*.rs`, which call
//! command functions directly without spawning a process.
//!
//! Per CLAUDE.md's "Definition of done," `zk-guard scan` must work on a
//! Noir fixture directory with both JSON and Markdown output — this file
//! is the test that proves that end to end.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

/// Resolves a path under the workspace's `fixtures/` directory, anchored to
/// this crate's manifest directory so the test works regardless of the
/// directory `cargo test` is invoked from.
fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

fn zk_guard() -> Command {
    Command::cargo_bin("zk-guard").expect("locate zk-guard binary")
}

#[test]
fn scan_vulnerable_fixture_exits_nonzero_and_reports_finding_human() {
    zk_guard()
        .arg("scan")
        .arg(fixture_path("noir/vulnerable/noir-public-001"))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("NOIR-PUBLIC-001"))
        .stdout(predicate::str::contains("HIGH"));
}

#[test]
fn scan_safe_fixture_exits_zero_with_no_findings() {
    // A fully clean project: the public input is bound to a constraint AND it
    // has a `#[test(should_fail)]`, so no rule (including the project-level
    // ZK-TEST-001) fires. `safe/noir-public-001` is clean for the per-file
    // rules but has no negative test, so it would trip ZK-TEST-001 — this
    // test needs an all-rules-clean fixture.
    zk_guard()
        .arg("scan")
        .arg(fixture_path("noir/safe/zk-test-001"))
        .assert()
        .code(0)
        .stdout(predicate::str::contains("No findings."));
}

#[test]
fn scan_json_format_is_valid_and_contains_rule_id() {
    let output = zk_guard()
        .arg("scan")
        .arg(fixture_path("noir/vulnerable/noir-public-001"))
        .arg("--format")
        .arg("json")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("utf8 stdout");
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");

    let findings = value
        .get("findings")
        .and_then(|f| f.as_array())
        .expect("findings array");
    // This fixture has no negative test, so the project-level ZK-TEST-001 also
    // fires here; assert on the NOIR-PUBLIC-001 finding specifically rather
    // than assuming it is the only one.
    let public = findings
        .iter()
        .find(|f| f["rule_id"] == "NOIR-PUBLIC-001")
        .expect("a NOIR-PUBLIC-001 finding");
    assert_eq!(public["severity"], "high");
    assert_eq!(public["confidence"], "medium");
    assert!(public["file"].is_string());
    assert!(public["evidence"].is_string());
    assert!(public["why_it_matters"].is_string());
    assert!(public["remediation"].is_string());
}

#[test]
fn scan_markdown_format_with_output_writes_file_containing_finding() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let report_path = dir.path().join("report.md");

    zk_guard()
        .arg("scan")
        .arg(fixture_path("noir/vulnerable/noir-public-001"))
        .arg("--format")
        .arg("markdown")
        .arg("--output")
        .arg(&report_path)
        .assert()
        .code(1);

    let contents = std::fs::read_to_string(&report_path).expect("report file written");
    assert!(contents.contains("# zk-guard scan report"));
    assert!(contents.contains("NOIR-PUBLIC-001"));
    assert!(contents.contains("Why it matters"));
    assert!(contents.contains("Remediation"));
}

#[test]
fn rules_list_shows_noir_public_001_with_severity_and_confidence() {
    zk_guard()
        .arg("rules")
        .arg("list")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("NOIR-PUBLIC-001"))
        .stdout(predicate::str::contains("high"))
        .stdout(predicate::str::contains("medium"));
}

#[test]
fn rules_list_json_format_round_trips() {
    let output = zk_guard()
        .arg("rules")
        .arg("list")
        .arg("--format")
        .arg("json")
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let text = String::from_utf8(output).expect("utf8 stdout");
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    let rules = value.as_array().expect("array of rules");
    assert!(rules.iter().any(|r| r["rule_id"] == "NOIR-PUBLIC-001"));
}

#[test]
fn fixtures_validate_succeeds_on_checked_in_fixture_tree() {
    zk_guard()
        .arg("fixtures")
        .arg("validate")
        .arg("--path")
        .arg(fixture_path("noir"))
        .assert()
        .code(0)
        .stdout(predicate::str::contains("ok:"));
}

#[test]
fn fixtures_validate_default_path_works_from_workspace_root() {
    // The default `--path` (`fixtures/noir`) is resolved relative to the
    // current working directory, matching `cargo run`/`cargo test`'s
    // convention of running with the workspace root as CWD. Pin that
    // behavior explicitly here, separate from the explicit-path test above,
    // so a future change to the default does not silently start resolving
    // against the wrong directory.
    zk_guard()
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .arg("fixtures")
        .arg("validate")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("ok:"));
}

#[test]
fn scan_missing_path_exits_usage_error_with_clear_message_no_panic() {
    zk_guard()
        .arg("scan")
        .arg("/definitely/does/not/exist/zk-guard-cli-test")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn scan_with_no_arguments_exits_usage_error() {
    zk_guard().arg("scan").assert().code(2);
}

#[test]
fn unknown_subcommand_exits_usage_error() {
    zk_guard().arg("not-a-real-command").assert().code(2);
}
