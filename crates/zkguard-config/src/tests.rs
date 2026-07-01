#![allow(clippy::expect_used)]

use std::path::PathBuf;

use zkguard_core::{Confidence, Finding, Severity, SourceView, SuppressionKind};

use super::*;

fn finding(rule_id: &str, file: &str, line: Option<u32>) -> Finding {
    let mut f = Finding::new(rule_id, "t", Severity::High, Confidence::Low, file);
    if let Some(l) = line {
        f = f.with_line(l);
    }
    f
}

#[test]
fn rules_enabled_by_default_disabled_when_false() {
    let cfg: Config = toml::from_str(
        r#"
        [rules]
        "NOIR-RANGE-001" = false
        "ZK-HASH-001" = true
        "#,
    )
    .expect("parse");
    assert!(!cfg.is_rule_enabled("NOIR-RANGE-001"));
    assert!(cfg.is_rule_enabled("ZK-HASH-001"));
    assert!(cfg.is_rule_enabled("NOIR-PUBLIC-001")); // absent -> enabled
}

#[test]
fn fail_on_precedence_cli_over_config_over_default() {
    let cfg: Config = toml::from_str("fail_on = \"high\"").expect("parse");
    // CLI wins.
    assert_eq!(
        cfg.effective_fail_on(Some(Severity::Critical)),
        Severity::Critical
    );
    // No CLI -> config value.
    assert_eq!(cfg.effective_fail_on(None), Severity::High);
    // No CLI, no config -> default low.
    let empty = Config::default();
    assert_eq!(empty.effective_fail_on(None), Severity::Low);
}

#[test]
fn empty_suppress_reason_is_a_validation_error() {
    let cfg: Config = toml::from_str(
        r#"
        [[suppress]]
        rule = "NOIR-PUBLIC-001"
        path = "src/main.nr"
        reason = "   "
        "#,
    )
    .expect("parse");
    assert!(matches!(
        cfg.validate(),
        Err(ConfigError::EmptySuppressReason { index: 0 })
    ));
}

#[test]
fn inline_directive_with_reason_suppresses_finding_on_same_line() {
    let src = SourceView::new(
        PathBuf::from("src/main.nr"),
        "let x = 1; // zkguard:ignore NOIR-RANGE-001 reason=\"reviewed, bounded by caller\"\n",
    );
    let out = apply_suppressions(
        vec![finding("NOIR-RANGE-001", "src/main.nr", Some(1))],
        &[src],
        &Config::default(),
    );
    assert!(out.active.is_empty());
    assert_eq!(out.suppressed.len(), 1);
    assert_eq!(out.suppressed[0].suppressed_by, SuppressionKind::Inline);
    assert_eq!(out.suppressed[0].reason, "reviewed, bounded by caller");
    assert!(out.warnings.is_empty());
}

#[test]
fn inline_directive_on_line_above_suppresses_next_line() {
    let src = SourceView::new(
        PathBuf::from("src/main.nr"),
        "// zkguard:ignore NOIR-RANGE-001 reason=\"ok\"\nlet x = arr[i];\n",
    );
    let out = apply_suppressions(
        vec![finding("NOIR-RANGE-001", "src/main.nr", Some(2))],
        &[src],
        &Config::default(),
    );
    assert_eq!(out.suppressed.len(), 1);
    assert!(out.active.is_empty());
}

#[test]
fn inline_directive_without_reason_warns_and_does_not_suppress() {
    let src = SourceView::new(
        PathBuf::from("src/main.nr"),
        "let x = 1; // zkguard:ignore NOIR-RANGE-001\n",
    );
    let out = apply_suppressions(
        vec![finding("NOIR-RANGE-001", "src/main.nr", Some(1))],
        &[src],
        &Config::default(),
    );
    assert_eq!(out.active.len(), 1, "finding stays active without a reason");
    assert!(out.suppressed.is_empty());
    assert_eq!(out.warnings.len(), 1);
    assert!(out.warnings[0].contains("reason"));
}

#[test]
fn inline_directive_for_other_rule_does_not_suppress() {
    let src = SourceView::new(
        PathBuf::from("src/main.nr"),
        "let x = 1; // zkguard:ignore ZK-HASH-001 reason=\"unrelated\"\n",
    );
    let out = apply_suppressions(
        vec![finding("NOIR-RANGE-001", "src/main.nr", Some(1))],
        &[src],
        &Config::default(),
    );
    assert_eq!(out.active.len(), 1);
    assert!(out.suppressed.is_empty());
}

#[test]
fn config_file_suppression_matches_rule_and_path() {
    let cfg: Config = toml::from_str(
        r#"
        [[suppress]]
        rule = "NOIR-PUBLIC-001"
        path = "./src/main.nr"
        reason = "documented informational input"
        "#,
    )
    .expect("parse");
    let out = apply_suppressions(
        vec![finding("NOIR-PUBLIC-001", "src/main.nr", Some(10))],
        &[],
        &cfg,
    );
    assert_eq!(out.suppressed.len(), 1);
    assert_eq!(out.suppressed[0].suppressed_by, SuppressionKind::Config);
}

#[test]
fn config_path_matches_as_trailing_suffix_of_reported_path() {
    let cfg: Config = toml::from_str(
        r#"
        [[suppress]]
        rule = "NOIR-PUBLIC-001"
        path = "main.nr"
        reason = "root-relative path vs absolute reported path"
        "#,
    )
    .expect("parse");
    // Reported path carries an absolute prefix; config path is root-relative.
    let hit = apply_suppressions(
        vec![finding("NOIR-PUBLIC-001", "/tmp/proj/main.nr", Some(1))],
        &[],
        &cfg,
    );
    assert_eq!(hit.suppressed.len(), 1);
    // Must not match a mere string suffix without a path boundary.
    let miss = apply_suppressions(
        vec![finding("NOIR-PUBLIC-001", "/tmp/proj/zmain.nr", Some(1))],
        &[],
        &cfg,
    );
    assert!(miss.suppressed.is_empty());
}

#[test]
fn config_file_suppression_with_line_only_matches_that_line() {
    let cfg: Config = toml::from_str(
        r#"
        [[suppress]]
        rule = "NOIR-PUBLIC-001"
        path = "src/main.nr"
        line = 10
        reason = "line-scoped"
        "#,
    )
    .expect("parse");

    let hit = apply_suppressions(
        vec![finding("NOIR-PUBLIC-001", "src/main.nr", Some(10))],
        &[],
        &cfg,
    );
    assert_eq!(hit.suppressed.len(), 1);

    let miss = apply_suppressions(
        vec![finding("NOIR-PUBLIC-001", "src/main.nr", Some(11))],
        &[],
        &cfg,
    );
    assert!(miss.suppressed.is_empty());
    assert_eq!(miss.active.len(), 1);
}

#[test]
fn load_returns_default_when_no_file_present() {
    let dir = std::env::temp_dir().join(format!("zkguard-cfg-none-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let cfg = load(&dir).expect("load");
    assert!(cfg.is_rule_enabled("NOIR-PUBLIC-001"));
    assert_eq!(cfg.effective_fail_on(None), Severity::Low);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_rejects_empty_reason_suppression() {
    let dir = std::env::temp_dir().join(format!("zkguard-cfg-bad-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(
        dir.join(CONFIG_FILE_NAME),
        "[[suppress]]\nrule = \"X\"\npath = \"a.nr\"\nreason = \"\"\n",
    )
    .expect("write");
    assert!(matches!(
        load(&dir),
        Err(ConfigError::EmptySuppressReason { .. })
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
