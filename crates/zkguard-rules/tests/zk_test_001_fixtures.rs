//! Fixture-backed regression tests for the project-level `ZK-TEST-001` rule,
//! exercised end to end through real Noir discovery (`zkguard_noir::discover`)
//! plus the real rule (`zkguard_rules::ZkTest001`).
//!
//! `ZK-TEST-001` is a `ProjectRule`: it reasons over all `.nr` sources at
//! once, so these tests discover a whole fixture project and call
//! `check_project` over its source set, unlike the per-file rule fixture
//! tests.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use zkguard_core::ProjectRule;
use zkguard_rules::ZkTest001;

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

fn findings_for(relative_fixture_dir: &str) -> Vec<zkguard_core::Finding> {
    let project = zkguard_noir::discover(fixture_path(relative_fixture_dir))
        .unwrap_or_else(|err| panic!("failed to discover fixture {relative_fixture_dir}: {err}"));
    ZkTest001.check_project(&project.sources)
}

#[test]
fn vulnerable_no_tests_fires_once() {
    let findings = findings_for("noir/vulnerable/zk-test-001-no-tests");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "ZK-TEST-001");
    assert_eq!(findings[0].line, Some(1));
}

#[test]
fn vulnerable_no_negative_test_fires_once() {
    let findings = findings_for("noir/vulnerable/zk-test-001-no-negative");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "ZK-TEST-001");
}

#[test]
fn safe_fixture_with_negative_test_does_not_fire() {
    let findings = findings_for("noir/safe/zk-test-001");
    assert!(
        findings.is_empty(),
        "safe fixture has a #[test(should_fail)] and must not fire ZK-TEST-001"
    );
}
