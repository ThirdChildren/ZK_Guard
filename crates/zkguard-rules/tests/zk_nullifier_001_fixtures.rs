//! Integration test for `ZK-NULLIFIER-001`: runs real Noir project
//! discovery (`zkguard_noir::discover`) over the checked-in fixture
//! projects and feeds every discovered `.nr` file through the rule, end to
//! end, without going through the CLI — mirrors
//! `noir_public_001_fixtures.rs`'s structure for the original rule.
//!
//! Fixture paths follow `docs/rule-taxonomy.md`'s ZK-NULLIFIER-001 fixture
//! requirements ("2 vulnerable: unhashed reuse, hash without tag" / "1
//! safe"): `fixtures/noir/vulnerable/zk-nullifier-001-unhashed/`,
//! `fixtures/noir/vulnerable/zk-nullifier-001-untagged-hash/`,
//! `fixtures/noir/safe/zk-nullifier-001/`.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use zkguard_core::{Confidence, Rule, Severity};
use zkguard_rules::ZkNullifier001;

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

fn findings_for(relative_fixture_dir: &str) -> Vec<zkguard_core::Finding> {
    let project = zkguard_noir::discover(fixture_path(relative_fixture_dir))
        .unwrap_or_else(|err| panic!("failed to discover fixture {relative_fixture_dir}: {err}"));
    let rule = ZkNullifier001;
    project
        .sources
        .iter()
        .flat_map(|source| rule.check(source))
        .collect()
}

#[test]
fn zk_nullifier_001_fires_on_unhashed_vulnerable_fixture() {
    let findings = findings_for("noir/vulnerable/zk-nullifier-001-unhashed");

    assert_eq!(findings.len(), 1, "findings: {findings:#?}");
    let finding = &findings[0];
    assert_eq!(finding.rule_id, "ZK-NULLIFIER-001");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::Low);
    assert!(finding.evidence.contains("nullifier"));
    assert!(finding.file.ends_with("src/main.nr"));
}

#[test]
fn zk_nullifier_001_fires_on_untagged_hash_vulnerable_fixture() {
    let findings = findings_for("noir/vulnerable/zk-nullifier-001-untagged-hash");

    assert_eq!(findings.len(), 1, "findings: {findings:#?}");
    assert_eq!(findings[0].severity, Severity::High);
    assert_eq!(findings[0].confidence, Confidence::Low);
}

#[test]
fn zk_nullifier_001_does_not_fire_on_safe_fixture() {
    let findings = findings_for("noir/safe/zk-nullifier-001");
    assert!(
        findings.is_empty(),
        "expected no ZK-NULLIFIER-001 findings on the domain-tagged fixture, got: \
         {findings:#?}"
    );
}

#[test]
fn discovery_locates_nargo_manifest_for_all_fixtures() {
    for dir in [
        "noir/vulnerable/zk-nullifier-001-unhashed",
        "noir/vulnerable/zk-nullifier-001-untagged-hash",
        "noir/safe/zk-nullifier-001",
    ] {
        let project = zkguard_noir::discover(fixture_path(dir))
            .unwrap_or_else(|err| panic!("failed to discover {dir}: {err}"));
        assert!(
            project.manifest_path.is_some(),
            "{dir} is missing a discoverable Nargo.toml"
        );
        assert_eq!(
            project.file_count(),
            1,
            "{dir} expected exactly one .nr file"
        );
    }
}
