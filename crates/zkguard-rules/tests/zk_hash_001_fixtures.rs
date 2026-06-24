//! Integration test for `ZK-HASH-001`: runs real Noir project discovery
//! (`zkguard_noir::discover`) over the checked-in fixture projects and
//! feeds every discovered `.nr` file through the rule, end to end, without
//! going through the CLI — mirrors `noir_public_001_fixtures.rs`'s
//! structure for the original rule.
//!
//! Fixture paths match `docs/rule-taxonomy.md`'s "Suggested fixture paths"
//! for ZK-HASH-001: `fixtures/noir/vulnerable/zk-hash-001/`,
//! `fixtures/noir/safe/zk-hash-001/`.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use zkguard_core::{Confidence, Rule, Severity};
use zkguard_rules::ZkHash001;

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

fn findings_for(relative_fixture_dir: &str) -> Vec<zkguard_core::Finding> {
    let project = zkguard_noir::discover(fixture_path(relative_fixture_dir))
        .unwrap_or_else(|err| panic!("failed to discover fixture {relative_fixture_dir}: {err}"));
    let rule = ZkHash001;
    project
        .sources
        .iter()
        .flat_map(|source| rule.check(source))
        .collect()
}

#[test]
fn zk_hash_001_fires_on_vulnerable_fixture() {
    let findings = findings_for("noir/vulnerable/zk-hash-001");

    assert_eq!(
        findings.len(),
        2,
        "expected one ZK-HASH-001 finding per colliding commitment call site, got: \
         {findings:#?}"
    );
    for finding in &findings {
        assert_eq!(finding.rule_id, "ZK-HASH-001");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(
            finding.confidence,
            Confidence::Medium,
            "both call sites corroborate each other via matching arity, so confidence \
             should stay at the rule's default `medium`: {findings:#?}"
        );
        assert!(finding.file.ends_with("src/main.nr"));
    }
}

#[test]
fn zk_hash_001_does_not_fire_on_safe_fixture() {
    let findings = findings_for("noir/safe/zk-hash-001");
    assert!(
        findings.is_empty(),
        "expected no ZK-HASH-001 findings on the domain-tagged fixture, got: {findings:#?}"
    );
}

#[test]
fn discovery_locates_nargo_manifest_for_both_fixtures() {
    for dir in ["noir/vulnerable/zk-hash-001", "noir/safe/zk-hash-001"] {
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
