//! Integration test for `NOIR-RANGE-001`: runs real Noir project discovery
//! (`zkguard_noir::discover`) over the checked-in fixture projects and
//! feeds every discovered `.nr` file through the rule, end to end, without
//! going through the CLI — mirrors `noir_public_001_fixtures.rs`'s
//! structure for the original rule.
//!
//! Fixture paths follow `docs/rule-taxonomy.md`'s NOIR-RANGE-001 fixture
//! requirements ("2 vulnerable: index, cast" / "2 safe matching variants +
//! loop-counter non-finding case"):
//! `fixtures/noir/vulnerable/noir-range-001-index/`,
//! `fixtures/noir/vulnerable/noir-range-001-cast/`,
//! `fixtures/noir/safe/noir-range-001-index/`,
//! `fixtures/noir/safe/noir-range-001-cast/`,
//! `fixtures/noir/safe/noir-range-001-loop-counter/`.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use zkguard_core::{Rule, Severity};
use zkguard_rules::NoirRange001;

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

fn findings_for(relative_fixture_dir: &str) -> Vec<zkguard_core::Finding> {
    let project = zkguard_noir::discover(fixture_path(relative_fixture_dir))
        .unwrap_or_else(|err| panic!("failed to discover fixture {relative_fixture_dir}: {err}"));
    let rule = NoirRange001;
    project
        .sources
        .iter()
        .flat_map(|source| rule.check(source))
        .collect()
}

#[test]
fn noir_range_001_fires_on_vulnerable_index_fixture() {
    let findings = findings_for("noir/vulnerable/noir-range-001-index");
    assert!(
        !findings.is_empty(),
        "expected at least one NOIR-RANGE-001 finding on the indexing fixture, got: \
         {findings:#?}"
    );
    for finding in &findings {
        assert_eq!(finding.rule_id, "NOIR-RANGE-001");
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.file.ends_with("src/main.nr"));
    }
}

#[test]
fn noir_range_001_fires_on_vulnerable_cast_fixture() {
    let findings = findings_for("noir/vulnerable/noir-range-001-cast");
    assert!(
        findings.iter().any(|f| f.evidence.contains("total as u32")),
        "expected a narrowing-cast finding, got: {findings:#?}"
    );
}

#[test]
fn noir_range_001_does_not_fire_on_safe_index_fixture() {
    let findings = findings_for("noir/safe/noir-range-001-index");
    assert!(
        findings.is_empty(),
        "expected no NOIR-RANGE-001 findings on the bounded indexing fixture, got: \
         {findings:#?}"
    );
}

#[test]
fn noir_range_001_does_not_fire_on_safe_cast_fixture() {
    let findings = findings_for("noir/safe/noir-range-001-cast");
    assert!(
        findings.is_empty(),
        "expected no NOIR-RANGE-001 findings on the bounded cast fixture, got: {findings:#?}"
    );
}

#[test]
fn noir_range_001_does_not_fire_on_loop_counter_fixture() {
    let findings = findings_for("noir/safe/noir-range-001-loop-counter");
    assert!(
        findings.is_empty(),
        "expected no NOIR-RANGE-001 findings on the for-loop-counter fixture, got: \
         {findings:#?}"
    );
}

#[test]
fn discovery_locates_nargo_manifest_for_all_fixtures() {
    for dir in [
        "noir/vulnerable/noir-range-001-index",
        "noir/vulnerable/noir-range-001-cast",
        "noir/safe/noir-range-001-index",
        "noir/safe/noir-range-001-cast",
        "noir/safe/noir-range-001-loop-counter",
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
