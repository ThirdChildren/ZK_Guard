//! Integration test for `NOIR-CONSTRAINT-001`: runs real Noir project
//! discovery (`zkguard_noir::discover`) over the checked-in fixture projects
//! and feeds every discovered `.nr` file through the rule, end to end,
//! without going through the CLI — mirrors `noir_public_001_fixtures.rs`'s
//! structure for the original rule.
//!
//! Fixture paths match `docs/rule-taxonomy.md`'s "Suggested fixture paths"
//! for NOIR-CONSTRAINT-001:
//! `fixtures/noir/vulnerable/noir-constraint-001/`,
//! `fixtures/noir/safe/noir-constraint-001/`, plus the taxonomy's explicit
//! "second safe variant showing the inline form" requirement at
//! `fixtures/noir/safe/noir-constraint-001-inline-no-binding/`.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use zkguard_core::{Rule, Severity};
use zkguard_rules::NoirConstraint001;

/// Resolves a path under the workspace's `fixtures/` directory, anchored
/// to this crate's manifest directory so the test works regardless of the
/// directory `cargo test` is invoked from.
fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

fn findings_for(relative_fixture_dir: &str) -> Vec<zkguard_core::Finding> {
    let project = zkguard_noir::discover(fixture_path(relative_fixture_dir))
        .unwrap_or_else(|err| panic!("failed to discover fixture {relative_fixture_dir}: {err}"));
    let rule = NoirConstraint001;
    project
        .sources
        .iter()
        .flat_map(|source| rule.check(source))
        .collect()
}

#[test]
fn noir_constraint_001_fires_on_vulnerable_fixture() {
    let findings = findings_for("noir/vulnerable/noir-constraint-001");

    assert_eq!(
        findings.len(),
        1,
        "expected exactly one NOIR-CONSTRAINT-001 finding, got: {findings:#?}"
    );
    let finding = &findings[0];
    assert_eq!(finding.rule_id, "NOIR-CONSTRAINT-001");
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.evidence.contains("is_equal"));
    assert!(finding.file.ends_with("src/main.nr"));
}

#[test]
fn noir_constraint_001_does_not_fire_on_safe_fixture() {
    let findings = findings_for("noir/safe/noir-constraint-001");
    assert!(
        findings.is_empty(),
        "expected no NOIR-CONSTRAINT-001 findings on the safe fixture, got: {findings:#?}"
    );
}

/// False-positive guard fixture: the comparison is passed directly into
/// `assert(...)` with no intermediate `let` binding at all.
#[test]
fn noir_constraint_001_does_not_fire_on_inline_no_binding_fixture() {
    let findings = findings_for("noir/safe/noir-constraint-001-inline-no-binding");
    assert!(
        findings.is_empty(),
        "expected no NOIR-CONSTRAINT-001 findings when the comparison has no \
         intermediate let binding, got: {findings:#?}"
    );
}

#[test]
fn discovery_locates_nargo_manifest_for_all_fixtures() {
    for dir in [
        "noir/vulnerable/noir-constraint-001",
        "noir/safe/noir-constraint-001",
        "noir/safe/noir-constraint-001-inline-no-binding",
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
