//! Integration test for `NOIR-PUBLIC-001`: runs real Noir project discovery
//! (`zkguard_noir::discover`) over the checked-in fixture projects and
//! feeds every discovered `.nr` file through the rule, end to end, without
//! going through the CLI (per `docs/roadmap.md` Phase 4 exit criteria: "a
//! rule runs end-to-end against a fixture directory and produces a correct
//! Finding (or no finding) without going through the CLI").
//!
//! Fixture paths match `docs/rule-taxonomy.md`'s "Suggested fixture file
//! names" for NOIR-PUBLIC-001:
//! `fixtures/noir/vulnerable/noir-public-001/`,
//! `fixtures/noir/safe/noir-public-001/`.
//!
//! `expect()` is used freely below (allowed via the crate-level lint
//! override, matching the convention already used for test modules in
//! `zkguard-core`): a fixture failing to discover is a test failure we
//! want a clear panic message for, not a `Result` to thread through
//! assertions.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use zkguard_core::{Rule, Severity};
use zkguard_rules::NoirPublic001;

/// Resolves a path under the workspace's `fixtures/` directory, anchored
/// to this crate's manifest directory so the test works regardless of the
/// directory `cargo test` is invoked from.
fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

#[test]
fn noir_public_001_fires_on_vulnerable_fixture() {
    let project = zkguard_noir::discover(fixture_path("noir/vulnerable/noir-public-001"))
        .expect("discover vulnerable fixture");

    assert_eq!(
        project.file_count(),
        1,
        "expected exactly one .nr file in the vulnerable fixture"
    );

    let rule = NoirPublic001;
    let findings: Vec<_> = project
        .sources
        .iter()
        .flat_map(|source| rule.check(source))
        .collect();

    assert_eq!(
        findings.len(),
        1,
        "expected exactly one NOIR-PUBLIC-001 finding, got: {findings:#?}"
    );
    let finding = &findings[0];
    assert_eq!(finding.rule_id, "NOIR-PUBLIC-001");
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.evidence.contains("claimed_total"));
    assert!(finding.file.ends_with("src/main.nr"));
}

#[test]
fn noir_public_001_does_not_fire_on_safe_fixture() {
    let project = zkguard_noir::discover(fixture_path("noir/safe/noir-public-001"))
        .expect("discover safe fixture");

    assert_eq!(
        project.file_count(),
        1,
        "expected exactly one .nr file in the safe fixture"
    );

    let rule = NoirPublic001;
    let findings: Vec<_> = project
        .sources
        .iter()
        .flat_map(|source| rule.check(source))
        .collect();

    assert!(
        findings.is_empty(),
        "expected no NOIR-PUBLIC-001 findings on the safe fixture, got: {findings:#?}"
    );
}

#[test]
fn discovery_locates_nargo_manifest_for_both_fixtures() {
    let vulnerable = zkguard_noir::discover(fixture_path("noir/vulnerable/noir-public-001"))
        .expect("discover vulnerable fixture");
    let safe = zkguard_noir::discover(fixture_path("noir/safe/noir-public-001"))
        .expect("discover safe fixture");

    assert!(vulnerable.manifest_path.is_some());
    assert!(safe.manifest_path.is_some());
}
