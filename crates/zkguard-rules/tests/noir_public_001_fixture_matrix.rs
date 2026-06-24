//! Extended regression coverage for `NOIR-PUBLIC-001`, exercised end to end
//! through real Noir project discovery (`zkguard_noir::discover`) plus the
//! real rule (`zkguard_rules::NoirPublic001`), the same way
//! `tests/noir_public_001_fixtures.rs` already does for the original two
//! fixtures.
//!
//! This file deepens fixture coverage per `docs/agent-workflow.md` Step 5
//! ("harden NOIR-PUBLIC-001 against the false-positive and false-negative
//! cases the taxonomy and the implementation comments already call out")
//! without touching the original fixtures or tests in
//! `noir_public_001_fixtures.rs`.
//!
//! Scope discipline: every fixture here is for `NOIR-PUBLIC-001` only. No
//! other rule from `docs/rule-taxonomy.md` is implemented yet (Step 7), so
//! none is exercised here.
//!
//! Two kinds of cases are covered:
//! 1. Correct-behavior cases (true positives / true negatives) — asserted
//!    as "this must always hold," no caveats.
//! 2. Known-limitation cases (documented false positives / false
//!    negatives from `docs/rule-taxonomy.md`'s false-positive notes and
//!    `crates/zkguard-noir/src/heuristics.rs`'s doc comments) — asserted as
//!    "this is the CURRENT pinned behavior," with an explicit comment
//!    marking it as a known limitation so a future detection improvement
//!    changes this test deliberately, not by silent regression.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

use zkguard_core::{Rule, Severity};
use zkguard_rules::NoirPublic001;

/// Resolves a path under the workspace's `fixtures/` directory, anchored to
/// this crate's manifest directory (mirrors the helper in
/// `noir_public_001_fixtures.rs`).
fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

fn findings_for(relative_fixture_dir: &str) -> Vec<zkguard_core::Finding> {
    let project = zkguard_noir::discover(fixture_path(relative_fixture_dir))
        .unwrap_or_else(|err| panic!("failed to discover fixture {relative_fixture_dir}: {err}"));
    let rule = NoirPublic001;
    project
        .sources
        .iter()
        .flat_map(|source| rule.check(source))
        .collect()
}

/// Table of fixtures expected to have a stable, *correct* finding count
/// (true positives and true negatives only — no documented-limitation
/// cases in this table, those get their own dedicated tests below so the
/// "why" is visible next to the assertion).
///
/// `(fixture_dir, expected_finding_count)`.
const CORRECT_BEHAVIOR_CASES: &[(&str, usize)] = &[
    // Original fixtures (unchanged expectations; re-asserted here as part
    // of the table so the full correct-behavior matrix is visible in one
    // place. The dedicated tests in `noir_public_001_fixtures.rs` remain
    // the canonical owners of these two cases and are not weakened.
    ("noir/vulnerable/noir-public-001", 1),
    ("noir/safe/noir-public-001", 0),
    // Case 1: multiple `pub` params, some constrained, some not.
    ("noir/vulnerable/noir-public-001-multi-param", 2),
    // Case 2: one-hop `let` indirection the rule explicitly supports.
    ("noir/safe/noir-public-001-one-hop-indirection", 0),
    // Case 3: pub input as either operand of assert_eq.
    ("noir/safe/noir-public-001-rhs-of-assert-eq", 0),
    // Case 6: no `pub` params at all.
    ("noir/safe/noir-public-001-no-public-params", 0),
    // Case 7: multiline / irregular-whitespace signature with array type.
    ("noir/safe/noir-public-001-multiline-signature", 0),
];

#[test]
fn correct_behavior_matrix_matches_expected_finding_counts() {
    for (fixture_dir, expected_count) in CORRECT_BEHAVIOR_CASES {
        let findings = findings_for(fixture_dir);
        assert_eq!(
            findings.len(),
            *expected_count,
            "fixture {fixture_dir} expected {expected_count} finding(s), got: {findings:#?}"
        );
    }
}

/// Case 1 (detailed): multiple `pub` params where some are constrained and
/// some are not — the finding(s) must be on exactly the unconstrained
/// param(s), with correct line numbers and evidence text, not just a
/// matching count.
#[test]
fn multi_param_fixture_flags_only_unconstrained_params_with_correct_lines() {
    let findings = findings_for("noir/vulnerable/noir-public-001-multi-param");

    assert_eq!(findings.len(), 2, "findings: {findings:#?}");

    let mut by_evidence: Vec<(&str, Option<u32>)> = findings
        .iter()
        .map(|f| (f.evidence.as_str(), f.line))
        .collect();
    by_evidence.sort();

    assert_eq!(
        by_evidence,
        vec![
            ("pub claimed_fee: Field", Some(15)),
            ("pub claimed_note: Field", Some(16)),
        ]
    );

    // `claimed_total` (the constrained param) must not appear in any
    // finding's evidence.
    assert!(
        findings
            .iter()
            .all(|f| !f.evidence.contains("claimed_total")),
        "constrained param `claimed_total` must not be flagged: {findings:#?}"
    );

    for finding in &findings {
        assert_eq!(finding.rule_id, "NOIR-PUBLIC-001");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.file.ends_with("src/main.nr"));
    }
}

/// Case 3 (detailed): the public input must be recognized whether it is
/// the first or second argument to `assert_eq`, confirming the rule does
/// not depend on operand order.
#[test]
fn rhs_of_assert_eq_fixture_recognizes_both_operand_positions() {
    let findings = findings_for("noir/safe/noir-public-001-rhs-of-assert-eq");
    assert!(
        findings.is_empty(),
        "pub inputs used as either assert_eq operand must not be flagged: {findings:#?}"
    );
}

/// Case 4 — KNOWN LIMITATION (expected false NEGATIVE), not a false
/// positive: per `crates/zkguard-noir/src/heuristics.rs` module docs, the
/// rule's text scan does not understand comments. A constraint-keyword
/// call shape (`assert(claimed_total == ...)`) that appears only inside a
/// `//` comment is indistinguishable, to this text scan, from a real call.
///
/// `claimed_total` in this fixture is genuinely never constrained by any
/// executable code, so the circuit is truly vulnerable — but the scanner
/// currently does NOT fire, because the comment text satisfies
/// `direct_use_in_constraint`'s pattern match. This is pinned here exactly
/// as it is today; do not change this assertion without first fixing
/// comment-awareness in `crates/zkguard-noir/src/heuristics.rs` and
/// updating the fixture's header comment together.
#[test]
fn comment_blindness_fixture_pins_current_false_negative() {
    let findings = findings_for("noir/vulnerable/noir-public-001-comment-blindness-fn");
    assert!(
        findings.is_empty(),
        "KNOWN LIMITATION regression: expected the CURRENT implementation to \
         miss this genuinely-vulnerable fixture because `assert(claimed_total \
         == ...)` appears only inside a `//` comment, which the text-only \
         scanner cannot distinguish from real code. If this now fails because \
         a finding WAS produced, the heuristics gained comment-awareness — \
         update this test (and its doc comment) deliberately rather than \
         deleting it. Findings: {findings:#?}"
    );
}

/// Case 5 — KNOWN LIMITATION (expected false POSITIVE), per
/// `docs/rule-taxonomy.md` NOIR-PUBLIC-001 false-positive notes: "Pattern
/// macros or trait-based constraint helpers (e.g. a custom `must_equal()`
/// wrapper around `assert`) will cause false positives until the rule's
/// keyword list is extended."
///
/// The fixture's `claimed_total` IS constrained, via a project-local
/// `must_equal` wrapper that itself calls `assert_eq`. The rule's
/// `CONSTRAINT_KEYWORDS` list does not include `must_equal`, so it cannot
/// see this and reports a finding on a circuit that is actually safe.
#[test]
fn custom_wrapper_fixture_pins_current_false_positive() {
    let findings = findings_for("noir/vulnerable/noir-public-001-custom-wrapper-fp");
    assert_eq!(
        findings.len(),
        1,
        "KNOWN LIMITATION regression: expected the CURRENT implementation to \
         fire once on `claimed_total` even though it is actually constrained \
         via the `must_equal` wrapper, because `must_equal` is not in \
         CONSTRAINT_KEYWORDS. If this now fails because no finding was \
         produced, the keyword list (or a wrapper-following mechanism) \
         changed — update this test deliberately (it is a documented \
         rule-versioning change per the taxonomy), don't just patch the \
         assertion. Findings: {findings:#?}"
    );
    assert!(findings[0].evidence.contains("claimed_total"));
}

/// Case 5b: a public input consumed only by a helper function defined in
/// the same crate (cross-function flow) is a separate, related known
/// limitation from the custom-wrapper case above — the taxonomy's
/// detection strategy step 4 explicitly anticipates this ("recurse one
/// call level deep if feasible; otherwise downgrade confidence to
/// `medium`"). The current implementation does neither: it does not
/// recurse, AND it does not downgrade confidence — it still emits the
/// default `medium` confidence as if no cross-function flow existed at
/// all, which happens to match the taxonomy's specified default anyway, so
/// this is not flagged as an extra bug, just documented here.
#[test]
fn cross_function_fixture_pins_current_false_positive() {
    let findings = findings_for("noir/vulnerable/noir-public-001-cross-function-fp");
    assert_eq!(
        findings.len(),
        1,
        "KNOWN LIMITATION regression: expected the CURRENT implementation to \
         fire once on `claimed_total` even though the same-crate `validate` \
         helper constrains it, because the rule does not recurse into \
         called functions. Findings: {findings:#?}"
    );
    assert!(findings[0].evidence.contains("claimed_total"));
}

/// Case 7 (detailed): confirms `extract_public_params` correctly resolves
/// the multi-line signature's `pub` parameter to the right line number
/// (line 28 in the fixture file, where `pub    claimed_sum : Field,` is
/// declared) — exercising line-number math, not just a finding count of 0.
///
/// We can't assert a finding's line directly here since there is no
/// finding (the fixture is safe), so instead this test goes one level
/// lower and checks `find_fn_entry_points` directly, confirming discovery
/// itself parsed the irregular signature correctly. This complements the
/// black-box "0 findings" assertion in the correct-behavior matrix by also
/// proving *why* (the param was found and recognized as constrained, not
/// just silently dropped by the parser).
#[test]
fn multiline_signature_fixture_extracts_pub_param_at_correct_line() {
    let project = zkguard_noir::discover(fixture_path(
        "noir/safe/noir-public-001-multiline-signature",
    ))
    .expect("discover multiline signature fixture");
    assert_eq!(project.file_count(), 1);

    let source = &project.sources[0];
    let entries = zkguard_noir::heuristics::find_fn_entry_points(&source.source);
    assert_eq!(entries.len(), 1, "expected exactly one fn main entry point");

    let entry = &entries[0];
    assert_eq!(
        entry.public_params.len(),
        1,
        "expected exactly one pub param, got: {:#?}",
        entry.public_params
    );
    let param = &entry.public_params[0];
    assert_eq!(param.name, "claimed_sum");
    assert_eq!(param.line, 28);
}

#[test]
fn no_public_params_fixture_has_no_findings() {
    let findings = findings_for("noir/safe/noir-public-001-no-public-params");
    assert!(findings.is_empty(), "findings: {findings:#?}");
}

#[test]
fn one_hop_indirection_fixture_has_no_findings() {
    let findings = findings_for("noir/safe/noir-public-001-one-hop-indirection");
    assert!(findings.is_empty(), "findings: {findings:#?}");
}

/// All fixtures referenced by [`CORRECT_BEHAVIOR_CASES`] plus the
/// dedicated-test fixtures must have a discoverable `Nargo.toml`, matching
/// the existing `discovery_locates_nargo_manifest_for_both_fixtures` check
/// in `noir_public_001_fixtures.rs` for the original two fixtures.
#[test]
fn all_new_fixtures_have_a_discoverable_manifest() {
    let dirs = [
        "noir/vulnerable/noir-public-001-multi-param",
        "noir/safe/noir-public-001-one-hop-indirection",
        "noir/safe/noir-public-001-rhs-of-assert-eq",
        "noir/vulnerable/noir-public-001-comment-blindness-fn",
        "noir/vulnerable/noir-public-001-custom-wrapper-fp",
        "noir/vulnerable/noir-public-001-cross-function-fp",
        "noir/safe/noir-public-001-no-public-params",
        "noir/safe/noir-public-001-multiline-signature",
    ];
    for dir in dirs {
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
