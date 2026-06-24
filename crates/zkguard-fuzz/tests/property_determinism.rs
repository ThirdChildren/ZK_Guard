//! Property 2 (Step 9): determinism, per CLAUDE.md principles 5 ("Prefer
//! deterministic local analysis over network calls") and 6 ("All scanner
//! output must be machine-readable and human-readable" — which implicitly
//! requires that output be stable, since a non-deterministic scanner cannot
//! produce a trustworthy machine-readable report).
//!
//! For any generated source text, running the same rule against the same
//! `SourceView` twice must yield identical `Vec<Finding>` (same count, same
//! `rule_id`/`severity`/`confidence`/`line`/`evidence` in the same order).
//! Every rule's `check()` takes `&self, &SourceView` with no hidden mutable
//! state, randomness, or wall-clock dependence, so this property should
//! hold trivially today — its value is as a regression guard against a
//! future rule accidentally introducing
//! `HashMap`-iteration-order-dependence, an RNG, or a timestamp into a
//! finding.
//!
//! ## Determinism / CI bound
//!
//! `cases: 128` with a fixed FIXED_SEED (see below); see
//! `property_no_panic.rs`'s module doc for the general policy this file
//! follows too.

use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use zkguard_core::SourceView;
use zkguard_fuzz::generators::{arbitrary_text, pathological_noir_like_text};

/// Fixed proptest seed for this file's properties, per CLAUDE.md principles
/// 5/6 (deterministic local analysis, reproducible output) and Step 9's
/// explicit instruction ("set a fixed proptest seed/config ... so the
/// default `cargo test` run is reproducible"). `proptest`'s own default
/// (`RngSeed::Random`) draws a fresh OS-random seed on every run, which
/// would make `cargo test` non-deterministic across runs even though each
/// individual run's case count stays bounded — this constant closes that
/// gap. The exact value is arbitrary; what matters is that it is fixed and
/// committed, not derived from wall-clock time or `/dev/urandom`.
const FIXED_SEED: RngSeed = RngSeed::Fixed(0x5a4b_5f47_5541_5244);

/// Runs every registered rule's `check()` twice against the same source and
/// asserts the two `Vec<Finding>` results are exactly equal (`Finding`
/// derives `PartialEq`, so this compares every field, including `evidence`,
/// `line`, `column`, `severity`, `confidence`, and `rule_id`).
fn assert_rules_are_deterministic(source_text: &str) {
    let source = SourceView::new("fuzz/main.nr", source_text);
    for rule in zkguard_rules::registry() {
        let first = rule.check(&source);
        let second = rule.check(&source);
        assert_eq!(
            first,
            second,
            "rule {} produced different findings on two identical runs over the same \
             source; this violates CLAUDE.md's deterministic-analysis principle. Source: \
             {source_text:?}",
            rule.metadata().rule_id
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    #[test]
    fn rules_are_deterministic_on_arbitrary_text(text in arbitrary_text()) {
        assert_rules_are_deterministic(&text);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    #[test]
    fn rules_are_deterministic_on_pathological_noir_like_text(
        text in pathological_noir_like_text(),
    ) {
        assert_rules_are_deterministic(&text);
    }
}

// Determinism must also hold across *independently constructed* but
// content-identical `SourceView`s (not just two calls reusing the same
// `SourceView` value), since a real scan run constructs a fresh
// `SourceView` per file read, never reusing the same value object — this is
// the case that would actually matter in production if some rule secretly
// keyed behavior off of `SourceView`'s memory address or a pointer-derived
// hash rather than its content. (Plain `//` comment, not `///`, because
// this comment precedes a `proptest!` macro invocation, not a documentable
// item — see `tests/property_no_panic.rs` for the equivalent pattern used
// throughout this crate's other property-test files.)
proptest! {
    #![proptest_config(ProptestConfig { cases: 64, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    #[test]
    fn rules_are_deterministic_across_independently_constructed_sources(
        text in pathological_noir_like_text(),
    ) {
        let source_a = SourceView::new("fuzz/main.nr", text.clone());
        let source_b = SourceView::new("fuzz/main.nr", text.clone());
        for rule in zkguard_rules::registry() {
            let findings_a = rule.check(&source_a);
            let findings_b = rule.check(&source_b);
            assert_eq!(
                findings_a, findings_b,
                "rule {} produced different findings for two independently constructed \
                 but content-identical SourceViews",
                rule.metadata().rule_id
            );
        }
    }
}
