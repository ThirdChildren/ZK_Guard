//! Property 5 (Step 9, optional): discovery/line-ending robustness.
//!
//! Asserts that converting every `\n` in a generated source to `\r\n`
//! (Windows-style line endings) does not change the *number* of findings
//! any rule produces. This is exercised at the `Rule::check` level directly
//! (not by writing files through `zkguard_noir::discover`, since
//! `discover`'s only job is reading bytes off disk into a `SourceView`
//! verbatim — it does not normalize line endings itself, so any line-ending
//! sensitivity would have to come from the rule/heuristic layer, which is
//! what this property actually probes).
//!
//! ## Why finding *count* and not full equality
//!
//! `Finding::evidence`/`line` *can* legitimately differ between LF and CRLF
//! input for a rule whose evidence slicing includes a trailing `\r`
//! character from the source, or whose line counting differs if a `\r\n`
//! pair were ever miscounted as two lines. Asserting full `Finding`
//! equality would conflate "the same logical findings, byte-identical
//! evidence" with "the same logical findings" — only the latter is what the
//! taxonomy implies should hold (a line-ending convention is not part of
//! any rule's documented detection semantics). This property is therefore
//! intentionally scoped to finding *count* per rule, which is exactly the
//! invariant that would catch a genuine bug (e.g. brace-matching or
//! comment-masking breaking on `\r\n`) without being so strict that an
//! incidental `\r` appearing in `evidence` would count as a false
//! "regression."
//!
//! ## Empirical basis for asserting this (not assuming it)
//!
//! Per Step 9's instruction ("only if it holds; if it reveals a real bug,
//! report it, don't paper over it"), this property was validated
//! empirically before being committed as an assertion: a manual sweep of
//! 5,000 generated `pathological_noir_like_text()` samples through all 5
//! registered rules, comparing LF vs. CRLF finding counts, found zero
//! mismatches (see this task's final report for the exact reproduction
//! command). The property below re-runs the same comparison under
//! `cargo test`'s bounded, deterministic proptest harness rather than the
//! one-off manual sweep, so it is continuously enforced rather than a
//! point-in-time observation.
//!
//! ## Determinism / CI bound
//!
//! `cases: 128` with a fixed FIXED_SEED (see below); see
//! `property_no_panic.rs`'s module doc for the general policy.

use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use zkguard_core::SourceView;
use zkguard_fuzz::generators::pathological_noir_like_text;

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

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    #[test]
    fn finding_counts_are_invariant_under_crlf_line_endings(
        text in pathological_noir_like_text(),
    ) {
        let crlf_text = text.replace('\n', "\r\n");

        let lf_source = SourceView::new("fuzz/main.nr", text.clone());
        let crlf_source = SourceView::new("fuzz/main.nr", crlf_text.clone());

        for rule in zkguard_rules::registry() {
            let lf_findings = rule.check(&lf_source);
            let crlf_findings = rule.check(&crlf_source);
            assert_eq!(
                lf_findings.len(),
                crlf_findings.len(),
                "rule {} produced a different finding count for LF vs. CRLF line endings \
                 over otherwise-identical source content.\nLF source: {text:?}\nLF findings: \
                 {lf_findings:#?}\nCRLF findings: {crlf_findings:#?}",
                rule.metadata().rule_id
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, rng_seed: FIXED_SEED, ..ProptestConfig::default() })]

    /// Trailing whitespace on otherwise-identical lines must not change
    /// finding counts either — a narrower, complementary case to the CRLF
    /// property above, targeting the explicit "trailing whitespace ...
    /// variations" wording in Step 9's task description.
    #[test]
    fn finding_counts_are_invariant_under_trailing_whitespace(
        text in pathological_noir_like_text(),
    ) {
        let padded_text: String = text
            .lines()
            .map(|line| format!("{line}   "))
            .collect::<Vec<_>>()
            .join("\n");

        let plain_source = SourceView::new("fuzz/main.nr", text.clone());
        let padded_source = SourceView::new("fuzz/main.nr", padded_text.clone());

        for rule in zkguard_rules::registry() {
            let plain_findings = rule.check(&plain_source);
            let padded_findings = rule.check(&padded_source);
            assert_eq!(
                plain_findings.len(),
                padded_findings.len(),
                "rule {} produced a different finding count after adding trailing whitespace \
                 to every line.\nOriginal source: {text:?}\nOriginal findings: \
                 {plain_findings:#?}\nPadded findings: {padded_findings:#?}",
                rule.metadata().rule_id
            );
        }
    }
}
