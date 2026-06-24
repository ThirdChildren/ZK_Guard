// Fixture for rule: NOIR-PUBLIC-001
// KNOWN LIMITATION / EXPECTED FALSE POSITIVE, per docs/rule-taxonomy.md
// NOIR-PUBLIC-001 false-positive notes: "Pattern macros or trait-based
// constraint helpers (e.g. a custom `must_equal()` wrapper around `assert`)
// will cause false positives until the rule's keyword list is extended."
//
// `claimed_total` IS actually bound to a constraint here: `must_equal` is a
// project-local helper function that itself calls `assert_eq` internally
// (see the body below). Semantically this circuit is safe. But
// `crates/zkguard-noir/src/heuristics.rs::CONSTRAINT_KEYWORDS` only
// recognizes the literal keywords `assert`, `assert_eq`, `constrain` — it
// has no way to know `must_equal` is a constraint-enforcing wrapper, since
// that requires following a function call the rule does not inline/trace.
//
// CURRENT (pinned) behavior: NOIR-PUBLIC-001 fires once on `claimed_total`,
// even though this circuit is actually safe. This is the documented,
// expected false positive for custom assertion wrappers; do not silently
// "fix" this fixture's expectation without extending
// `CONSTRAINT_KEYWORDS` (a deliberate rule-versioning change per the
// taxonomy) and updating this comment + test together.
//
// Expected scanner result (CURRENT, KNOWN FALSE POSITIVE): NOIR-PUBLIC-001
// fires once, on `claimed_total`.
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    must_equal(computed, claimed_total);
}

// Project-local wrapper around `assert_eq`. Not in the rule's keyword list.
fn must_equal(a: Field, b: Field) {
    assert_eq(a, b);
}
