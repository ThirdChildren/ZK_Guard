// Fixture for rule: NOIR-PUBLIC-001
// KNOWN LIMITATION / EXPECTED FALSE NEGATIVE: the rule does not understand
// comments or string literals (see crates/zkguard-noir/src/heuristics.rs
// module docs: "Does not understand string literals or comments containing
// `{`/`}` ... a known, accepted v1 limitation," and `find_fn_entry_points`'s
// text-only co-occurrence approach in general).
//
// `claimed_total` is declared `pub` and is genuinely never bound to any
// real constraint in executable code. The only place its name appears next
// to a real-looking `assert(...)` call shape is inside a `//` comment. The
// scanner's `direct_use_in_constraint` text scan does not distinguish
// "assert(...) appears in a comment" from "assert(...) appears in code," so
// it currently treats this as if the input WERE constrained.
//
// CURRENT (pinned) behavior: NOIR-PUBLIC-001 does NOT fire here, even
// though the circuit is genuinely vulnerable (claimed_total is fully
// unconstrained). This is a false NEGATIVE caused by the same
// comment-blindness gap documented for `NOIR-PUBLIC-001`'s false-positive
// notes (the taxonomy calls out keyword-list/wrapper blind spots; comments
// containing the literal keyword text are an adjacent, equally real gap in
// the same text-scanning approach). This is intentionally asserted as a
// known-limitation regression test, not silently fixed, so a future
// Step-7/comment-aware-parser improvement flips this test deliberately.
//
// Expected scanner result (CURRENT, NOT desired): NOIR-PUBLIC-001 does not
// fire, despite claimed_total being truly unconstrained.
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    // TODO: should be assert(claimed_total == computed) but this check was
    // never actually written below.
}
