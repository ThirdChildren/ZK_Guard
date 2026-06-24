// Fixture for rule: NOIR-CONSTRAINT-001
//
// `is_equal` is computed from a top-level equality comparison (`a == b`)
// and bound to a `let` identifier, but `is_equal` is never passed into an
// assert/assert_eq/constrain expression anywhere in the function body. The
// witness still contains a value for `is_equal`, but it exerts zero
// constraint pressure on the proof: a malicious prover can supply `a` and
// `b` that are NOT equal and still produce a valid proof, because nothing
// ever checks that `is_equal` is true.
//
// Expected scanner result: NOIR-CONSTRAINT-001 fires once, on the
// `let is_equal = a == b;` binding.
fn main(a: Field, b: Field) {
    let is_equal = a == b;
    // BUG: `is_equal` is computed but never asserted anywhere below.
}
