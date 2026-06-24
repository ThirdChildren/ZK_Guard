// Fixture for rule: NOIR-PUBLIC-001
// Case: `pub` input used only via the one-hop `let` indirection the rule
// explicitly supports (docs/rule-taxonomy.md detection strategy step 2:
// "an expression that is itself later passed into [a constraint]: one
// level of indirection ... counts as used").
//
// `claimed_total` never appears directly inside an assert/assert_eq, but it
// feeds the `let shifted = claimed_total + 1;` binding, and `shifted` is
// then asserted. This is the exact taxonomy example
// (`let x = pub_input + 1; assert(x == y);`), so it must be treated as a
// true negative.
//
// Expected scanner result: NOIR-PUBLIC-001 does not fire.
fn main(secret: Field, pub claimed_total: Field) {
    let shifted = claimed_total + 1;
    assert(shifted == secret);
}
