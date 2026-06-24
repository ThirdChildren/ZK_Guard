// Fixture for rule: NOIR-PUBLIC-001
//
// `claimed_total` is declared `pub` and is the direct operand of an
// `assert_eq` that a malicious prover cannot trivially satisfy (it is
// compared against a value derived from the private input, not against
// itself). This is the safe pattern: the public input is bound to a real
// constraint.
//
// Expected scanner result: NOIR-PUBLIC-001 does not fire.
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    assert_eq(computed, claimed_total);
}
