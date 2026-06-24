// Fixture for rule: NOIR-PUBLIC-001
// Case: `pub` input used directly as either argument of `assert_eq`, to
// confirm the rule does not depend on argument order (left vs. right
// operand). Two public inputs are declared: `claimed_total` appears as the
// *first* argument, `claimed_double` appears as the *second* argument.
//
// Expected scanner result: NOIR-PUBLIC-001 does not fire for either input.
fn main(secret: Field, pub claimed_total: Field, pub claimed_double: Field) {
    let computed = secret * 2;
    // claimed_total is the first (left) argument.
    assert_eq(claimed_total, computed);
    // claimed_double is the second (right) argument.
    assert_eq(computed, claimed_double);
}
