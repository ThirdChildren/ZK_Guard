// Fixture for rule: NOIR-PUBLIC-001
// Case: multiple `pub` parameters, only some of which are constrained.
//
// `claimed_total` (line 14) is bound to a real constraint. `claimed_fee`
// (line 15) and `claimed_note` (line 16) are declared `pub` but never reach
// an assert/assert_eq/constrain expression anywhere in the body.
//
// Expected scanner result: NOIR-PUBLIC-001 fires exactly twice — once for
// `claimed_fee` (line 15) and once for `claimed_note` (line 16), each
// pinned to its own declaration line. `claimed_total` must not produce a
// finding.
fn main(
    secret: Field,
    pub claimed_total: Field,
    pub claimed_fee: Field,
    pub claimed_note: Field,
) {
    let computed = secret * 2;
    assert(computed == claimed_total);
    // BUG: claimed_fee and claimed_note are never used in any constraint.
}
