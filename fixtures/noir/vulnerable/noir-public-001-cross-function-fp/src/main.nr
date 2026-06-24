// Fixture for rule: NOIR-PUBLIC-001
// KNOWN LIMITATION / EXPECTED FALSE POSITIVE, per docs/rule-taxonomy.md
// NOIR-PUBLIC-001 detection strategy step 4: "If the identifier is passed
// as an argument to another function defined in the same crate, do not
// assume safety — recurse one call level deep if feasible; otherwise
// downgrade confidence to `medium` ... rather than suppress the finding."
//
// `claimed_total` is passed directly into `validate(claimed_total)`, a
// same-crate helper function that DOES constrain it (via `assert` inside
// `validate`'s own body). Semantically this circuit is safe — the public
// input is bound to a real constraint, just one function call away. The
// current implementation does not recurse into called functions at all
// (no call-level tracing is implemented yet), so it cannot see that
// `validate` enforces anything.
//
// CURRENT (pinned) behavior: NOIR-PUBLIC-001 fires once on `claimed_total`,
// even though `validate` does constrain it. This is the documented,
// expected false positive for cross-function flow (taxonomy: "cannot be
// followed; default to `medium` confidence" — note the CURRENT
// implementation does not yet implement that confidence downgrade either;
// see the regression test for this fixture, which flags that gap
// explicitly with an `#[ignore]`d test rather than silently asserting
// wrong confidence).
//
// Expected scanner result (CURRENT, KNOWN FALSE POSITIVE): NOIR-PUBLIC-001
// fires once, on `claimed_total`.
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    validate(claimed_total, computed);
}

// Project-local helper that actually constrains its argument.
fn validate(total: Field, computed: Field) {
    assert(total == computed);
}
