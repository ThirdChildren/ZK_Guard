// Fixture for rule: NOIR-PUBLIC-001
//
// `claimed_total` is declared `pub` (a public input to the circuit) but is
// never referenced inside an `assert`/`assert_eq`/`constrain` expression,
// directly or via a one-hop intermediate `let`. A malicious prover can
// therefore set `claimed_total` to any value and still produce a valid
// proof — the public input is not actually bound by any constraint.
//
// Expected scanner result: NOIR-PUBLIC-001 fires once, on `claimed_total`.
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    // BUG: `computed` is never compared against `claimed_total`, and
    // `claimed_total` is never used anywhere else either.
}
