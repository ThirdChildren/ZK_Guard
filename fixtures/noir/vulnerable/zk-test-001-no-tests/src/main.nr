// Fixture for rule: ZK-TEST-001 (vulnerable — no tests at all)
//
// This project declares an entry point (`fn main`) but ships no `#[test]`
// functions whatsoever, so nothing ever exercises the circuit's rejection
// path. The `main` body itself is otherwise clean (the public input is bound
// to a real constraint), so ZK-TEST-001 is the only rule expected to fire.
//
// Expected scanner result: ZK-TEST-001 fires (project has `fn main`, zero
// negative tests).
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    assert_eq(computed, claimed_total);
}
