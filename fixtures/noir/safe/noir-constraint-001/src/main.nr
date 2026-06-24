// Fixture for rule: NOIR-CONSTRAINT-001
//
// Same comparison as the vulnerable fixture (`a == b`), but here the
// resulting `is_equal` binding is passed to `assert(...)` on the very next
// line, so the proof actually enforces the check. A malicious prover
// supplying `a != b` can no longer produce a valid proof.
//
// Expected scanner result: NOIR-CONSTRAINT-001 does not fire.
fn main(a: Field, b: Field) {
    let is_equal = a == b;
    assert(is_equal);
}
