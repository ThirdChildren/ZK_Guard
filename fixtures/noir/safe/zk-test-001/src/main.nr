// Fixture for rule: ZK-TEST-001 (safe — has a negative test)
//
// This project has an entry point, a happy-path `#[test]`, and a
// `#[test(should_fail)]` that feeds the circuit a witness it must reject.
// The `main` body is otherwise clean (public input bound to a constraint),
// so no rule should fire.
//
// Expected scanner result: no findings (in particular ZK-TEST-001 does not
// fire — a negative test exists).
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    assert_eq(computed, claimed_total);
}

#[test]
fn test_valid_witness() {
    main(3, 6);
}

#[test(should_fail)]
fn test_invalid_witness_rejected() {
    // 3 * 2 != 7, so the assertion in `main` must fail.
    main(3, 7);
}
