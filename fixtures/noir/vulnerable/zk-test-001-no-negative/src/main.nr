// Fixture for rule: ZK-TEST-001 (vulnerable — only happy-path tests)
//
// This project has an entry point and a `#[test]`, but the test only checks
// a valid witness. There is no `#[test(should_fail)]` (or negatively-named
// test), so the rejection path the circuit enforces is never exercised.
//
// Expected scanner result: ZK-TEST-001 fires (tests exist, none negative).
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    assert_eq(computed, claimed_total);
}

#[test]
fn test_valid_witness() {
    main(3, 6);
}
