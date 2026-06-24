// Fixture for rule: NOIR-PUBLIC-001
// Case: the circuit entry point below has no `pub` parameters at all
// (every parameter is private). There is nothing for NOIR-PUBLIC-001 to
// flag — this fixture guards against a false positive on a circuit that
// simply has no public inputs.
//
// NOTE for fixture maintainers: do not write the entry point's keyword and
// name back to back in this comment — see
// noir-public-001-multiline-signature/src/main.nr for why (a known,
// genuine bug in `find_fn_entry_points`'s naive text scan, not fixed here).
//
// Expected scanner result: NOIR-PUBLIC-001 does not fire.
fn main(secret: Field, other_private: Field) {
    let computed = secret * 2;
    assert(computed == other_private);
}
