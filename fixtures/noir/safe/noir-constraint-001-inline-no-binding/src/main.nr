// Fixture for rule: NOIR-CONSTRAINT-001
// False-positive guard: per `docs/rule-taxonomy.md` NOIR-CONSTRAINT-001
// detection strategy step 4, "Treat direct inline comparisons passed
// straight into assert(...) (no intermediate let) as the safe pattern —
// they never reach this rule because there is no unused intermediate
// binding to flag."
//
// `a == b` is compared directly inside `assert(...)` with no intermediate
// `let is_equal = a == b;` binding at all, so `find_boolean_let_bindings`
// has nothing to flag here in the first place — this confirms the rule
// does not misfire on the most common, idiomatic Noir constraint pattern.
//
// Expected scanner result: NOIR-CONSTRAINT-001 does not fire (there is no
// `let` binding of a comparison for the rule to even consider).
fn main(a: Field, b: Field) {
    assert(a == b);
}
