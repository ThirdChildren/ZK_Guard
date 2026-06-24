// Fixture for rule: NOIR-RANGE-001 (narrowing-cast variant, safe)
//
// Same shape as the vulnerable cast fixture, but `total` is explicitly
// bounded with `assert(total as u32 < 1000)` before the narrowing cast is
// used. (Note: the explicit cast inside the assert is itself a narrowing
// cast of `total`, so it would also be checked against itself, which is
// fine — the rule's range-check idiom recognizes the comparison alongside
// the identifier in the same assert call.)
//
// Expected scanner result: NOIR-RANGE-001 does not fire.
fn main(a: Field, b: Field) {
    let total = a + b;
    assert(total as u32 < 1000);
    let narrowed = total as u32;
    let _ = narrowed;
}
