// Fixture for rule: NOIR-RANGE-001 (narrowing-cast variant)
//
// `total` (a `Field`-derived value) is narrowed to `u32` with no preceding
// range check establishing that `total` actually fits in 32 bits. Field
// arithmetic that overflows a narrower integer type can wrap around during
// the cast, producing a witness value the developer did not intend.
//
// Expected scanner result: NOIR-RANGE-001 fires on `total as u32`.
fn main(a: Field, b: Field) {
    let total = a + b;
    let narrowed = total as u32;
    let _ = narrowed;
}
