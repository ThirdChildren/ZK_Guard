// Fixture for rule: NOIR-RANGE-001 (indexing variant, safe)
//
// Same shape as the vulnerable indexing fixture, but `index` is explicitly
// bounded with `assert(index as u32 < 8)` before the cast result `i` is
// used to index `items`. The scanner recognizes this as a range-check
// idiom referencing `index`, and (via one `let`-hop indirection) recognizes
// that `i` inherits the same bound because it was bound directly from
// `index`.
//
// Expected scanner result: NOIR-RANGE-001 does not fire.
fn main(index: Field, items: [Field; 8]) {
    assert(index as u32 < 8);
    let i = index as u32;
    let v = items[i];
    let _ = v;
}
