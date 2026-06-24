// Fixture for rule: NOIR-RANGE-001 (indexing variant)
//
// `index` is cast to `u32` and the result, `i`, is used to index a
// fixed-size array with no preceding `assert` bounding either `index` or
// `i`. A malicious prover can supply an out-of-range `index` value; Noir's
// runtime will reject a genuinely out-of-bounds index at proving time in
// many cases, but the *circuit itself* contains no explicit constraint
// documenting or enforcing the intended bound, which is the soundness gap
// this rule flags (e.g. wraparound during the cast, or array semantics that
// differ from the developer's intent).
//
// Expected scanner result: NOIR-RANGE-001 fires on `items[i]` (and likely
// also on the `index as u32` cast feeding it, since neither `index` nor `i`
// has a visible range check anywhere in the function).
fn main(index: Field, items: [Field; 8]) {
    let i = index as u32;
    let v = items[i];
    let _ = v;
}
