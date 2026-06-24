// Fixture for rule: NOIR-RANGE-001 (loop-counter false-positive guard)
//
// `i` indexes `items`, but `i` is the control variable of a
// `for i in 0..4` loop, which the taxonomy explicitly requires the rule to
// exempt: "Loop counters bound by a for _ in 0..N are not findings; the
// rule must special-case this idiom explicitly to avoid noisy output on
// completely ordinary code."
//
// Expected scanner result: NOIR-RANGE-001 does not fire.
fn main(items: [Field; 4]) {
    let mut total = 0;
    for i in 0..4 {
        total = total + items[i];
    }
    let _ = total;
}
