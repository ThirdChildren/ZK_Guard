// Fixture for rule: NOIR-PUBLIC-001
// Case: the circuit entry point's signature spans multiple lines, uses
// irregular spacing, and has an array-typed parameter, with the public
// parameter declared deep in the parameter list. This confirms discovery
// and public-parameter extraction (see `extract_public_params` and
// `split_top_level_commas` in crates/zkguard-noir/src/heuristics.rs) still
// work on a non-trivial signature shape, not just the single-line happy
// path.
//
// NOTE for fixture maintainers: deliberately avoid writing the entry
// point's keyword and name back to back anywhere in this header comment,
// even in backtick-quoted prose. `find_fn_entry_points` is a naive text
// scan for that exact two-token substring and does not skip `//` comments
// (see that function's documented limitation); a comment mentioning the
// entry point by name can itself be misidentified as the real declaration
// and corrupt signature/body extraction. This is tracked as a genuine bug,
// not a documented limitation — see `crates/zkguard-noir/tests` for an
// isolated regression test.
//
// `claimed_sum` (declared `pub`, line 28 below) IS bound to a real
// constraint, so this is a safe fixture: the rule must not fire just
// because the signature is unusually formatted.
//
// Expected scanner result: NOIR-PUBLIC-001 does not fire.
fn main(
        secret  :   Field ,
    items: [Field; 4],
        pub    claimed_sum : Field,
) {
    let mut total = 0;
    for i in 0..4 {
        total = total + items[i];
    }
    assert(total + secret == claimed_sum);
}
