// Fixture for rule: NOIR-PUBLIC-001
// Case: the circuit entry point's signature spans multiple lines, uses
// irregular spacing, and has an array-typed parameter, with the public
// parameter declared deep in the parameter list. This confirms discovery
// and public-parameter extraction (see `extract_public_params` and
// `split_top_level_commas` in crates/zkguard-noir/src/heuristics.rs) still
// work on a non-trivial signature shape, not just the single-line happy
// path.
//
// NOTE for fixture maintainers (historical): earlier revisions of this
// comment warned against writing the entry point's keyword and name back
// to back in fixture prose, because `find_fn_entry_points` used to be a
// naive text scan with no comment-awareness, so a comment mentioning the
// entry point by name could be misidentified as the real declaration and
// corrupt signature/body extraction. As of Step 7 (`noir-static-analyzer`),
// `find_fn_entry_points` masks `//`/`/* */` comments before searching, so
// this is no longer a live concern — see
// `crates/zkguard-noir/src/heuristics.rs`'s `mask_comments` and the
// (now-passing, no-longer-`#[ignore]`d)
// `comment_mentioning_entry_point_name_corrupts_param_extraction` test.
//
// `claimed_sum` (declared `pub`, line 30 below) IS bound to a real
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
