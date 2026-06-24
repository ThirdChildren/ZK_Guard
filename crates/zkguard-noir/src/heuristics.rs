//! Lightweight, text-level Noir heuristics shared by rule implementations.
//!
//! Per `docs/architecture.md`'s "Avoiding premature complexity" and
//! CLAUDE.md's instruction not to over-engineer the parser before rule
//! value is proven, this module does **not** implement a real Noir
//! lexer/parser/AST. It implements just enough line-oriented text scanning
//! to support `NOIR-PUBLIC-001` (Step 4 of `docs/agent-workflow.md`).
//!
//! Design note for future maintainers (per the `noir-static-analyzer`
//! charter, "Design traits so a future real Noir AST adapter can replace
//! heuristics"): the public functions here ([`find_fn_entry_points`],
//! [`identifier_appears_in_constraint`]) are deliberately free functions
//! operating on plain `&str`, not methods on a parser struct. A future
//! `zkguard-noir` AST adapter can reimplement the same two function
//! signatures against a real parse tree without changing
//! `zkguard-rules`' call sites.

/// Keywords recognized as "this expression constrains the proof."
///
/// Per `docs/rule-taxonomy.md` NOIR-PUBLIC-001 false-positive notes:
/// "Pattern macros or trait-based constraint helpers ... will cause false
/// positives until the rule's keyword list is extended; document the
/// keyword list in the implementation and treat additions as a
/// rule-versioning change." This list is exactly that documented keyword
/// set for NOIR-PUBLIC-001 v1.
pub const CONSTRAINT_KEYWORDS: &[&str] = &["assert_eq", "assert", "constrain"];

/// One `fn` declaration recognized as a circuit entry point, with enough
/// information to extract its `pub` parameters.
///
/// Per NOIR-PUBLIC-001's false-positive notes ("restrict the rule to `fn
/// main` ... to avoid flagging helper/test code"), only `fn main` is
/// treated as an entry point in this v1 heuristic. Recognizing additional
/// Noir entry-point attributes (if any project convention emerges) is a
/// documented future extension, not assumed here.
#[derive(Debug, Clone, PartialEq)]
pub struct FnEntryPoint {
    /// 1-based line on which the `fn` keyword for this entry point starts.
    pub signature_line: u32,
    /// The full, possibly multi-line, signature text from `fn` up to (and
    /// excluding) the opening `{` of the body.
    pub signature_text: String,
    /// The function body text, from (and excluding) the opening `{` to its
    /// matching closing `}`.
    pub body: String,
    /// 1-based line on which the function body's opening `{` appears; used
    /// to translate offsets within `body` back into absolute source lines.
    pub body_start_line: u32,
    /// Public parameters declared in this function's signature.
    pub public_params: Vec<PublicParam>,
}

/// One `pub` parameter found in a recognized entry point's signature.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicParam {
    /// The parameter identifier, e.g. `claimed_total`.
    pub name: String,
    /// 1-based line on which this parameter declaration appears.
    pub line: u32,
    /// The literal declaration text, e.g. `pub claimed_total: Field`, used
    /// as `Finding::evidence`.
    pub declaration_text: String,
}

/// Scans `source` for `fn main(...)` entry points and extracts their `pub`
/// parameters plus a slice of the function body for later usage analysis.
///
/// Detection approach: a simple brace-matching scan, not a full
/// expression parser. This is sufficient because Noir function bodies are
/// brace-delimited and we only need "does identifier X occur in this span
/// of text," not a structured AST. Limitations (documented per CLAUDE.md
/// principle 10, not silently assumed):
/// - Does not understand string literals or `{`/`}` inside block comments
///   (`/* ... */`); a `{`/`}` inside a string would desynchronize brace
///   counting. Noir circuits rarely contain such literals in practice, and
///   this is a known, accepted v1 limitation rather than a silent bug.
/// - Only recognizes the literal `fn main` signature; helper functions
///   with other names are intentionally not treated as entry points (see
///   module doc and NOIR-PUBLIC-001 false-positive notes).
///
/// `//` line comments and `/* ... */` block comments are masked out (see
/// [`mask_comments`]) before the `"fn main"` substring search and before
/// brace-matching, so a comment that merely mentions the entry point's name
/// (optionally followed by its own `(`) can no longer be misidentified as
/// the real declaration. This is the fix for the genuine bug pinned by
/// `crates/zkguard-noir/src/heuristics.rs`'s previously-`#[ignore]`d test
/// `comment_mentioning_entry_point_name_corrupts_param_extraction` (now
/// un-ignored below). All returned text (`signature_text`, `body`,
/// `declaration_text`) is sliced from the *original* `source`, not the
/// masked copy, so evidence strings are never corrupted by masking — only
/// the search/brace-matching positions are computed against the mask.
#[must_use]
pub fn find_fn_entry_points(source: &str) -> Vec<FnEntryPoint> {
    let masked = mask_comments(source);
    let mut entry_points = Vec::new();
    let bytes = masked.as_bytes();
    let mut search_from = 0usize;

    while let Some(rel_idx) = masked[search_from..].find("fn main") {
        let fn_idx = search_from + rel_idx;

        // Require a word boundary before `fn` so `not_fn main` style
        // identifiers (unlikely in Noir, but cheap to guard) don't match.
        let boundary_ok =
            fn_idx == 0 || !bytes[fn_idx - 1].is_ascii_alphanumeric() && bytes[fn_idx - 1] != b'_';
        if !boundary_ok {
            search_from = fn_idx + "fn main".len();
            continue;
        }

        let signature_line = line_number_at(source, fn_idx);

        // Find the opening `{` that starts the body, scanning forward from
        // the signature start (against the masked text, so a `{`/`}` inside
        // a comment between the signature and the real body cannot
        // desynchronize this search either).
        let Some(brace_rel) = masked[fn_idx..].find('{') else {
            // Malformed/truncated signature (e.g. end of file mid-edit);
            // nothing more to extract for this match.
            break;
        };
        let body_open = fn_idx + brace_rel;
        // Sliced from the original `source`, not `masked`, so the returned
        // signature text is the real, uncorrupted source text.
        let signature_text = source[fn_idx..body_open].to_string();
        let body_start_line = line_number_at(source, body_open);

        let Some(body_close) = matching_close_brace(&masked, body_open) else {
            // Unbalanced braces; stop processing rather than guessing.
            break;
        };
        let body = source[body_open + 1..body_close].to_string();

        let public_params = extract_public_params(&signature_text, signature_line);

        entry_points.push(FnEntryPoint {
            signature_line,
            signature_text,
            body,
            body_start_line,
            public_params,
        });

        search_from = body_close + 1;
    }

    entry_points
}

/// Returns a copy of `source` with the contents of every `//` line comment
/// and `/* ... */` block comment replaced by space characters (newlines
/// inside comments are preserved as-is), so that:
/// - byte offsets and line numbers are identical between `source` and the
///   returned string (callers can keep using [`line_number_at`] against
///   either), and
/// - substring searches (`"fn main"`, brace matching, constraint-keyword
///   scans) run against the mask never match text that only exists inside a
///   comment.
///
/// This is a character-level mask, not a tokenizer: it does not understand
/// string literals, so a `//` or `/*` occurring inside a Noir string literal
/// would be (incorrectly) treated as starting a comment. Noir circuit source
/// essentially never contains string literals with comment-like substrings
/// in practice (string literals are rare outside of `println`/`assert`
/// messages), so this is an accepted, documented v1 limitation rather than a
/// silent gap — matching the same "does not understand string literals"
/// caveat already documented on [`find_fn_entry_points`] and
/// [`identifier_appears_in_constraint`].
fn mask_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = vec![0u8; bytes.len()];
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            // Line comment: mask through (but not including) the next
            // newline, or end of file.
            while i < bytes.len() && bytes[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            // Block comment: mask through the closing `*/`, preserving any
            // newlines inside so line numbers downstream stay correct.
            out[i] = b' ';
            out[i + 1] = b' ';
            i += 2;
            while i < bytes.len() {
                if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                    break;
                }
                out[i] = if bytes[i] == b'\n' { b'\n' } else { b' ' };
                i += 1;
            }
        } else {
            out[i] = bytes[i];
            i += 1;
        }
    }

    // `source` is valid UTF-8 (it's `&str`) and masking only ever replaces
    // bytes with the single-byte ASCII space or leaves multi-byte UTF-8
    // sequences fully intact (comment bodies are masked byte-for-byte, but
    // any multi-byte UTF-8 sequence inside a comment gets every one of its
    // bytes replaced by the ASCII space `b' '`, which never splits a
    // multi-byte sequence in a way that produces invalid UTF-8 — each
    // original byte maps to either itself or `b' '`, both valid standalone
    // UTF-8). `from_utf8` therefore cannot fail; falling back to an empty
    // mask on the (unreachable) error path is the only alternative to
    // `unwrap`/`expect`, which the workspace lints discourage.
    String::from_utf8(out).unwrap_or_default()
}

/// Returns the 1-based line number containing byte offset `idx` in `text`.
fn line_number_at(text: &str, idx: usize) -> u32 {
    // `+1` because line numbers are 1-based and we count newlines strictly
    // before `idx`.
    1 + text[..idx].bytes().filter(|&b| b == b'\n').count() as u32
}

/// Finds the index of the `}` matching the `{` at `open_idx`, accounting
/// for nesting. Returns `None` if braces are unbalanced.
fn matching_close_brace(text: &str, open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (offset, ch) in text[open_idx..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open_idx + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parses `pub <name>: <Type>` parameter declarations out of a function
/// signature's raw text.
///
/// Noir parameter lists are comma-separated `name: Type` pairs, optionally
/// prefixed with `pub`. This implementation splits on top-level commas
/// (respecting bracket/paren/generic nesting so `[Field; 8]` style array
/// types don't get split mid-type) and then checks each parameter for a
/// leading `pub` token.
fn extract_public_params(signature_text: &str, signature_line: u32) -> Vec<PublicParam> {
    let Some(open_paren) = signature_text.find('(') else {
        return Vec::new();
    };
    let Some(close_paren) = matching_close_paren(signature_text, open_paren) else {
        return Vec::new();
    };
    let params_text = &signature_text[open_paren + 1..close_paren];

    let mut params = Vec::new();
    for raw_param in split_top_level_commas(params_text) {
        let trimmed = raw_param.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("pub ")
            .or_else(|| trimmed.strip_prefix("pub\t"))
        {
            let rest = rest.trim_start();
            let name = rest
                .split(':')
                .next()
                .unwrap_or(rest)
                .trim()
                .trim_start_matches("mut ")
                .trim()
                .to_string();
            if !name.is_empty() {
                // Line number: count newlines in the signature up to the
                // start of this parameter's *trimmed* text (not the raw,
                // comma-split slice) for multi-line signatures; single-line
                // signatures (the common case) simply resolve to
                // `signature_line`.
                //
                // Small fix noted explicitly (found while building
                // NOIR-PUBLIC-001 fixtures in Step 5, fixed here as a
                // small, obvious, low-risk correction per task protocol
                // rather than left as a silent bug): using `raw_param`'s
                // offset instead of `trimmed`'s undercounts by one newline
                // whenever a parameter's raw (untrimmed) slice begins with
                // the leading `\n` that follows the previous parameter's
                // comma — that leading newline is the one that actually
                // puts this parameter's `pub` token on its own line, but it
                // was previously excluded from the "newlines strictly
                // before the parameter" count.
                let param_offset = trimmed.as_ptr() as usize - signature_text.as_ptr() as usize;
                let line =
                    signature_line + signature_text[..param_offset].matches('\n').count() as u32;
                params.push(PublicParam {
                    name,
                    line,
                    declaration_text: trimmed.to_string(),
                });
            }
        }
    }
    params
}

fn matching_close_paren(text: &str, open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (offset, ch) in text[open_idx..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open_idx + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// Splits `text` on commas that are not nested inside `()`, `[]`, or `{}`,
/// e.g. so `items: [Field; 8], pub total: Field` splits into two
/// parameters rather than being confused by the `;` inside the array type
/// (which this function does not need to split on at all, but nested
/// commas inside generics like `HashMap<A, B>` would otherwise break a
/// naive `split(',')`).
fn split_top_level_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&text[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

/// Checks whether `identifier` appears in `body` inside a constraint-
/// relevant expression, per `docs/rule-taxonomy.md` NOIR-PUBLIC-001
/// detection strategy steps 2-3.
///
/// Two-tier check, matching the taxonomy's "one level of indirection"
/// allowance:
/// 1. Direct: `identifier` appears as a token inside the argument list of
///    a call to one of [`CONSTRAINT_KEYWORDS`] (`assert`, `assert_eq`,
///    `constrain`), anywhere in `body`.
/// 2. One-hop indirect: `identifier` appears on the right-hand side of a
///    `let <other> = ... identifier ...;` binding, and `<other>` itself
///    then appears directly inside a constraint keyword's arguments
///    (taxonomy example: `let x = pub_input + 1; assert(x == y);`).
///
/// Known limitation (documented, not silently assumed, per
/// `docs/rule-taxonomy.md`'s false-positive notes and the
/// `noir-static-analyzer` charter's "never claim definitely exploitable"):
/// this is a textual co-occurrence check, not dataflow. It can be fooled by
/// shadowing, unrelated bindings reusing the same name, or a constraint
/// keyword appearing in an unrelated comment/string. It does not recurse
/// more than one `let` hop, matching the taxonomy's explicit one-hop scope;
/// deeper chains are a documented, accepted gap (the taxonomy's point 4
/// already caps cross-function reasoning at confidence `medium`, and
/// multi-hop intra-function chains are rarer in practice than the
/// single-hop case the taxonomy calls out).
#[must_use]
pub fn identifier_appears_in_constraint(body: &str, identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }

    if direct_use_in_constraint(body, identifier) {
        return true;
    }

    // One-hop indirection: identifier feeds a `let` binding whose target
    // name is itself directly constrained.
    for bound_name in lets_referencing(body, identifier) {
        if direct_use_in_constraint(body, &bound_name) {
            return true;
        }
    }

    false
}

/// True if `identifier` occurs as a whole token inside the parenthesized
/// argument list of any call to a [`CONSTRAINT_KEYWORDS`] keyword.
fn direct_use_in_constraint(body: &str, identifier: &str) -> bool {
    for keyword in CONSTRAINT_KEYWORDS {
        let mut search_from = 0usize;
        while let Some(rel) = body[search_from..].find(keyword) {
            let idx = body.len() - body[search_from..].len() + rel;
            let after_kw = idx + keyword.len();

            // Require the keyword to be followed (after optional
            // whitespace) by `(`, i.e. it's a call, not part of a longer
            // identifier like `assert_something_else` (already disambiguated
            // by the explicit keyword list) or a comment mentioning the
            // word.
            let boundary_ok = idx == 0
                || !body.as_bytes()[idx - 1].is_ascii_alphanumeric()
                    && body.as_bytes()[idx - 1] != b'_';
            if boundary_ok {
                let rest = body[after_kw..].trim_start();
                if let Some(stripped) = rest.strip_prefix('(') {
                    if let Some(close_rel) = find_matching_close_paren_in(stripped) {
                        let args = &stripped[..close_rel];
                        if contains_identifier_token(args, identifier) {
                            return true;
                        }
                    }
                }
            }
            search_from = after_kw;
        }
    }
    false
}

/// Finds the matching `)` for an implicit `(` at the start of `text`
/// (i.e. `text` is everything *after* the opening paren).
fn find_matching_close_paren_in(text: &str) -> Option<usize> {
    let mut depth = 1i32;
    for (idx, ch) in text.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

/// True if `identifier` appears as a standalone token (not as a substring
/// of a longer identifier) anywhere in `text`.
fn contains_identifier_token(text: &str, identifier: &str) -> bool {
    let bytes = text.as_bytes();
    let id_bytes = identifier.as_bytes();
    let mut start = 0usize;
    while let Some(rel) = text[start..].find(identifier) {
        let idx = start + rel;
        let before_ok =
            idx == 0 || !(bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'_');
        let end = idx + id_bytes.len();
        let after_ok =
            end >= bytes.len() || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
        if before_ok && after_ok {
            return true;
        }
        start = idx + 1;
    }
    false
}

/// Returns the bound-name (`let <name> = ...`) of every `let` statement in
/// `body` whose right-hand side references `identifier` as a token.
fn lets_referencing(body: &str, identifier: &str) -> Vec<String> {
    let mut bound_names = Vec::new();
    let mut search_from = 0usize;

    while let Some(rel) = body[search_from..].find("let ") {
        let idx = search_from + rel;
        let boundary_ok = idx == 0
            || !(body.as_bytes()[idx - 1].is_ascii_alphanumeric()
                || body.as_bytes()[idx - 1] == b'_');
        if !boundary_ok {
            search_from = idx + 4;
            continue;
        }

        let after_let = &body[idx + 4..];
        // Statement ends at the next top-level `;` (good enough for the
        // simple `let name = expr;` shape this heuristic targets; complex
        // multi-statement-per-line edge cases are an accepted gap).
        let stmt_end = after_let.find(';').unwrap_or(after_let.len());
        let stmt = &after_let[..stmt_end];

        if let Some(eq_idx) = stmt.find('=') {
            let name_part = stmt[..eq_idx].trim();
            let bound_name = name_part
                .split(':')
                .next()
                .unwrap_or(name_part)
                .trim()
                .trim_start_matches("mut ")
                .trim();
            let rhs = &stmt[eq_idx + 1..];
            if !bound_name.is_empty() && contains_identifier_token(rhs, identifier) {
                bound_names.push(bound_name.to_string());
            }
        }

        search_from = idx + 4 + stmt_end;
    }

    bound_names
}

/// Comparison operators recognized as "this expression produces a boolean,"
/// per `docs/rule-taxonomy.md` NOIR-CONSTRAINT-001 detection strategy (the
/// step that identifies boolean-producing expressions). Checked in this
/// order so the two-character operators (`==`, `!=`, `<=`, `>=`) are
/// matched before the corresponding one-character prefix (`<`, `>`) could
/// shadow them.
///
/// Per the taxonomy: "an explicit call to a known boolean-returning helper
/// (e.g. `is_zero`, `lt`, `eq`)" is also in-scope conceptually, but is
/// **not** implemented in this v1 list — recognizing call-shaped boolean
/// helpers would require resolving which stdlib/user functions actually
/// return booleans, which this text scanner cannot do without false
/// positives on arbitrarily-named helper calls. This is a documented,
/// accepted gap (false negative): a `let ok = is_zero(x);` binding is not
/// recognized as boolean-producing by [`find_boolean_let_bindings`] today.
pub const COMPARISON_OPERATORS: &[&str] = &["==", "!=", "<=", ">=", "<", ">"];

/// One `let <ident> = <expr>;` binding in a function body whose `<expr>` is
/// recognized as boolean-producing (a top-level comparison operator), per
/// `docs/rule-taxonomy.md` NOIR-CONSTRAINT-001 detection strategy step 1.
#[derive(Debug, Clone, PartialEq)]
pub struct BooleanLetBinding {
    /// The bound identifier, e.g. `is_equal`.
    pub name: String,
    /// 1-based line on which the `let` statement starts.
    pub line: u32,
    /// The literal `let ...;` statement text, used as `Finding::evidence`.
    pub statement_text: String,
}

/// Scans `body` for `let <ident> = <expr>;` bindings where `<expr>` contains
/// a top-level comparison operator (see [`COMPARISON_OPERATORS`]), per
/// `docs/rule-taxonomy.md` NOIR-CONSTRAINT-001 detection strategy step 1.
///
/// "Top-level" means the operator is not nested inside a parenthesized
/// sub-call's argument list at a deeper bracket depth than the statement
/// itself — this avoids, for example, misreading a comparison that appears
/// only inside a function-call argument unrelated to the binding's own
/// truth value (an accepted heuristic boundary, not exhaustive dataflow).
///
/// Known limitations (documented per the taxonomy's false-positive notes,
/// not silently assumed):
/// - Does not recognize boolean-returning helper calls like `is_zero(x)`
///   with no comparison operator at all (see [`COMPARISON_OPERATORS`]'s
///   doc comment) — a false negative.
/// - `body` is expected to already be comment-masked by the caller (see
///   [`mask_comments`]) if comment-blindness matters for the call site;
///   this function itself does no masking, matching
///   [`identifier_appears_in_constraint`]'s existing behavior of operating
///   on whatever text it is given.
#[must_use]
pub fn find_boolean_let_bindings(body: &str) -> Vec<BooleanLetBinding> {
    let mut bindings = Vec::new();
    let mut search_from = 0usize;

    while let Some(rel) = body[search_from..].find("let ") {
        let idx = search_from + rel;
        let boundary_ok = idx == 0
            || !(body.as_bytes()[idx - 1].is_ascii_alphanumeric()
                || body.as_bytes()[idx - 1] == b'_');
        if !boundary_ok {
            search_from = idx + 4;
            continue;
        }

        let after_let = &body[idx + 4..];
        let stmt_end_rel = after_let.find(';').unwrap_or(after_let.len());
        let stmt = &after_let[..stmt_end_rel];
        // Absolute end of the statement, including the trailing `;` if one
        // was found, so `statement_text` matches what a developer would
        // actually read as "the let statement."
        let stmt_abs_end = idx + 4 + stmt_end_rel + usize::from(stmt_end_rel < after_let.len());

        if let Some(eq_idx) = find_assignment_equals(stmt) {
            let name_part = stmt[..eq_idx].trim();
            let bound_name = name_part
                .split(':')
                .next()
                .unwrap_or(name_part)
                .trim()
                .trim_start_matches("mut ")
                .trim();
            let rhs = &stmt[eq_idx + 1..];

            if !bound_name.is_empty() && contains_top_level_comparison(rhs) {
                bindings.push(BooleanLetBinding {
                    name: bound_name.to_string(),
                    line: line_number_at(body, idx),
                    statement_text: format!("let {}", body[idx + 4..stmt_abs_end].trim_end()),
                });
            }
        }

        search_from = idx + 4 + stmt_end_rel;
    }

    bindings
}

/// Finds the byte offset of the `=` that separates a `let` statement's
/// bound-name part from its initializer expression, skipping past `==`,
/// `!=`, `<=`, `>=` so a comparison operator inside the *name* position
/// (impossible in valid Noir, but cheap to guard) or, more realistically,
/// skipping `=` characters that are the second half of a two-character
/// comparison operator does not get misidentified as the assignment `=`.
///
/// Concretely: scans left to right for a bare `=` that is not preceded by
/// `=`, `!`, `<`, or `>` and not followed by `=` (which would make it part
/// of `==`).
fn find_assignment_equals(stmt: &str) -> Option<usize> {
    let bytes = stmt.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b != b'=' {
            continue;
        }
        let prev_is_comparison_lead =
            idx > 0 && matches!(bytes[idx - 1], b'=' | b'!' | b'<' | b'>');
        let next_is_eq = idx + 1 < bytes.len() && bytes[idx + 1] == b'=';
        if !prev_is_comparison_lead && !next_is_eq {
            return Some(idx);
        }
    }
    None
}

/// True if `text` contains any [`COMPARISON_OPERATORS`] operator at
/// top-level bracket/paren depth (depth 0), so a comparison nested inside a
/// call's argument list one level deeper still counts (function-call
/// arguments are part of the same top-level expression), but this is
/// intentionally a permissive depth-insensitive scan in v1: precise
/// "top-level of the overall expression vs. top-level of a sub-call" depth
/// reasoning is not implemented, matching the taxonomy's instruction that
/// parser depth is an implementation detail, not a fixed requirement.
fn contains_top_level_comparison(text: &str) -> bool {
    for op in COMPARISON_OPERATORS {
        let mut search_from = 0usize;
        while let Some(rel) = text[search_from..].find(op) {
            let idx = search_from + rel;
            // Avoid matching `<`/`>` as part of `<=`/`>=`/`==`/`!=` when
            // scanning the single-character operators after the
            // two-character ones already matched at a different idx (the
            // outer loop tries operators in [`COMPARISON_OPERATORS`]'s
            // declared order, two-char first, so this guard only needs to
            // reject re-matching half of an already-distinct operator).
            let is_lone_lt_or_gt = matches!(*op, "<" | ">")
                && ((idx + 1 < text.len() && text.as_bytes()[idx + 1] == b'=')
                    || (idx > 0 && text.as_bytes()[idx - 1] == b'='));
            if !is_lone_lt_or_gt {
                return true;
            }
            search_from = idx + op.len();
        }
    }
    false
}

/// True if `identifier` is used as (or as part of) a constraint condition
/// anywhere in `body`: either directly inside a [`CONSTRAINT_KEYWORDS`]
/// call's arguments (covers `assert(is_equal)` and
/// `assert(is_equal == true)`, since both put the token `is_equal` inside
/// the call's argument list), or via one `let`-hop indirection, reusing
/// exactly the same two-tier logic as
/// [`identifier_appears_in_constraint`]. NOIR-CONSTRAINT-001 reuses this
/// rather than duplicating the constraint-detection logic, per the
/// `noir-static-analyzer` charter's instruction to keep heuristics in one
/// place.
#[must_use]
pub fn identifier_used_as_constraint_condition(body: &str, identifier: &str) -> bool {
    identifier_appears_in_constraint(body, identifier)
}

/// Narrowing integer cast suffixes recognized by NOIR-RANGE-001's
/// "arithmetic immediately followed by a narrowing cast" detection
/// strategy, per `docs/rule-taxonomy.md` NOIR-RANGE-001 step 1. `Field` and
/// `u64`/`i64` (the widest integer type Noir exposes at the time of
/// writing) are intentionally excluded — casting *to* the widest type is
/// never narrowing.
pub const NARROWING_CAST_SUFFIXES: &[&str] = &["as u8", "as u16", "as u32", "as i8", "as i16"];

/// Substrings recognized as a "range-check idiom" referencing some
/// identifier, per `docs/rule-taxonomy.md` NOIR-RANGE-001 step 2: "explicit
/// bit-length assertions ... calls into recognized range-check helpers
/// (e.g. names containing `range_check`, `assert_max_bits`, `lt`/`lte`
/// against a constant bound)." Kept as a fixed, documented list per the
/// same "rule-versioning change" discipline as [`CONSTRAINT_KEYWORDS`] —
/// extending it later is a deliberate taxonomy update, not a casual edit.
pub const RANGE_CHECK_HINTS: &[&str] = &["range_check", "assert_max_bits", "lt", "lte"];

/// One security-sensitive site flagged by NOIR-RANGE-001's syntactic-shape
/// detection (array indexing, narrowing cast, or unsigned subtraction).
#[derive(Debug, Clone, PartialEq)]
pub struct RangeSensitiveSite {
    /// The identifier whose range is in question (the index identifier, the
    /// cast operand identifier, or the subtraction's left operand
    /// identifier).
    pub identifier: String,
    /// 1-based line on which the sensitive expression appears, relative to
    /// the start of the text given to [`find_range_sensitive_sites`]. The
    /// caller is responsible for translating this to an absolute file line
    /// the same way rule implementations already do for
    /// [`FnEntryPoint`]'s `body_start_line` field.
    pub line: u32,
    /// The literal matched snippet, used as `Finding::evidence`.
    pub evidence: String,
}

/// Scans `body` for the three security-sensitive syntactic shapes fixed by
/// `docs/rule-taxonomy.md` NOIR-RANGE-001 detection strategy step 1:
/// 1. Array/slice indexing (`arr[idx]`) where `idx` is an identifier (not a
///    compile-time integer literal) and not the control variable of an
///    enclosing `for _ in 0..N` loop (the taxonomy's required loop-counter
///    exemption).
/// 2. A narrowing cast (`<expr> as u8/u16/u32/i8/i16`, see
///    [`NARROWING_CAST_SUFFIXES`]) applied to an expression containing at
///    least one identifier.
/// 3. Subtraction (`a - b`) where the left operand is a bare identifier
///    (Noir/Field underflow-wraparound risk per the taxonomy).
///
/// Known limitations (documented, not silently assumed):
/// - This is a single-pass text scan, not a typed AST: it cannot confirm
///   that an indexing/cast/subtraction operand actually originates from a
///   function parameter versus a purely local, compile-time-bounded value.
///   Per the taxonomy's false-positive notes, this is the most heuristic
///   rule in the MVP set and defaults to `low` confidence for exactly this
///   reason.
/// - Loop-counter detection only recognizes the literal `for <ident> in
///   0..` idiom (taxonomy-mandated exemption); other loop-bound shapes
///   (`for i in start..end` with a non-zero `start`, or a `while` loop) are
///   not special-cased and may produce additional findings — an accepted,
///   documented gap rather than a silent one.
#[must_use]
pub fn find_range_sensitive_sites(body: &str) -> Vec<RangeSensitiveSite> {
    let mut sites = Vec::new();
    let loop_counters = find_for_loop_counters(body);

    sites.extend(find_indexing_sites(body, &loop_counters));
    sites.extend(find_narrowing_cast_sites(body));
    sites.extend(find_unsigned_subtraction_sites(body));

    sites
}

/// Returns the set of identifiers bound as the control variable of a
/// `for <ident> in 0..` loop anywhere in `body`, per NOIR-RANGE-001's
/// required loop-counter exemption.
fn find_for_loop_counters(body: &str) -> Vec<String> {
    let mut counters = Vec::new();
    let mut search_from = 0usize;

    while let Some(rel) = body[search_from..].find("for ") {
        let idx = search_from + rel;
        let boundary_ok = idx == 0
            || !(body.as_bytes()[idx - 1].is_ascii_alphanumeric()
                || body.as_bytes()[idx - 1] == b'_');
        if !boundary_ok {
            search_from = idx + 4;
            continue;
        }

        let after_for = body[idx + 4..].trim_start();
        if let Some(in_rel) = after_for.find(" in ") {
            let ident = after_for[..in_rel].trim();
            let after_in = &after_for[in_rel + 4..];
            if !ident.is_empty()
                && ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && after_in.trim_start().starts_with("0..")
            {
                counters.push(ident.to_string());
            }
        }

        search_from = idx + 4;
    }

    counters
}

/// Finds `arr[idx]` sites where `idx` is a bare identifier token (not a
/// compile-time integer literal) and not one of `loop_counters`.
fn find_indexing_sites(body: &str, loop_counters: &[String]) -> Vec<RangeSensitiveSite> {
    let mut sites = Vec::new();
    let bytes = body.as_bytes();

    for (idx, &b) in bytes.iter().enumerate() {
        if b != b'[' {
            continue;
        }
        // Require a preceding identifier character so this is indexing
        // (`arr[`) rather than an array-type/literal opening bracket
        // (`[Field; 8]` has no identifier immediately before its `[`, and a
        // bare array literal `[1, 2, 3]` likewise has none).
        if idx == 0 || !(bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'_') {
            continue;
        }
        let Some(close_rel) = find_matching_close_bracket_in(&body[idx + 1..]) else {
            continue;
        };
        let inner = body[idx + 1..idx + 1 + close_rel].trim();

        // Only flag when the index is a bare identifier token, not a
        // compile-time integer literal (`arr[0]`) and not a compound
        // expression (`arr[i + 1]` still contains the identifier `i`, but
        // matching only bare identifiers keeps this v1 scan conservative
        // and avoids parsing arithmetic inside the brackets).
        let is_bare_identifier = !inner.is_empty()
            && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && inner.chars().next().is_some_and(|c| !c.is_ascii_digit());

        if is_bare_identifier && !loop_counters.iter().any(|c| c == inner) {
            // Walk backward from `idx` to find the start of the array
            // identifier, for evidence purposes only.
            let mut start = idx;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_')
            {
                start -= 1;
            }
            sites.push(RangeSensitiveSite {
                identifier: inner.to_string(),
                line: line_number_at(body, idx),
                evidence: body[start..idx + 1 + close_rel + 1].to_string(),
            });
        }
    }

    sites
}

/// Finds the matching `]` for an implicit `[` at the start of `text` (i.e.
/// `text` is everything *after* the opening bracket).
fn find_matching_close_bracket_in(text: &str) -> Option<usize> {
    let mut depth = 1i32;
    for (idx, ch) in text.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

/// Finds narrowing-cast sites: `<expr> as <narrow-type>` where `<expr>`'s
/// immediately-preceding token is an identifier (covers both the bare
/// `index as u32` case and, conservatively, the common
/// `(arithmetic) as u32` case by also walking back across a closing
/// paren+matching arithmetic when present is **not** attempted in v1 — the
/// identifier immediately before the cast keyword is what is reported,
/// matching the taxonomy's example `let i = index as u32;`).
fn find_narrowing_cast_sites(body: &str) -> Vec<RangeSensitiveSite> {
    let mut sites = Vec::new();

    for suffix in NARROWING_CAST_SUFFIXES {
        let mut search_from = 0usize;
        while let Some(rel) = body[search_from..].find(suffix) {
            let idx = search_from + rel;
            let boundary_ok = idx == 0
                || !(body.as_bytes()[idx - 1].is_ascii_alphanumeric()
                    || body.as_bytes()[idx - 1] == b'_');
            if !boundary_ok {
                search_from = idx + suffix.len();
                continue;
            }

            // Walk backward over whitespace then an identifier token
            // immediately preceding ` as `.
            let before = body[..idx].trim_end();
            let ident_end = before.len();
            let mut ident_start = ident_end;
            while ident_start > 0
                && (before.as_bytes()[ident_start - 1].is_ascii_alphanumeric()
                    || before.as_bytes()[ident_start - 1] == b'_')
            {
                ident_start -= 1;
            }
            let identifier = &before[ident_start..ident_end];

            if !identifier.is_empty() && !identifier.chars().next().unwrap_or('0').is_ascii_digit()
            {
                let evidence_start = ident_start;
                let evidence_end = idx + suffix.len();
                sites.push(RangeSensitiveSite {
                    identifier: identifier.to_string(),
                    line: line_number_at(body, ident_start),
                    evidence: body[evidence_start..evidence_end].to_string(),
                });
            }

            search_from = idx + suffix.len();
        }
    }

    sites
}

/// Finds unsigned-subtraction sites: a bare identifier immediately
/// followed by ` - ` (binary subtraction, not a unary negative literal).
/// Per the taxonomy, this is a syntactic shape match only — it does not
/// confirm the operand's declared type is actually one of `u8`/.../`u64`,
/// matching the taxonomy's framing of this as the most heuristic NOIR-RANGE
/// detection.
fn find_unsigned_subtraction_sites(body: &str) -> Vec<RangeSensitiveSite> {
    let mut sites = Vec::new();
    let mut search_from = 0usize;

    while let Some(rel) = body[search_from..].find(" - ") {
        let idx = search_from + rel;
        let before = body[..idx].trim_end();
        let ident_end = before.len();
        let mut ident_start = ident_end;
        while ident_start > 0
            && (before.as_bytes()[ident_start - 1].is_ascii_alphanumeric()
                || before.as_bytes()[ident_start - 1] == b'_')
        {
            ident_start -= 1;
        }
        let identifier = &before[ident_start..ident_end];

        let is_bare_identifier =
            !identifier.is_empty() && !identifier.chars().next().unwrap_or('0').is_ascii_digit();

        if is_bare_identifier {
            // Evidence spans from the identifier through the next token
            // after the `-` (best-effort, just for readability of the
            // finding; not used for further matching).
            let after = &body[idx + 3..];
            let rhs_end = after
                .find([';', ')', ','])
                .map(|p| idx + 3 + p)
                .unwrap_or(body.len());
            sites.push(RangeSensitiveSite {
                identifier: identifier.to_string(),
                line: line_number_at(body, ident_start),
                evidence: body[ident_start..rhs_end].trim().to_string(),
            });
        }

        search_from = idx + 3;
    }

    sites
}

/// True if `body` contains a recognized range-check idiom (see
/// [`RANGE_CHECK_HINTS`]) that also references `identifier` as a token
/// within the same call/assert expression, per `docs/rule-taxonomy.md`
/// NOIR-RANGE-001 detection strategy step 2.
///
/// Two recognized shapes, checked both directly on `identifier` and, per
/// NOIR-RANGE-001's taxonomy-mandated safe pattern (`assert(index as u32 <
/// 8); let i = index as u32; let v = items[i];`), via one `let`-hop
/// indirection so a range check on the *source* identifier of a binding is
/// recognized as covering the *bound* identifier too:
/// 1. `identifier` appears as a token inside the argument list of an
///    `assert(...)`/`assert_eq(...)`/`constrain ...` call whose argument
///    text *also* contains a comparison operator against what looks like a
///    bound (a numeric literal or a identifier — kept permissive: any
///    comparison co-occurring with the identifier inside an assert is
///    treated as a plausible bound check, since precisely distinguishing
///    "a bound check" from "an unrelated comparison" is exactly the
///    type-width-aware reasoning the taxonomy says this rule does not
///    attempt).
/// 2. `identifier` appears as a token inside the argument list of a call
///    whose callee name contains one of [`RANGE_CHECK_HINTS`].
///
/// One-hop indirection mirrors [`identifier_appears_in_constraint`]'s
/// existing "one level of indirection" allowance, but in the opposite
/// direction: [`lets_referencing`] (used by NOIR-PUBLIC-001/
/// NOIR-CONSTRAINT-001) starts from a *source* identifier and finds names
/// bound from it, whereas here `identifier` is itself the *bound name*
/// (e.g. `i` in `let i = index as u32;`), and [`let_binding_sources`] finds
/// the *source* identifier(s) feeding that binding (`index`), so a range
/// check on `index` is recognized as covering `i` too.
#[must_use]
pub fn has_range_check_for_identifier(body: &str, identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }

    if direct_range_check_for_identifier(body, identifier) {
        return true;
    }

    // One-hop indirection: `identifier` was itself bound from some other
    // identifier (`let identifier = source as u32;`) that is directly
    // range-checked elsewhere in `body`.
    for source_identifier in let_binding_sources(body, identifier) {
        if direct_range_check_for_identifier(body, &source_identifier) {
            return true;
        }
    }

    false
}

/// Direct (non-indirect) check for the two range-check shapes documented on
/// [`has_range_check_for_identifier`].
fn direct_range_check_for_identifier(body: &str, identifier: &str) -> bool {
    // Shape 1: assert/assert_eq/constrain call whose arguments contain both
    // the identifier and a comparison operator.
    for keyword in CONSTRAINT_KEYWORDS {
        let mut search_from = 0usize;
        while let Some(rel) = body[search_from..].find(keyword) {
            let idx = search_from + rel;
            let after_kw = idx + keyword.len();
            let boundary_ok = idx == 0
                || !(body.as_bytes()[idx - 1].is_ascii_alphanumeric()
                    || body.as_bytes()[idx - 1] == b'_');
            if boundary_ok {
                let rest = body[after_kw..].trim_start();
                if let Some(stripped) = rest.strip_prefix('(') {
                    if let Some(close_rel) = find_matching_close_paren_in(stripped) {
                        let args = &stripped[..close_rel];
                        if contains_identifier_token(args, identifier)
                            && contains_top_level_comparison(args)
                        {
                            return true;
                        }
                    }
                }
            }
            search_from = after_kw;
        }
    }

    // Shape 2: call to a recognized range-check helper referencing the
    // identifier in its arguments.
    for hint in RANGE_CHECK_HINTS {
        let mut search_from = 0usize;
        while let Some(rel) = body[search_from..].find(hint) {
            let idx = search_from + rel;
            let after_hint = idx + hint.len();
            let boundary_ok = idx == 0
                || !(body.as_bytes()[idx - 1].is_ascii_alphanumeric()
                    || body.as_bytes()[idx - 1] == b'_');
            let next_is_call = body[after_hint..].trim_start().starts_with('(');
            if boundary_ok && next_is_call {
                let rest = body[after_hint..].trim_start();
                if let Some(stripped) = rest.strip_prefix('(') {
                    if let Some(close_rel) = find_matching_close_paren_in(stripped) {
                        let args = &stripped[..close_rel];
                        if contains_identifier_token(args, identifier) {
                            return true;
                        }
                    }
                }
            }
            search_from = after_hint;
        }
    }

    false
}

/// Returns the source identifier(s) referenced on the right-hand side of
/// every `let <bound_name> = <expr>;` statement in `body` whose
/// `<bound_name>` equals `bound_name`, e.g. for `let i = index as u32;`
/// with `bound_name = "i"`, returns `["index"]` (every identifier token
/// found in the RHS, not just the first — a permissive over-approximation
/// consistent with this module's other text-level heuristics).
fn let_binding_sources(body: &str, bound_name: &str) -> Vec<String> {
    let mut sources = Vec::new();
    let mut search_from = 0usize;

    while let Some(rel) = body[search_from..].find("let ") {
        let idx = search_from + rel;
        let boundary_ok = idx == 0
            || !(body.as_bytes()[idx - 1].is_ascii_alphanumeric()
                || body.as_bytes()[idx - 1] == b'_');
        if !boundary_ok {
            search_from = idx + 4;
            continue;
        }

        let after_let = &body[idx + 4..];
        let stmt_end = after_let.find(';').unwrap_or(after_let.len());
        let stmt = &after_let[..stmt_end];

        if let Some(eq_idx) = find_assignment_equals(stmt) {
            let name_part = stmt[..eq_idx].trim();
            let name = name_part
                .split(':')
                .next()
                .unwrap_or(name_part)
                .trim()
                .trim_start_matches("mut ")
                .trim();
            if name == bound_name {
                let rhs = &stmt[eq_idx + 1..];
                for token in rhs.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                    if !token.is_empty() && !token.chars().next().unwrap_or('0').is_ascii_digit() {
                        sources.push(token.to_string());
                    }
                }
            }
        }

        search_from = idx + 4 + stmt_end;
    }

    sources
}

/// Substrings recognized as identifying a "hash/commitment function" callee
/// path, per `docs/rule-taxonomy.md` ZK-HASH-001 detection strategy step 1:
/// "calls to recognized hash functions used for commitments (e.g.
/// `poseidon::bn254::hash_*`, `std::hash::pedersen_hash`,
/// `std::hash::sha256`, or other calls whose callee path contains `hash`)."
/// Checking for the substring `"hash"` alone already covers the
/// `poseidon::...::hash_*` and `pedersen_hash` cases; `sha256` and
/// `pedersen` are listed separately since neither contains the literal
/// substring `"hash"`.
pub const HASH_CALLEE_HINTS: &[&str] = &["hash", "sha256", "pedersen"];

/// Substrings recognized as marking an identifier "plausibly a domain/
/// context tag," per `docs/rule-taxonomy.md` ZK-HASH-001 detection strategy
/// step 2 and ZK-NULLIFIER-001 detection strategy step 2 (which reuses this
/// same heuristic). Checked case-insensitively against argument identifier
/// tokens. `nullifier` is included because ZK-NULLIFIER-001 explicitly
/// extends this list with "or a per-application/per-action identifier such
/// as an action ID, contract address, or circuit identifier" — kept as one
/// shared, documented list per the `noir-static-analyzer` charter's
/// instruction to keep heuristics in one place rather than duplicating a
/// near-identical list in two rule modules.
pub const DOMAIN_TAG_HINTS: &[&str] = &["domain", "tag", "context", "version", "nullifier"];

/// One call to a recognized hash/commitment function with an inline array
/// literal argument, per `docs/rule-taxonomy.md` ZK-HASH-001 detection
/// strategy step 1 (`hash([a, b, c])` shape).
#[derive(Debug, Clone, PartialEq)]
pub struct HashCallSite {
    /// The callee text immediately before the array literal's `(`, e.g.
    /// `poseidon::bn254::hash_2`.
    pub callee: String,
    /// Identifier/literal tokens found inside the array literal argument,
    /// in order, e.g. `["a", "b"]` for `hash([a, b])`.
    pub arguments: Vec<String>,
    /// 1-based line on which the call starts.
    pub line: u32,
    /// The literal matched call text, used as `Finding::evidence`.
    pub evidence: String,
}

impl HashCallSite {
    /// True if none of [`Self::arguments`] looks like a domain/context tag
    /// per [`DOMAIN_TAG_HINTS`] (case-insensitive substring match), i.e. no
    /// apparent domain separator was passed to this hash call.
    #[must_use]
    pub fn lacks_apparent_domain_tag(&self) -> bool {
        !self.arguments.iter().any(|arg| {
            let lower = arg.to_lowercase();
            DOMAIN_TAG_HINTS.iter().any(|hint| lower.contains(hint))
        })
    }

    /// The argument count, used to compare call "shape" across call sites
    /// per ZK-HASH-001 detection strategy step 2's second condition
    /// (same arity used for more than one distinct logical commitment).
    #[must_use]
    pub fn arity(&self) -> usize {
        self.arguments.len()
    }
}

/// Scans `source` (intended to be a whole file's text, not a single
/// function body, since ZK-HASH-001's cross-call comparison is file/
/// project scoped per the taxonomy) for calls to a recognized hash/
/// commitment function whose argument is an inline array literal, e.g.
/// `poseidon::bn254::hash_2([a, b])`.
///
/// Detection approach: find every occurrence of a [`HASH_CALLEE_HINTS`]
/// substring, check whether it is immediately followed (after optional
/// whitespace) by `(` then `[` (the `hash([...])` shape the taxonomy
/// targets), and if so extract the comma-separated tokens inside the array
/// literal as [`HashCallSite::arguments`].
///
/// Known limitations (documented, not silently assumed):
/// - Only the `func_name([a, b, c])` shape is recognized; a hash call whose
///   array is built via an intermediate `let` binding
///   (`let inputs = [a, b]; hash(inputs)`) is not recognized — a documented
///   false negative, since resolving `inputs` back to its literal requires
///   the same one-hop `let` tracing used elsewhere in this module and was
///   not judged worth the added complexity for v1 (the taxonomy's example
///   pattern is always the inline-literal shape).
/// - A domain tag passed via a wrapper function (e.g. `domain_hash(TAG, [a,
///   b])`) rather than inlined in the array literal is not recognized,
///   matching the taxonomy's documented false-positive note about wrapper
///   functions.
#[must_use]
pub fn find_hash_calls(source: &str) -> Vec<HashCallSite> {
    let masked = mask_comments(source);
    let mut sites = Vec::new();

    for hint in HASH_CALLEE_HINTS {
        let mut search_from = 0usize;
        while let Some(rel) = masked[search_from..].find(hint) {
            let idx = search_from + rel;
            let after_hint = idx + hint.len();
            let boundary_ok = idx == 0
                || !(masked.as_bytes()[idx - 1].is_ascii_alphanumeric()
                    || masked.as_bytes()[idx - 1] == b'_');
            // Allow the hint to be followed by more identifier characters
            // (e.g. `hash_2`, `hash256`) before the call's `(`.
            let mut callee_end = after_hint;
            while callee_end < masked.len()
                && (masked.as_bytes()[callee_end].is_ascii_alphanumeric()
                    || masked.as_bytes()[callee_end] == b'_')
            {
                callee_end += 1;
            }

            if boundary_ok {
                let rest = masked[callee_end..].trim_start();
                if let Some(after_open_paren) = rest.strip_prefix('(') {
                    let after_open_paren_trimmed = after_open_paren.trim_start();
                    if let Some(after_bracket) = after_open_paren_trimmed.strip_prefix('[') {
                        if let Some(close_bracket_rel) =
                            find_matching_close_bracket_in(after_bracket)
                        {
                            let array_inner = &after_bracket[..close_bracket_rel];
                            let arguments: Vec<String> = split_top_level_commas(array_inner)
                                .into_iter()
                                .map(|tok| tok.trim().to_string())
                                .filter(|tok| !tok.is_empty())
                                .collect();

                            // Walk back to the start of the callee path
                            // (identifier/`::` characters) for evidence.
                            let mut callee_start = idx;
                            while callee_start > 0
                                && (masked.as_bytes()[callee_start - 1].is_ascii_alphanumeric()
                                    || masked.as_bytes()[callee_start - 1] == b'_'
                                    || masked.as_bytes()[callee_start - 1] == b':')
                            {
                                callee_start -= 1;
                            }

                            // Find the absolute end of the call (including
                            // the closing `)`) for evidence purposes.
                            let close_bracket_abs = callee_end + 1 + after_open_paren.len()
                                - after_bracket.len()
                                + close_bracket_rel;
                            let after_close_bracket = &masked[close_bracket_abs + 1..];
                            let close_paren_rel = after_close_bracket.find(')');
                            let evidence_end = match close_paren_rel {
                                Some(p) => close_bracket_abs + 1 + p + 1,
                                None => close_bracket_abs + 1,
                            };

                            sites.push(HashCallSite {
                                callee: source[callee_start..callee_end].to_string(),
                                arguments,
                                line: line_number_at(source, callee_start),
                                evidence: source[callee_start..evidence_end].to_string(),
                            });
                        }
                    }
                }
            }

            search_from = callee_end.max(after_hint);
        }
    }

    sites
}

/// Naming-convention substrings recognized as "this binding/function is
/// nullifier-like," per `docs/rule-taxonomy.md` ZK-NULLIFIER-001 detection
/// strategy step 1: "a `let`/return value whose identifier, or the
/// function it is returned from, matches (case-insensitively) `nullifier`,
/// `null_hash`, or `spent_tag`." Checked case-insensitively as a substring
/// match (so `compute_nullifier`, `nullifier_value`, etc. all match), per
/// the taxonomy's explicit framing: "intentionally name-based — there is no
/// semantic way to recognize 'this value is meant to prevent replay' from
/// syntax alone."
pub const NULLIFIER_NAME_HINTS: &[&str] = &["nullifier", "null_hash", "spent_tag"];

/// One nullifier-like binding or function found by
/// [`find_nullifier_like_sites`], per `docs/rule-taxonomy.md`
/// ZK-NULLIFIER-001 detection strategy step 1.
#[derive(Debug, Clone, PartialEq)]
pub struct NullifierLikeSite {
    /// The matched identifier (the `let` binding's name, or the function's
    /// name for a single-expression-body function).
    pub name: String,
    /// 1-based line on which the binding/function starts.
    pub line: u32,
    /// The literal expression text computing this value (the `let`
    /// statement's RHS, or the function body's sole expression), used both
    /// for [`HashCallSite`] re-detection and as `Finding::evidence`.
    pub expression_text: String,
}

/// Scans `source` (whole-file text, matching [`find_hash_calls`]'s scope
/// rather than the single-`fn main`-body scope of the other three rules)
/// for nullifier-like bindings and functions, per `docs/rule-taxonomy.md`
/// ZK-NULLIFIER-001 detection strategy step 1.
///
/// Two recognized shapes:
/// 1. `let <ident> = <expr>;` where `<ident>` matches
///    [`NULLIFIER_NAME_HINTS`] case-insensitively.
/// 2. `fn <ident>(...) -> ... { <expr> }` where `<ident>` matches
///    [`NULLIFIER_NAME_HINTS`] case-insensitively and the function body is
///    a single trailing expression (Noir's implicit-return idiom, matching
///    the taxonomy's own example `fn compute_nullifier(...) -> Field {
///    poseidon::bn254::hash_2([secret, leaf_index]) }`).
///
/// Known limitations (documented, not silently assumed):
/// - Function bodies with intermediate `let` bindings before the final
///   return expression (`fn compute_nullifier(...) -> Field { let h =
///   hash(...); h }`) are not recognized as shape 2 in v1 — only a
///   single-expression body is. This is a documented false negative; such
///   functions would still be caught by shape 1 if the intermediate `let`
///   binding's name itself matches [`NULLIFIER_NAME_HINTS`] (as in the
///   example just given, `h` does not match, so it would currently be
///   missed — an accepted v1 gap, not a silent one).
#[must_use]
pub fn find_nullifier_like_sites(source: &str) -> Vec<NullifierLikeSite> {
    let masked = mask_comments(source);
    let mut sites = Vec::new();

    sites.extend(find_nullifier_like_let_bindings(source, &masked));
    sites.extend(find_nullifier_like_functions(source, &masked));

    sites
}

/// Shape 1: `let <ident> = <expr>;` bindings whose name matches
/// [`NULLIFIER_NAME_HINTS`].
fn find_nullifier_like_let_bindings(source: &str, masked: &str) -> Vec<NullifierLikeSite> {
    let mut sites = Vec::new();
    let mut search_from = 0usize;

    while let Some(rel) = masked[search_from..].find("let ") {
        let idx = search_from + rel;
        let boundary_ok = idx == 0
            || !(masked.as_bytes()[idx - 1].is_ascii_alphanumeric()
                || masked.as_bytes()[idx - 1] == b'_');
        if !boundary_ok {
            search_from = idx + 4;
            continue;
        }

        let after_let = &masked[idx + 4..];
        let stmt_end = after_let.find(';').unwrap_or(after_let.len());
        let stmt = &masked[idx + 4..idx + 4 + stmt_end];

        if let Some(eq_idx) = find_assignment_equals(stmt) {
            let name_part = stmt[..eq_idx].trim();
            let name = name_part
                .split(':')
                .next()
                .unwrap_or(name_part)
                .trim()
                .trim_start_matches("mut ")
                .trim();
            let lower = name.to_lowercase();
            if !name.is_empty() && NULLIFIER_NAME_HINTS.iter().any(|h| lower.contains(h)) {
                let rhs_start = idx + 4 + eq_idx + 1;
                let rhs_end = idx + 4 + stmt_end;
                sites.push(NullifierLikeSite {
                    name: name.to_string(),
                    line: line_number_at(source, idx),
                    expression_text: source[rhs_start..rhs_end].trim().to_string(),
                });
            }
        }

        search_from = idx + 4 + stmt_end;
    }

    sites
}

/// Shape 2: `fn <ident>(...) -> ... { <expr> }` single-expression-body
/// functions whose name matches [`NULLIFIER_NAME_HINTS`].
fn find_nullifier_like_functions(source: &str, masked: &str) -> Vec<NullifierLikeSite> {
    let mut sites = Vec::new();
    let mut search_from = 0usize;

    while let Some(rel) = masked[search_from..].find("fn ") {
        let idx = search_from + rel;
        let boundary_ok = idx == 0
            || !(masked.as_bytes()[idx - 1].is_ascii_alphanumeric()
                || masked.as_bytes()[idx - 1] == b'_');
        if !boundary_ok {
            search_from = idx + 3;
            continue;
        }

        let after_fn = masked[idx + 3..].trim_start();
        let name_end = after_fn
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(after_fn.len());
        let name = &after_fn[..name_end];

        let Some(brace_rel) = masked[idx..].find('{') else {
            break;
        };
        let body_open = idx + brace_rel;
        let Some(body_close) = matching_close_brace(masked, body_open) else {
            break;
        };

        let lower = name.to_lowercase();
        if !name.is_empty() && NULLIFIER_NAME_HINTS.iter().any(|h| lower.contains(h)) {
            let body = masked[body_open + 1..body_close].trim();
            // Only treat this as shape 2 if the body is a single trailing
            // expression: no `let` keyword and no top-level `;` other than
            // possibly a single trailing one (Noir allows but does not
            // require a trailing `;`-free implicit return).
            let body_no_trailing_semi = body.trim_end_matches(';').trim_end();
            let is_single_expression =
                !body.contains("let ") && !body_no_trailing_semi.contains(';');
            if is_single_expression && !body_no_trailing_semi.is_empty() {
                sites.push(NullifierLikeSite {
                    name: name.to_string(),
                    line: line_number_at(source, idx),
                    expression_text: source[body_open + 1..body_close].trim().to_string(),
                });
            }
        }

        search_from = body_close + 1;
    }

    sites
}

/// Parses `expression_text` (typically a [`NullifierLikeSite`]'s
/// `expression_text`) as a single hash call, reusing the same detection
/// shape as [`find_hash_calls`], so ZK-NULLIFIER-001 can check whether the
/// nullifier-like value is itself the output of a tagged or untagged hash,
/// per `docs/rule-taxonomy.md` ZK-NULLIFIER-001 detection strategy step 2.
/// Returns `None` if `expression_text` is not (at its top level) a call to
/// a recognized hash function with an inline array literal argument — per
/// the taxonomy step 3, this is the "not the output of a hash at all"
/// signal, which is a *stronger* vulnerability indicator than a hash
/// lacking a tag.
#[must_use]
pub fn as_hash_call(expression_text: &str) -> Option<HashCallSite> {
    find_hash_calls(expression_text).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_comments_blanks_line_comments_but_preserves_length_and_newlines() {
        let source = "let a = 1; // a comment with fn main(\nlet b = 2;\n";
        let masked = mask_comments(source);
        assert_eq!(masked.len(), source.len());
        assert!(!masked.contains("fn main"));
        assert!(masked.contains("let a = 1;"));
        assert!(masked.contains("let b = 2;"));
        // Newline count (hence line numbers) must be unchanged.
        assert_eq!(masked.matches('\n').count(), source.matches('\n').count());
    }

    #[test]
    fn mask_comments_blanks_block_comments_preserving_internal_newlines() {
        let source = "let a = 1;\n/* fn main(\n   block comment */\nlet b = 2;\n";
        let masked = mask_comments(source);
        assert_eq!(masked.len(), source.len());
        assert!(!masked.contains("fn main"));
        assert!(masked.contains("let a = 1;"));
        assert!(masked.contains("let b = 2;"));
        assert_eq!(masked.matches('\n').count(), source.matches('\n').count());
    }

    #[test]
    fn mask_comments_leaves_code_with_no_comments_untouched() {
        let source = "fn main(secret: Field) {\n    assert(secret == 1);\n}\n";
        assert_eq!(mask_comments(source), source);
    }

    #[test]
    fn finds_single_entry_point_with_public_param() {
        let source = "fn main(secret: Field, pub claimed_total: Field) {\n    let computed = secret * 2;\n}\n";
        let entries = find_fn_entry_points(source);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.signature_line, 1);
        assert_eq!(entry.public_params.len(), 1);
        assert_eq!(entry.public_params[0].name, "claimed_total");
        assert_eq!(entry.public_params[0].line, 1);
        assert_eq!(
            entry.public_params[0].declaration_text,
            "pub claimed_total: Field"
        );
    }

    #[test]
    fn finds_no_public_params_when_none_declared() {
        let source = "fn main(secret: Field, other: Field) {\n}\n";
        let entries = find_fn_entry_points(source);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].public_params.is_empty());
    }

    #[test]
    fn ignores_non_main_functions() {
        let source = "fn helper(pub x: Field) {\n    assert(x == 0);\n}\n";
        let entries = find_fn_entry_points(source);
        assert!(entries.is_empty());
    }

    #[test]
    fn direct_use_in_assert_is_detected() {
        let body = "let computed = secret * 2;\nassert(computed == claimed_total);\n";
        assert!(identifier_appears_in_constraint(body, "claimed_total"));
    }

    #[test]
    fn unused_identifier_is_not_detected() {
        let body = "let computed = secret * 2;\n";
        assert!(!identifier_appears_in_constraint(body, "claimed_total"));
    }

    #[test]
    fn one_hop_indirection_is_detected() {
        let body = "let x = claimed_total + 1;\nassert(x == computed);\n";
        assert!(identifier_appears_in_constraint(body, "claimed_total"));
    }

    #[test]
    fn println_only_use_is_not_a_constraint() {
        let body = "println(claimed_total);\n";
        assert!(!identifier_appears_in_constraint(body, "claimed_total"));
    }

    #[test]
    fn assert_eq_keyword_is_recognized() {
        let body = "assert_eq(claimed_total, computed);\n";
        assert!(identifier_appears_in_constraint(body, "claimed_total"));
    }

    /// GENUINE BUG (not a documented `docs/rule-taxonomy.md` limitation),
    /// found while building fixtures for Step 5 (`fixtures-test-engineer`).
    ///
    /// `find_fn_entry_points` searches for the literal substring `"fn
    /// main"` and does not skip over `//` line comments (see this
    /// function's own doc comment: "Does not understand string literals or
    /// comments containing `{`/`}` ... a known, accepted v1 limitation" —
    /// that limitation is scoped to brace characters inside
    /// comments/strings, NOT to the initial `"fn main"` substring search
    /// itself, which has no comment-awareness at all).
    ///
    /// If a `//` comment anywhere above the real `fn main` declaration
    /// happens to contain the literal text `fn main` followed eventually by
    /// an opening paren (e.g. ordinary prose like "the `fn main(...)`
    /// signature" or, as below, a comment that simply says `// fn main is
    /// the entry point`), the scanner locks onto that comment as the
    /// "signature start," searches forward for the first `{`/`}` pair
    /// (which ends up being the REAL function's body, since the comment
    /// itself has no braces), and then tries to extract `pub` parameters
    /// from a `signature_text` that is actually comment prose followed by
    /// the real signature concatenated together. Depending on the exact
    /// comment wording, this can silently drop real `pub` parameters
    /// (this test) or, by luck, produce a coincidentally-correct empty
    /// parameter list (masking the bug rather than failing loudly).
    ///
    /// **FIXED in Step 7** (`noir-static-analyzer`): `find_fn_entry_points`
    /// now runs its `"fn main"` substring search and brace-matching against
    /// a comment-masked copy of the source (see [`mask_comments`]), so a
    /// comment that merely mentions the entry point's name (even one
    /// containing its own opening paren) can no longer be misidentified as
    /// the real declaration. This test is un-`#[ignore]`d and now asserts
    /// the correct (fixed) behavior rather than pinning the bug.
    #[test]
    fn comment_mentioning_entry_point_name_corrupts_param_extraction() {
        let source = "// fn main (the entry point) has no pub params here\n\
                       fn main(secret: Field, pub claimed_total: Field) {\n\
                       \x20   assert(secret == claimed_total);\n\
                       }\n";

        let entries = find_fn_entry_points(source);
        assert_eq!(entries.len(), 1);
        // This is the desired/correct behavior, which currently fails: the
        // real `pub claimed_total` parameter should still be found even
        // though an earlier comment also contains the text "fn main" and
        // its own parenthesis.
        assert_eq!(
            entries[0].public_params.len(),
            1,
            "comment mentioning the entry point's name corrupted parameter \
             extraction: {:#?}",
            entries[0]
        );
    }

    #[test]
    fn finds_boolean_let_binding_from_equality() {
        let body = "let is_equal = a == b;\n";
        let bindings = find_boolean_let_bindings(body);
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].name, "is_equal");
        assert_eq!(bindings[0].line, 1);
        assert_eq!(bindings[0].statement_text, "let is_equal = a == b;");
    }

    #[test]
    fn finds_boolean_let_binding_from_each_comparison_operator() {
        for op in ["==", "!=", "<", "<=", ">", ">="] {
            let body = format!("let cond = a {op} b;\n");
            let bindings = find_boolean_let_bindings(&body);
            assert_eq!(bindings.len(), 1, "operator {op} not detected");
            assert_eq!(bindings[0].name, "cond");
        }
    }

    #[test]
    fn non_boolean_let_binding_is_not_flagged() {
        let body = "let total = a + b;\n";
        assert!(find_boolean_let_bindings(body).is_empty());
    }

    #[test]
    fn boolean_let_binding_line_number_is_correct_on_later_lines() {
        let body = "let a = 1;\nlet b = 2;\nlet is_equal = a == b;\n";
        let bindings = find_boolean_let_bindings(body);
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].line, 3);
    }

    #[test]
    fn multiple_boolean_bindings_are_all_found() {
        let body = "let is_equal = a == b;\nlet in_range = a < b;\n";
        let bindings = find_boolean_let_bindings(body);
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].name, "is_equal");
        assert_eq!(bindings[1].name, "in_range");
    }

    #[test]
    fn assignment_equals_is_not_confused_with_comparison_operators() {
        // A binding whose RHS has no comparison at all must not be detected
        // just because `find_assignment_equals` has to skip past `==`-like
        // sequences; this also indirectly exercises `find_assignment_equals`
        // since this binding's RHS itself contains no `=` at all.
        let body = "let total = a + b;\n";
        assert!(find_boolean_let_bindings(body).is_empty());
    }

    #[test]
    fn identifier_used_as_constraint_condition_matches_bare_boolean_assert() {
        let body = "let is_equal = a == b;\nassert(is_equal);\n";
        assert!(identifier_used_as_constraint_condition(body, "is_equal"));
    }

    #[test]
    fn identifier_used_as_constraint_condition_false_when_unused() {
        let body = "let is_equal = a == b;\n";
        assert!(!identifier_used_as_constraint_condition(body, "is_equal"));
    }

    #[test]
    fn finds_unbounded_index_site() {
        let body = "let i = index as u32;\nlet v = items[i];\n";
        let sites = find_range_sensitive_sites(body);
        assert!(
            sites.iter().any(|s| s.identifier == "i"),
            "expected an indexing site on `i`, got: {sites:#?}"
        );
    }

    #[test]
    fn does_not_flag_constant_index() {
        let body = "let v = items[0];\n";
        let sites = find_indexing_sites(body, &[]);
        assert!(
            sites.is_empty(),
            "constant index must not be flagged: {sites:#?}"
        );
    }

    #[test]
    fn does_not_flag_for_loop_counter_index() {
        let body = "for i in 0..4 {\n    let v = items[i];\n}\n";
        let sites = find_range_sensitive_sites(body);
        assert!(
            sites.is_empty(),
            "for _ in 0..N loop counter must not be flagged: {sites:#?}"
        );
    }

    #[test]
    fn flags_index_not_matching_a_different_loop_counter() {
        let body = "for i in 0..4 {\n    let v = items[j];\n}\n";
        let sites = find_range_sensitive_sites(body);
        assert!(
            sites.iter().any(|s| s.identifier == "j"),
            "an index identifier different from the loop counter must still be flagged: \
             {sites:#?}"
        );
    }

    #[test]
    fn finds_narrowing_cast_site() {
        let body = "let i = index as u32;\n";
        let sites = find_narrowing_cast_sites(body);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].identifier, "index");
        assert_eq!(sites[0].evidence, "index as u32");
    }

    #[test]
    fn does_not_flag_widening_or_field_cast() {
        // `as Field` / `as u64` are not in NARROWING_CAST_SUFFIXES.
        let body = "let i = index as Field;\nlet j = index as u64;\n";
        assert!(find_narrowing_cast_sites(body).is_empty());
    }

    #[test]
    fn finds_unsigned_subtraction_site() {
        let body = "let diff = balance - amount;\n";
        let sites = find_unsigned_subtraction_sites(body);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].identifier, "balance");
    }

    #[test]
    fn has_range_check_for_identifier_detects_inline_assert_bound() {
        let body = "let i = index as u32;\nassert(index as u32 < 8);\nlet v = items[i];\n";
        assert!(has_range_check_for_identifier(body, "index"));
    }

    #[test]
    fn has_range_check_for_identifier_detects_named_helper() {
        let body = "range_check(index, 8);\n";
        assert!(has_range_check_for_identifier(body, "index"));
    }

    #[test]
    fn has_range_check_for_identifier_false_when_absent() {
        let body = "let i = index as u32;\nlet v = items[i];\n";
        assert!(!has_range_check_for_identifier(body, "index"));
        assert!(!has_range_check_for_identifier(body, "i"));
    }

    /// Regression guard: the `lt`/`lte` hints in [`RANGE_CHECK_HINTS`] are
    /// short substrings that could in principle match inside an unrelated
    /// longer identifier (e.g. `salty(...)` contains the substring `"lt"`).
    /// The `next_is_call` requirement (hint immediately followed by
    /// optional whitespace then `(`) is what prevents this: `salty(` has
    /// `y(` immediately after the `lt` substring, not `(`, so it must not
    /// be treated as a call to a range-check helper.
    #[test]
    fn has_range_check_for_identifier_does_not_match_lt_inside_unrelated_identifier() {
        let body = "let result = salty(index);\n";
        assert!(!has_range_check_for_identifier(body, "index"));
    }

    /// Taxonomy's safe pattern: `assert(index as u32 < 8); let i = index as
    /// u32; let v = items[i];`. A range check on `index` must be recognized
    /// as covering `i`, since `i` was bound directly from `index`.
    #[test]
    fn has_range_check_for_identifier_follows_one_hop_let_binding() {
        let body = "assert(index as u32 < 8);\nlet i = index as u32;\nlet v = items[i];\n";
        assert!(has_range_check_for_identifier(body, "i"));
    }

    #[test]
    fn has_range_check_for_identifier_one_hop_does_not_fire_when_source_unchecked() {
        let body = "let i = index as u32;\nlet v = items[i];\n";
        assert!(!has_range_check_for_identifier(body, "i"));
    }

    #[test]
    fn finds_hash_call_with_inline_array_literal() {
        let source = "fn leaf_commitment(a: Field, b: Field) -> Field {\n    poseidon::bn254::hash_2([a, b])\n}\n";
        let sites = find_hash_calls(source);
        assert_eq!(sites.len(), 1, "sites: {sites:#?}");
        assert_eq!(sites[0].callee, "poseidon::bn254::hash_2");
        assert_eq!(sites[0].arguments, vec!["a", "b"]);
        assert_eq!(sites[0].line, 2);
    }

    #[test]
    fn hash_call_without_array_literal_argument_is_not_matched() {
        let source =
            "fn f(inputs: [Field; 2]) -> Field {\n    poseidon::bn254::hash_2(inputs)\n}\n";
        assert!(find_hash_calls(source).is_empty());
    }

    #[test]
    fn lacks_apparent_domain_tag_true_when_no_tag_argument() {
        let source = "fn f(a: Field, b: Field) -> Field {\n    hash_2([a, b])\n}\n";
        let sites = find_hash_calls(source);
        assert_eq!(sites.len(), 1);
        assert!(sites[0].lacks_apparent_domain_tag());
    }

    #[test]
    fn lacks_apparent_domain_tag_false_when_tag_argument_present() {
        let source = "fn f(a: Field, b: Field) -> Field {\n    hash_3([LEAF_DOMAIN, a, b])\n}\n";
        let sites = find_hash_calls(source);
        assert_eq!(sites.len(), 1);
        assert!(!sites[0].lacks_apparent_domain_tag());
    }

    #[test]
    fn finds_multiple_hash_calls_in_one_file() {
        let source = "fn leaf(a: Field, b: Field) -> Field {\n    hash_2([a, b])\n}\nfn nullifier_hash(c: Field, d: Field) -> Field {\n    hash_2([c, d])\n}\n";
        let sites = find_hash_calls(source);
        assert_eq!(sites.len(), 2, "sites: {sites:#?}");
        assert_eq!(sites[0].arity(), 2);
        assert_eq!(sites[1].arity(), 2);
    }

    #[test]
    fn hash_call_inside_comment_is_not_matched() {
        let source = "// hash_2([a, b])\nfn f(a: Field, b: Field) -> Field {\n    a + b\n}\n";
        assert!(find_hash_calls(source).is_empty());
    }

    #[test]
    fn finds_nullifier_like_let_binding() {
        let source =
            "fn main(secret: Field) -> Field {\n    let nullifier = poseidon::bn254::hash_2([secret, 1]);\n    nullifier\n}\n";
        let sites = find_nullifier_like_sites(source);
        assert_eq!(sites.len(), 1, "sites: {sites:#?}");
        assert_eq!(sites[0].name, "nullifier");
        assert_eq!(
            sites[0].expression_text,
            "poseidon::bn254::hash_2([secret, 1])"
        );
    }

    #[test]
    fn finds_nullifier_like_function_with_single_expression_body() {
        let source = "fn compute_nullifier(secret: Field, leaf_index: Field) -> Field {\n    poseidon::bn254::hash_2([secret, leaf_index])\n}\n";
        let sites = find_nullifier_like_sites(source);
        assert_eq!(sites.len(), 1, "sites: {sites:#?}");
        assert_eq!(sites[0].name, "compute_nullifier");
        assert_eq!(
            sites[0].expression_text,
            "poseidon::bn254::hash_2([secret, leaf_index])"
        );
    }

    #[test]
    fn does_not_flag_unrelated_names() {
        let source =
            "fn leaf_commitment(secret: Field) -> Field {\n    poseidon::bn254::hash_1([secret])\n}\n";
        assert!(find_nullifier_like_sites(source).is_empty());
    }

    #[test]
    fn finds_nullifier_like_site_for_raw_unhashed_value() {
        let source =
            "fn main(secret: Field) -> Field {\n    let nullifier = secret;\n    nullifier\n}\n";
        let sites = find_nullifier_like_sites(source);
        assert_eq!(sites.len(), 1, "sites: {sites:#?}");
        assert_eq!(sites[0].expression_text, "secret");
    }

    #[test]
    fn function_body_with_intermediate_let_is_not_recognized_as_shape_two() {
        // Documented v1 limitation: a multi-statement function body is not
        // matched by `find_nullifier_like_functions`'s single-expression
        // shape, even though the function's name matches.
        let source =
            "fn compute_nullifier(secret: Field) -> Field {\n    let h = secret;\n    h\n}\n";
        assert!(find_nullifier_like_sites(source).is_empty());
    }

    #[test]
    fn as_hash_call_recognizes_hash_expression() {
        let parsed = as_hash_call("poseidon::bn254::hash_2([secret, leaf_index])");
        match parsed {
            Some(call) => assert_eq!(call.arguments, vec!["secret", "leaf_index"]),
            None => panic!("expected a recognized hash call"),
        }
    }

    #[test]
    fn as_hash_call_returns_none_for_non_hash_expression() {
        assert!(as_hash_call("secret").is_none());
    }
}
