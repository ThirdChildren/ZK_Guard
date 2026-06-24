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
/// - Does not understand string literals or comments containing `{`/`}`;
///   a `{`/`}` inside a `//` comment or string would desynchronize brace
///   counting. Noir circuits rarely contain such literals in practice, and
///   this is a known, accepted v1 limitation rather than a silent bug.
/// - Only recognizes the literal `fn main` signature; helper functions
///   with other names are intentionally not treated as entry points (see
///   module doc and NOIR-PUBLIC-001 false-positive notes).
#[must_use]
pub fn find_fn_entry_points(source: &str) -> Vec<FnEntryPoint> {
    let mut entry_points = Vec::new();
    let bytes = source.as_bytes();
    let mut search_from = 0usize;

    while let Some(rel_idx) = source[search_from..].find("fn main") {
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
        // the signature start.
        let Some(brace_rel) = source[fn_idx..].find('{') else {
            // Malformed/truncated signature (e.g. end of file mid-edit);
            // nothing more to extract for this match.
            break;
        };
        let body_open = fn_idx + brace_rel;
        let signature_text = source[fn_idx..body_open].to_string();
        let body_start_line = line_number_at(source, body_open);

        let Some(body_close) = matching_close_brace(source, body_open) else {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    /// This is `#[ignore]`d rather than fixed here, per the
    /// `fixtures-test-engineer` task protocol ("If you discover a genuine
    /// bug ... do NOT silently fix the rule ... add a test marked
    /// #[ignore]"). Suggested fix direction for whoever picks this up
    /// (likely `noir-static-analyzer`, Step 7 territory since it touches
    /// the shared heuristic, not just one rule): strip `//` line comments
    /// (and ideally block comments) from the source before running any of
    /// `find_fn_entry_points`'s text search, or require the matched `"fn
    /// main"` occurrence to start at the beginning of a non-comment line.
    ///
    /// Reproduction note: the comment must contain an opening `(` of its
    /// own (typical of ordinary prose like "(declared `pub`)") *before* the
    /// real signature's `(` for the bug to corrupt the extracted parameter
    /// list; a comment mentioning "fn main" with no parenthesis at all
    /// happens to still resolve correctly, because
    /// `extract_public_params` finds the comment's `fn main` occurrence but
    /// then locates the real signature's own `(` as the first parenthesis
    /// in the (corrupted) `signature_text` span — so this is not a
    /// reliable mitigation, just a narrower trigger condition.
    #[test]
    #[ignore = "genuine bug: find_fn_entry_points does not skip `//` comments \
                before searching for the literal `fn main` substring, so a \
                comment merely mentioning the entry point's name (and \
                containing its own opening paren) can be misidentified as \
                the real declaration and corrupt signature/param \
                extraction; see test body and \
                fixtures/noir/safe/noir-public-001-multiline-signature for \
                the discovery context. Tracked for noir-static-analyzer, \
                not fixed by fixtures-test-engineer."]
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
}
