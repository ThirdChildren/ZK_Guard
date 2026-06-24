//! Reusable `proptest` `Strategy` builders shared by the property tests
//! under `tests/`.
//!
//! Two families of generators live here, matching the two distinct
//! properties `docs/agent-workflow.md` Step 9 asks for:
//!
//! 1. [`arbitrary_text`] / [`pathological_text`]: unstructured, possibly
//!    hostile text, used only to assert robustness ("no panic, terminates")
//!    and determinism — these generators make **no** attempt to look like
//!    Noir source, by design, since the point is to stress the heuristic
//!    text scanners in `zkguard_noir::heuristics` with inputs they were
//!    never designed to handle (deeply nested brackets, unbalanced braces,
//!    huge identifiers, embedded comment/string syntax, very long lines).
//! 2. [`noir_main_snippet`] and its building blocks: small, intentionally
//!    narrow generators that emit syntactically-controlled `fn main`
//!    snippets, used only to assert the specific directional safe/
//!    vulnerable guarantees each rule's `docs/rule-taxonomy.md` entry
//!    already commits to. These are deliberately *not* a general Noir
//!    fuzzer — see `tests/property_directional.rs` module doc for why a
//!    broader generator would assert properties the taxonomy does not
//!    promise (and would therefore encode false confidence, the opposite of
//!    CLAUDE.md principle 3's "false positives are acceptable only if
//!    clearly marked with confidence").

use proptest::prelude::*;

/// Bound on generated arbitrary-text length, keeping each proptest case
/// cheap (so `cases: 256` in a `ProptestConfig` still finishes in seconds)
/// while still exercising "very long line" pathological inputs at the upper
/// end of this range.
const MAX_ARBITRARY_TEXT_LEN: usize = 2_000;

/// A `Strategy` producing arbitrary, unconstrained `String`s (valid UTF-8,
/// since `SourceView::source` is a `String`, not raw bytes) — the
/// "random UTF-8 text" generator from Step 9's robustness property.
///
/// This intentionally includes the full `char` range proptest's default
/// `String` strategy can produce (ASCII, multi-byte UTF-8, control
/// characters), not just printable ASCII, since the heuristics in
/// `zkguard_noir::heuristics` operate on raw byte/char offsets and must not
/// panic on multi-byte boundaries either.
pub fn arbitrary_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::any(), 0..MAX_ARBITRARY_TEXT_LEN)
        .prop_map(|chars| chars.into_iter().collect())
}

/// A cheap (debug-build-friendly) identifier-like token: 1-40 lowercase
/// ASCII letters. Built from [`proptest::char::ranges`] + `prop::collection`
/// rather than a `string_regex`/regex-`&str`-`Strategy` literal, because
/// proptest's regex-backed string strategies compile and walk a regex
/// automaton *per generated value*, which was measured (see this task's
/// final report) to be roughly 1000x slower per sample than this
/// hand-rolled char-vector approach in an unoptimized (`cargo test`
/// default) build — the difference between this crate's whole property
/// suite running in seconds vs. tens of seconds. The two approaches produce
/// an equivalent alphabet for this generator's purposes (no semantic
/// distinction matters here, only "looks like an identifier").
fn cheap_identifier_token() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::char::ranges(vec!['a'..='z', 'A'..='Z'].into()),
        1..40,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// A cheap digit-only token, mirroring [`cheap_identifier_token`]'s
/// rationale for avoiding regex-backed string strategies in a hot
/// generation path.
fn cheap_digit_token() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::ranges(vec!['0'..='9'].into()), 1..20)
        .prop_map(|chars| chars.into_iter().collect())
}

/// A `Strategy` producing text built only from a small, Noir-syntax-shaped
/// alphabet (`{`, `}`, `(`, `)`, `[`, `]`, `<`, `>`, identifiers, `fn`,
/// `main`, `pub`, `let`, `assert`, comment markers, quotes, `;`, `,`, `:`,
/// whitespace, digits) rather than fully arbitrary Unicode.
///
/// This targets exactly the "pathological but syntax-adjacent" inputs Step
/// 9 calls out (deeply nested brackets, unbalanced braces, huge
/// identifiers, comment/string edge cases) with much higher probability
/// than [`arbitrary_text`], whose uniform-random characters rarely happen
/// to contain even a single brace. Both generators are run by the
/// robustness property tests since they stress different failure modes:
/// [`arbitrary_text`] stresses UTF-8/char-boundary handling, this one
/// stresses the brace-matching/keyword-search control flow itself.
///
/// Token-count bound: `0..80` (rather than, say, `0..400`) is a deliberate
/// performance choice, not a coverage compromise — `proptest`'s
/// `prop_oneof!`/`Union` weighted-selection machinery has measurable
/// per-element overhead in an unoptimized (`cargo test` default) build
/// (see this task's final report for the measured ~12µs/element figure),
/// so this bound was chosen to keep this crate's whole property suite
/// running in low single-digit seconds under `cargo test -p zkguard-fuzz`
/// while still generating sources long enough (up to ~80 multi-character
/// tokens, i.e. potentially several hundred characters) to exercise deep
/// nesting, long unbalanced-brace runs, and multi-line comment edge cases.
pub fn pathological_noir_like_text() -> impl Strategy<Value = String> {
    let token = prop_oneof![
        Just("{".to_string()),
        Just("}".to_string()),
        Just("(".to_string()),
        Just(")".to_string()),
        Just("[".to_string()),
        Just("]".to_string()),
        Just("<".to_string()),
        Just(">".to_string()),
        Just("fn".to_string()),
        Just("main".to_string()),
        Just("pub".to_string()),
        Just("let".to_string()),
        Just("assert".to_string()),
        Just("assert_eq".to_string()),
        Just("constrain".to_string()),
        Just("//".to_string()),
        Just("/*".to_string()),
        Just("*/".to_string()),
        Just("\"".to_string()),
        Just(";".to_string()),
        Just(",".to_string()),
        Just(":".to_string()),
        Just("=".to_string()),
        Just("==".to_string()),
        Just(" ".to_string()),
        Just("\n".to_string()),
        Just("\t".to_string()),
        cheap_identifier_token(),
        cheap_digit_token(),
    ];

    proptest::collection::vec(token, 0..80).prop_map(|tokens| tokens.join(""))
}

/// Generates a single huge identifier-like token (no separators), targeting
/// Step 9's explicit "huge identifiers" pathological case independently of
/// [`pathological_noir_like_text`]'s token-join approach (which caps any one
/// token at 40 chars). Uses the same cheap char-vector approach as
/// [`cheap_identifier_token`] for the same debug-build performance reason,
/// scaled up to the much larger length this generator targets.
pub fn huge_identifier() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::char::ranges(vec!['a'..='z', 'A'..='Z'].into()),
        1..5000,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// Identifier strategy used inside structured [`noir_main_snippet`]
/// generation: short, simple, lowercase-ish identifiers so generated
/// snippets stay human-legible in proptest shrink output and never
/// accidentally collide with a Noir/rule keyword (`fn`, `main`, `pub`,
/// `let`, `assert`, etc. are excluded by construction since every character
/// is drawn only from `a`-`z`/`0`-`9`/`_`, never matching any multi-letter
/// reserved word these structured generators rely on staying distinct from).
fn plain_identifier() -> impl Strategy<Value = String> {
    (
        proptest::char::ranges(vec!['a'..='z'].into()),
        proptest::collection::vec(
            proptest::char::ranges(vec!['a'..='z', '0'..='9', '_'..='_'].into()),
            0..8,
        ),
    )
        .prop_map(|(first, rest)| {
            let mut s = String::with_capacity(1 + rest.len());
            s.push(first);
            s.extend(rest);
            s
        })
}

/// One generated `fn main` snippet plus the ground truth the test asserting
/// against it needs: which rule-relevant feature was generated and whether
/// the *safe* or *vulnerable* shape was chosen.
#[derive(Debug, Clone)]
pub struct PublicParamSnippet {
    pub source: String,
    pub param_name: String,
    /// `true` if the generated snippet asserts `param_name` (the taxonomy's
    /// documented safe pattern); `false` if it is left completely unused
    /// (the taxonomy's documented vulnerable pattern).
    pub is_safe: bool,
}

/// Generates a `fn main` snippet with exactly one `pub` parameter that is
/// either:
/// - asserted directly (`assert(<param> == <other>)`) — the taxonomy's
///   documented NOIR-PUBLIC-001 safe pattern, or
/// - left completely unused in the body — the taxonomy's documented
///   NOIR-PUBLIC-001 vulnerable pattern.
///
/// Per `docs/rule-taxonomy.md` NOIR-PUBLIC-001's safe-pattern fixture
/// requirement ("not `assert(claimed_total == claimed_total)`"), the safe
/// branch asserts the public parameter against a *different* identifier
/// (`secret`), never against itself.
pub fn public_param_snippet() -> impl Strategy<Value = PublicParamSnippet> {
    (plain_identifier(), any::<bool>()).prop_map(|(param_name, is_safe)| {
        let source = if is_safe {
            format!(
                "fn main(secret: Field, pub {param_name}: Field) {{\n    assert({param_name} == secret);\n}}\n"
            )
        } else {
            format!(
                "fn main(secret: Field, pub {param_name}: Field) {{\n    let unused = secret * 2;\n}}\n"
            )
        };
        PublicParamSnippet {
            source,
            param_name,
            is_safe,
        }
    })
}

/// One generated `fn main` snippet for NOIR-CONSTRAINT-001's directional
/// property: a boolean `let` binding that is either asserted (safe) or left
/// dangling (vulnerable).
#[derive(Debug, Clone)]
pub struct BooleanBindingSnippet {
    pub source: String,
    pub is_safe: bool,
}

/// Generates a `fn main` snippet with one `let <ident> = a == b;` boolean
/// binding that is either passed to `assert(<ident>)` (safe pattern) or
/// never referenced again (vulnerable pattern), per
/// `docs/rule-taxonomy.md` NOIR-CONSTRAINT-001's vulnerable/safe patterns.
pub fn boolean_binding_snippet() -> impl Strategy<Value = BooleanBindingSnippet> {
    (plain_identifier(), any::<bool>()).prop_map(|(ident, is_safe)| {
        let source = if is_safe {
            format!(
                "fn main(a: Field, b: Field) {{\n    let {ident} = a == b;\n    assert({ident});\n}}\n"
            )
        } else {
            format!("fn main(a: Field, b: Field) {{\n    let {ident} = a == b;\n}}\n")
        };
        BooleanBindingSnippet { source, is_safe }
    })
}

/// One generated standalone helper function for ZK-HASH-001's directional
/// property: a two-argument hash call with or without a leading domain-tag
/// constant identifier, per `docs/rule-taxonomy.md` ZK-HASH-001's
/// vulnerable/safe patterns.
///
/// Two independent calls (`leaf_commitment`/`nullifier_hash`, both sharing
/// the same arity) are generated together in the *vulnerable* branch so the
/// taxonomy's "corroborating second commitment-shape match" condition for
/// `medium` confidence is met deterministically — see
/// `tests/property_directional.rs` for the exact assertion this backs.
#[derive(Debug, Clone)]
pub struct HashDomainSnippet {
    pub source: String,
    pub is_safe: bool,
}

/// Generates a small Noir source with two hash-commitment-shaped helper
/// functions, either both lacking a domain tag (vulnerable) or both
/// prefixing their inputs with a distinct named domain constant (safe).
pub fn hash_domain_snippet() -> impl Strategy<Value = HashDomainSnippet> {
    any::<bool>().prop_map(|is_safe| {
        let source = if is_safe {
            "global LEAF_DOMAIN: Field = 0x4c454146;\n\
             global NULL_DOMAIN: Field = 0x4e554c4c;\n\
             fn leaf_commitment(a: Field, b: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_3([LEAF_DOMAIN, a, b])\n\
             }\n\
             fn nullifier_hash(c: Field, d: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_3([NULL_DOMAIN, c, d])\n\
             }\n"
            .to_string()
        } else {
            "fn leaf_commitment(a: Field, b: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_2([a, b])\n\
             }\n\
             fn nullifier_hash(c: Field, d: Field) -> Field {\n\
             \x20   poseidon::bn254::hash_2([c, d])\n\
             }\n"
            .to_string()
        };
        HashDomainSnippet { source, is_safe }
    })
}
