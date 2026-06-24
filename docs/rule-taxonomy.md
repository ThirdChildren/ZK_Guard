# zk-guard rule taxonomy

Status: this document defines the seven MVP rules from CLAUDE.md's "MVP
rule families" section. It is a specification for Step 4/7
(`noir-static-analyzer`) and Step 5 (`fixtures-test-engineer`) to implement
against. **No rule logic, parser, or fixture exists yet** — this document
only fixes intent so those steps don't have to re-derive it.

## Scope

- Target language: Noir (`.nr` source files, `Nargo.toml` projects). Circom
  and zkVM guest code are out of scope (CLAUDE.md: future extensions).
- Detection mechanism: deterministic, local, text/AST-shape heuristics over
  source files. No network calls, no execution of target-repository code,
  no formal verification, no SMT solving. If a rule's confidence ever
  depends on running the Noir compiler or `nargo test`, that dependency is
  stated explicitly in the rule's detection strategy.
- This document does not implement parsing depth. Where a detection
  strategy says "look for X," the concrete parser/text-matching technique
  (regex pass vs. lightweight AST walk) is an implementation decision left
  to `zkguard-noir` / `zkguard-rules`, not fixed here.

## Disclaimer

**These are heuristic, best-effort static detections, not a formal
verifier.** A finding describes a *suspicious pattern in source code*. It
is not proof that a circuit is exploitable, under-constrained in the formal
sense, or that an attack is realistic against any specific deployment.
Severity and confidence communicate the scanner's own uncertainty; they are
not a substitute for a manual audit. See CLAUDE.md "Security boundaries":
the tool must never treat findings as proof of exploitability or claim
cryptographic soundness.

## Finding field mapping

Every rule below must produce `Finding` values (struct defined in Step 3,
CLAUDE.md "Reporting schema") using this mapping, so rule authors don't
improvise field semantics:

| Finding field    | Source in this taxonomy                                                                 |
|-------------------|-------------------------------------------------------------------------------------------|
| `rule_id`         | The rule's stable ID (e.g. `NOIR-PUBLIC-001`). Never reused across rules.                 |
| `title`           | The rule's "Title" line below, used verbatim or near-verbatim.                            |
| `severity`        | The rule's "Default severity" — fixed per rule, not computed per finding in the MVP.      |
| `confidence`      | The rule's "Default confidence," downgraded per the rule's "False-positive notes" when a known misfire pattern is matched. |
| `file`            | Path to the `.nr` file containing the matched pattern.                                    |
| `line` / `column` | Location of the matched expression/statement (start of match is sufficient for MVP).      |
| `evidence`        | The literal matched source snippet (or closely paraphrased), not a paraphrase of the rule. |
| `why_it_matters`  | The rule's "Why it matters" section, optionally trimmed to one sentence for brevity.       |
| `remediation`     | The rule's "Remediation" section.                                                          |

## Severity scale (fixed set, per CLAUDE.md)

`critical`, `high`, `medium`, `low`, `info`. A rule is `critical` only when
the matched pattern, if real, leads to a direct, realistic compromise (e.g.
an unconstrained public input that controls fund flow) with no further
conditions required. Patterns that *might* be exploitable depending on
surrounding code that the scanner cannot see are capped at `high` or below.

## Confidence scale (fixed set, per CLAUDE.md)

`high`, `medium`, `low`. Confidence is about the *detection*, not the
*impact*. Use:

- `high` — the pattern is matched and the scanner can also positively
  confirm the absence of a known mitigating pattern (e.g. no `assert` or
  `constrain` anywhere referencing the same identifier in the same
  function).
- `medium` — the pattern is matched but the scanner's visibility is
  incomplete (e.g. cross-file/cross-function flow, macro/trait
  indirection, or the mitigating pattern might exist under a name/shape the
  heuristic doesn't recognize).
- `low` — the pattern is matched on weak/structural grounds only (e.g. a
  naming convention like `nullifier` or `nonce`) with no semantic check at
  all.

No rule below defaults to `confidence: high` paired with `severity:
critical` unless the detection is both structurally unambiguous and the
exploit path requires no additional assumptions. This is a deliberate
design constraint, not an oversight — see "Why not higher" notes inline
where relevant.

---

## NOIR-PUBLIC-001 — Public input declared but unused in a constraint-relevant expression

**Vulnerability class:** under-constrained circuit / public input not bound to constraints.

**Default severity:** `high`
**Default confidence:** `medium`

**Detection strategy:**
1. Parse the function signature(s) of `fn main(...)` (and any other entry
   point Noir treats as circuit boundary) and collect parameters declared
   `pub` (Noir's public-input marker).
2. For each public parameter identifier, scan the function body (text/AST
   walk, not full dataflow) for any occurrence of that identifier inside:
   - an `assert(...)` / `assert_eq(...)` / `constrain ...` expression, or
   - an expression that is itself later passed into one of the above
     (one level of indirection: `let x = pub_input + 1; assert(x == y);`
     counts as "used").
3. If the identifier appears **zero times** outside the function signature,
   or appears only in non-constraining contexts (e.g. passed to
   `println`/`dep::std::println`, used only to compute a value that is
   itself never asserted), emit a finding.
4. If the identifier is passed as an argument to another function defined
   in the same crate, do not assume safety — recurse one call level deep if
   feasible; otherwise downgrade confidence to `medium` (cross-function
   reasoning is incomplete) rather than suppress the finding.

**False-positive notes:**
- A public input legitimately used only for a `println`/debug statement in
  a test harness function will look unused; restrict the rule to `fn
  main` and functions Noir attributes as circuit entry points to avoid
  flagging helper/test code. Mark `low` confidence if the rule cannot
  reliably distinguish entry points from helpers in a given project layout.
- A public input consumed only inside a called function from an external
  dependency (not in-tree) cannot be followed; default to `medium`
  confidence in that case and say so in `evidence`.
- Pattern macros or trait-based constraint helpers (e.g. a custom
  `must_equal()` wrapper around `assert`) will cause false positives until
  the rule's keyword list is extended; document the keyword list in the
  implementation and treat additions as a rule-versioning change.

**Vulnerable pattern:**
```text
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    // claimed_total is never compared against `computed` or anything else
}
```

**Safe pattern:**
```text
fn main(secret: Field, pub claimed_total: Field) {
    let computed = secret * 2;
    assert(computed == claimed_total);
}
```

**Why it matters:** A public input that never reaches an `assert`/
`constrain` is not actually bound by the proof — a malicious prover can set
it to any value, defeating the purpose of making it public in the first
place. This is the canonical "under-constrained circuit" bug class in ZK
audits.

**Remediation:** Bind every public input to at least one constraint that a
malicious prover cannot satisfy arbitrarily. If a public input is
intentionally informational only (rare), document that decision in code
comments next to the parameter and accept the finding as a documented
exception, rather than removing detection.

**Fixture requirements:**
- *Vulnerable fixture*: a `Nargo.toml` + `src/main.nr` where `fn main` has
  at least one `pub` parameter that is never referenced inside any
  `assert`/`constrain` expression, directly or via a one-hop intermediate
  `let`.
- *Safe fixture*: same shape, but the public parameter is the direct
  operand of an `assert_eq`/`assert` that the prover cannot trivially
  satisfy (i.e. not `assert(claimed_total == claimed_total)`).
- Both fixtures must compile under `nargo check` if CI tooling for Noir is
  available (tracked as a concrete follow-up for `fixtures-test-engineer`
  in Step 5, not assumed here).
- Suggested fixture file names: `fixtures/noir/vulnerable/noir-public-001/`,
  `fixtures/noir/safe/noir-public-001/`.

---

## NOIR-CONSTRAINT-001 — Computed boolean/equality/range check not asserted

**Vulnerability class:** under-constrained circuit / computed-but-not-enforced check.

**Default severity:** `high`
**Default confidence:** `medium`

**Detection strategy:**
1. Scan for `let <ident> = <expr>;` bindings where `<expr>` is a boolean-
   producing comparison (`==`, `!=`, `<`, `<=`, `>`, `>=`) or an explicit
   call to a known boolean-returning helper (e.g. `is_zero`, `lt`, `eq`)
   from Noir's standard library idioms.
2. Track whether `<ident>` is subsequently passed into `assert(<ident>)`,
   `assert(<ident> == true)`, `constrain <ident>`, or used as the condition
   of an `if` that itself leads to an `assert`/return-with-error path,
   within the same function body.
3. If `<ident>` is computed and then **only** used in a non-constraining
   way (stored, returned without assertion, passed to `println`, or simply
   never read again), emit a finding at the `let` binding's location.
4. Treat direct inline comparisons passed straight into `assert(...)`
   (no intermediate `let`) as the safe pattern — they never reach this
   rule because there is no unused intermediate binding to flag.

**False-positive notes:**
- A boolean intentionally computed for branching logic that leads to an
  `assert` inside *one* of the `if`/`else` arms (rather than
  unconditionally) is a legitimate safe pattern but may be missed by a
  shallow text scan; if the rule cannot trace into both branches, default
  to `medium` confidence and note the limitation in `evidence`.
- Helper functions that wrap `assert` under a different name will be
  invisible to a fixed keyword list; this is the most likely source of
  false positives in real Noir code that uses custom assertion helpers.
  Confidence should drop to `low` if the project defines any function
  whose name contains `assert`, `require`, or `constrain` that isn't in
  the rule's built-in keyword set (signals an unrecognized wrapper may
  exist).

**Vulnerable pattern:**
```text
fn main(a: Field, b: Field) {
    let is_equal = a == b;
    // is_equal is computed but never asserted — proof accepts any a, b
}
```

**Safe pattern:**
```text
fn main(a: Field, b: Field) {
    let is_equal = a == b;
    assert(is_equal);
}
```

**Why it matters:** Computing a check without asserting it produces a
witness value that looks meaningful but exerts zero constraint pressure on
the proof — the circuit accepts inputs the developer intended to reject.
This is a frequent root cause of "the circuit compiles and tests pass but
proves false statements" bugs.

**Remediation:** Every security-relevant boolean computed in a circuit must
flow into an `assert`/`constrain` (or a `return Err`-equivalent path that
itself is enforced by the verifier integration). If the boolean is purely
informational (e.g. for an off-circuit log), rename it clearly and isolate
it from security-relevant variable names to reduce audit ambiguity.

**Fixture requirements:**
- *Vulnerable fixture*: a `let` binding from a comparison expression that
  is never passed to `assert`/`constrain` anywhere in the function.
- *Safe fixture*: the same comparison, with the resulting identifier passed
  to `assert(...)` on the next line, and a second safe variant showing the
  inline form (`assert(a == b);` with no intermediate `let`) to confirm the
  rule does not falsely fire on the no-intermediate-binding case.
- Suggested fixture paths: `fixtures/noir/vulnerable/noir-constraint-001/`,
  `fixtures/noir/safe/noir-constraint-001/`.

---

## NOIR-RANGE-001 — Numeric value used in a security-sensitive context without an obvious range check

**Vulnerability class:** missing range check / unsafe cast or truncation risk.

**Default severity:** `medium`
**Default confidence:** `low`

**Detection strategy:**
1. Identify "security-sensitive contexts" by a fixed, documented list of
   syntactic shapes, not general dataflow:
   - array/slice indexing (`arr[idx]`) where `idx` derives from a function
     parameter (public or private) rather than a compile-time constant or
     a loop counter bound by `for _ in 0..N`.
   - arithmetic immediately followed by a cast to a smaller integer type
     (e.g. `as u8`, `as u32`) on a value that originated from a `Field` or
     wider integer parameter.
   - subtraction on unsigned integer types (`u8`/.../`u64`) where operands
     come from parameters, given Noir/Field-underflow wraparound risk.
2. For each match, search the enclosing function for any call to a known
   range-check idiom referencing the same identifier: explicit bit-length
   assertions (e.g. `assert(x as u64 ... )` patterns establishing bounds),
   calls into recognized range-check helpers (e.g. names containing
   `range_check`, `assert_max_bits`, `lt`/`lte` against a constant bound),
   or a standard library range-constraint call if one is referenced by
   name in the source.
3. If no such idiom is found referencing the identifier anywhere in the
   function, emit a finding at the sensitive-context site.

**False-positive notes:**
- This rule is the most heuristic of the MVP set: integer types in Noir
  already carry a bit-width, so "missing range check" often means "value
  is within its declared type's range but that range is wider than the
  security property actually requires" — a distinction a syntactic scan
  cannot make. Default confidence is `low` for this reason; do not raise
  the default without adding real type-width-aware reasoning.
- Loop counters bound by a `for _ in 0..N` are not findings; the rule must
  special-case this idiom explicitly to avoid noisy output on completely
  ordinary code.
- A range check performed in a *caller* function before passing the value
  in will not be visible to a single-function scan; mark `low` confidence
  explicitly rather than silently suppressing, since cross-function
  visibility is a known, documented gap (not a guess).

**Vulnerable pattern:**
```text
fn main(index: Field, items: [Field; 8]) {
    let i = index as u32;
    let v = items[i]; // no assert bounding `index`/`i` before indexing
}
```

**Safe pattern:**
```text
fn main(index: Field, items: [Field; 8]) {
    assert(index as u32 < 8);
    let i = index as u32;
    let v = items[i];
}
```

**Why it matters:** Using an unbounded or wraparound-prone value as an
index, bound, or arithmetic operand without an explicit range constraint
can let a malicious prover supply out-of-range or wrapped values, producing
witnesses that are valid in the field but not in the intended integer
domain — a classic source of soundness bugs distinct from normal type
checking.

**Remediation:** Add an explicit `assert` bounding the value's range before
it is used in indexing, truncating casts, or unsigned subtraction. Prefer
well-known, named range-check helpers over ad hoc inequality chains so
later static analysis (and human reviewers) can recognize the pattern.

**Fixture requirements:**
- *Vulnerable fixture*: indexing into a fixed-size array using a value
  derived from a parameter with no preceding `assert` bounding it, plus a
  second variant showing a narrowing cast with no bound check.
- *Safe fixture*: the same indexing/cast preceded by an explicit `assert`
  establishing the bound, and a fixture demonstrating the `for _ in 0..N`
  loop-counter idiom to confirm it is not flagged.
- Suggested fixture paths: `fixtures/noir/vulnerable/noir-range-001/`,
  `fixtures/noir/safe/noir-range-001/`.

---

## ZK-HASH-001 — Hash commitment built from ambiguous concatenation or missing domain tag

**Vulnerability class:** ambiguous hash commitment / missing domain separator.

**Default severity:** `medium`
**Default confidence:** `medium`

**Detection strategy:**
1. Scan for calls to recognized hash functions used for commitments (e.g.
   `poseidon::bn254::hash_*`, `std::hash::pedersen_hash`, `std::hash::sha256`,
   or other calls whose callee path contains `hash`) where the argument is
   an array/slice literal built inline from multiple identifiers, e.g.
   `hash([a, b, c])`.
2. Flag the call site if **either**:
   - none of the arguments is a fixed, named constant clearly intended as a
     domain/context tag (heuristic: an identifier or literal bound to a
     name containing `domain`, `tag`, `context`, `version`, or a
     module-level `const` passed as the first or last array element), **or**
   - the same set of input identifiers, in the same hash call shape, is
     used to build more than one distinct logical commitment in the
     project (e.g. both a "leaf commitment" and a "nullifier" call
     `hash([a, b])` with no differentiating tag) — a sign that two
     different commitments could collide if inputs coincide.
3. The second condition requires comparing call sites across the file/
   project, which is more expensive; the first condition (no apparent
   domain tag) is cheaper and should run unconditionally as the rule's
   primary trigger.

**False-positive notes:**
- Many legitimate hashes have a fixed arity and ordering that already acts
  as an implicit domain separator at the protocol level (e.g. a Merkle
  hash that is always exactly `hash([left, right])` and never reused for
  another purpose). The rule cannot verify protocol-level uniqueness, so
  default confidence is `medium`, and should drop to `low` when only the
  "no apparent constant tag" heuristic fired without a corroborating
  second commitment-shape match.
- Projects that pass a domain tag via a wrapper function (e.g.
  `domain_hash(TAG, [a, b])`) rather than inlining the constant in the
  array literal will not be recognized unless the wrapper name is added to
  the rule's keyword list; document the keyword list alongside the rule.

**Vulnerable pattern:**
```text
fn leaf_commitment(a: Field, b: Field) -> Field {
    poseidon::bn254::hash_2([a, b]) // no domain tag distinguishing this
                                     // from any other 2-input hash use
}
```

**Safe pattern:**
```text
global LEAF_DOMAIN: Field = 0x4c454146; // "LEAF" tag, project-defined

fn leaf_commitment(a: Field, b: Field) -> Field {
    poseidon::bn254::hash_3([LEAF_DOMAIN, a, b])
}
```

**Why it matters:** Hashing the same shape of inputs for two different
semantic purposes (e.g. a leaf commitment and a nullifier) without a domain
tag can let values collide across contexts, undermining the uniqueness
guarantees the commitment scheme was supposed to provide.

**Remediation:** Include a fixed, protocol-specific domain separator
(a constant tag) as one of the hash inputs for every distinct commitment
purpose, and never reuse the exact same `(tag, arity, ordering)` shape for
two different semantic commitments.

**Fixture requirements:**
- *Vulnerable fixture*: at least two functions in the same project calling
  the same hash function with the same input arity and no constant tag
  argument, representing two different logical commitments (e.g. one named
  `leaf_commitment`, one named `nullifier_hash`).
- *Safe fixture*: the same two functions, each prefixing its hash inputs
  with a distinct named domain constant.
- Suggested fixture paths: `fixtures/noir/vulnerable/zk-hash-001/`,
  `fixtures/noir/safe/zk-hash-001/`.

---

## ZK-NULLIFIER-001 — Nullifier-like value generated without a visible domain separator

**Vulnerability class:** replay/nullifier mistake / missing domain separator.

**Default severity:** `high`
**Default confidence:** `low`

**Detection strategy:**
1. Identify "nullifier-like" bindings by naming convention only: a
   `let`/return value whose identifier, or the function it is returned
   from, matches (case-insensitively) `nullifier`, `null_hash`, or
   `spent_tag`. This is intentionally name-based — there is no semantic
   way to recognize "this value is meant to prevent replay" from syntax
   alone.
2. For each match, inspect the expression computing the value. If it is a
   hash call (see `ZK-HASH-001` detection), check whether any input to
   that hash is plausibly a domain/context tag (same heuristic as
   `ZK-HASH-001`: named constant containing `domain`, `tag`, `context`,
   `nullifier`, or a per-application/per-action identifier such as an
   action ID, contract address, or circuit identifier).
3. If the nullifier-like value is **not** the output of a hash at all
   (e.g. it is just a raw private input reused directly as "the
   nullifier"), emit a finding unconditionally — reusing an unhashed
   input as a nullifier is a stronger structural signal than a missing
   tag on an otherwise-hashed value.
4. If it is a hash with no apparent domain/context input, emit a finding
   with the lower of the two confidences from steps 2/3.

**False-positive notes:**
- Naming-convention detection means any variable named `nullifier` that
  has nothing to do with replay protection (rare, but possible in sample/
  test code) will be flagged; this is acceptable at `low` confidence per
  CLAUDE.md's early-false-positive tolerance, but must never be emitted
  above `medium` confidence given the name-only basis.
- A project-wide domain tag applied once at a higher level (e.g. all
  circuit inputs are already namespaced by a contract address baked into
  every hash call elsewhere) will not be visible to a single-function
  scan; document this as a known gap rather than attempting cross-file
  inference in the MVP.

**Vulnerable pattern:**
```text
fn compute_nullifier(secret: Field, leaf_index: Field) -> Field {
    poseidon::bn254::hash_2([secret, leaf_index])
    // no action/circuit/app-specific domain tag — same secret+index pair
    // could double as a valid nullifier in a different circuit/context
}
```

**Safe pattern:**
```text
global NULLIFIER_DOMAIN: Field = 0x4e554c4c; // "NULL" tag

fn compute_nullifier(secret: Field, leaf_index: Field) -> Field {
    poseidon::bn254::hash_3([NULLIFIER_DOMAIN, secret, leaf_index])
}
```

**Why it matters:** A nullifier without a domain separator can potentially
be replayed across different circuits, actions, or deployments that share
the same underlying secret/index inputs, weakening the uniqueness property
the nullifier is meant to guarantee.

**Remediation:** Always mix a fixed, action/circuit-specific domain
constant into nullifier computation, in addition to (not instead of) the
nullifier actually being checked against a set of previously-seen values
by the verifier/contract integration (see `ZK-REPLAY-001`).

**Fixture requirements:**
- *Vulnerable fixture*: a function named/returning something matching the
  `nullifier` naming convention, computed via a hash with no domain-tag
  input, and a second vulnerable variant using a raw input directly as the
  nullifier with no hash at all.
- *Safe fixture*: the same function with a named domain constant included
  as a hash input.
- Suggested fixture paths: `fixtures/noir/vulnerable/zk-nullifier-001/`,
  `fixtures/noir/safe/zk-nullifier-001/`.

---

## ZK-REPLAY-001 — Proof/action pattern appears to lack nonce, nullifier, or uniqueness binding

**Vulnerability class:** replay-prone circuit/integration pattern.

**Default severity:** `medium`
**Default confidence:** `low`

**Detection strategy:**
1. This rule operates at the **project level**, not a single expression
   site: scan all `.nr` files in the Noir project for any identifier,
   function name, or public input matching nullifier/nonce/uniqueness
   naming conventions (`nullifier`, `nonce`, `nonce_hash`, `used_`,
   `spent_`, case-insensitive).
2. If the project's public-facing circuit(s) (`fn main` with at least one
   `pub` parameter, or any function the project's `Nargo.toml`/README
   exposes as the externally callable circuit) contain **zero** such
   identifiers anywhere in the project, and the circuit's `pub` outputs
   include something that looks state-changing or value-transferring by
   naming convention (`amount`, `transfer`, `withdraw`, `claim`, `mint`),
   emit a single project-level finding rather than one per file.
3. This rule explicitly does not attempt to verify that a nullifier, once
   computed, is actually checked against a set on the verifier/contract
   side — that integration detail is outside Noir source and is instead
   captured qualitatively in `why_it_matters`/`remediation`, not asserted
   as confirmed by the scanner.

**False-positive notes:**
- Circuits that are not the replay-sensitive kind (e.g. a pure computation
  circuit with no value transfer, like a Sudoku-solution checker) will
  trigger naming heuristics around "transfer/withdraw/claim" only when
  those words appear, but absence of nullifier-like names alone on a
  non-value-transfer circuit should not be flagged — restrict the
  state-changing-naming check to be a **required co-condition** for this
  rule, not optional, specifically to avoid noisy findings on circuits
  with no replay-sensitive semantics.
- A project that implements replay protection entirely outside Noir (e.g.
  in the smart-contract verifier wrapper, not in-circuit) is legitimate and
  will still be flagged here since the scanner only sees Noir source;
  default confidence is `low` for exactly this reason, and remediation
  text must say "or document where replay protection is enforced
  on-chain," not assert that the circuit itself is broken.

**Vulnerable pattern:**
```text
// project-wide: no identifier anywhere matches nullifier/nonce/used_/spent_
fn main(secret: Field, pub amount: Field, pub recipient: Field) {
    // proves "I know a secret authorizing transfer of `amount`"
    // but nothing in the project binds this proof to a single use
}
```

**Safe pattern:**
```text
fn main(secret: Field, pub amount: Field, pub recipient: Field, pub nullifier: Field) {
    let expected_nullifier = poseidon::bn254::hash_2([NULLIFIER_DOMAIN, secret]);
    assert(nullifier == expected_nullifier);
    // verifier/contract integration is expected to track spent nullifiers
}
```

**Why it matters:** A circuit that authorizes a state-changing action with
no nonce/nullifier-shaped value anywhere in the project gives the
integrator no obvious in-circuit hook to prevent the same proof from being
submitted more than once; whether replay is actually possible depends on
verifier-side integration this scanner cannot see, which is exactly why
this finding stays at `medium` severity and `low` confidence by default.

**Remediation:** Add a nullifier or nonce that is asserted inside the
circuit and is intended to be checked for prior use by the verifier/
contract integration. If replay protection is deliberately handled outside
the circuit, document that decision (CLAUDE.md principle 10: no vague
TODOs) in the project's README or a code comment near `fn main` so the
finding can be triaged as a documented exception.

**Fixture requirements:**
- *Vulnerable fixture*: a project whose `fn main` has `pub` outputs named
  like a value transfer (`amount`, `recipient`) and contains no
  nullifier/nonce-shaped identifier anywhere in `src/`.
- *Safe fixture*: the same project shape with a `pub nullifier` parameter
  that is asserted against a computed hash inside `fn main`.
- Suggested fixture paths: `fixtures/noir/vulnerable/zk-replay-001/`,
  `fixtures/noir/safe/zk-replay-001/`.

---

## ZK-TEST-001 — Circuit has no negative tests or no failing-witness tests

**Vulnerability class:** weak test harness / missing negative tests.

**Default severity:** `low`
**Default confidence:** `high`

**Detection strategy:**
1. Locate Noir test functions: items annotated `#[test]` anywhere in the
   project's `.nr` files (Noir's test attribute).
2. For each test function, inspect its body for a "should fail" signal:
   - the `#[test(should_fail)]` / `#[test(should_fail_with = "...")]`
     attribute form, or
   - a body that calls the circuit's entry point with inputs and expects a
     `Result`/error path to be returned and matched against an error case
     (project-specific; only recognized if it follows Noir's standard
     `should_fail` attribute, to keep this rule's detection unambiguous).
3. If a project has **zero** `#[test]` functions at all, emit a finding
   (no test harness at all is a stronger, unambiguous signal).
4. If a project has one or more `#[test]` functions but **none** use
   `should_fail`/`should_fail_with`, emit a finding (tests exist but only
   exercise the happy path).
5. This is a pure presence/absence check over attribute syntax — no
   semantic judgment about whether the negative tests are *good* negative
   tests is attempted in the MVP.

**False-positive notes:**
- This is the most reliable rule in the MVP set because `#[test]` and
  `should_fail` are fixed Noir syntax, not a naming convention — default
  confidence is `high`.
- A project that tests failing witnesses through an external harness
  outside Noir's `#[test]` mechanism (e.g. a separate Rust integration
  test driving `nargo prove` and asserting failure) will be flagged as a
  false positive by this rule; this is a known, documented limitation, not
  a bug — the rule only inspects in-tree `.nr` test attributes.

**Vulnerable pattern:**
```text
#[test]
fn test_valid_witness() {
    let result = main(5, 10);
    assert(result == 15);
}
// no #[test(should_fail)] anywhere in the project
```

**Safe pattern:**
```text
#[test]
fn test_valid_witness() {
    let result = main(5, 10);
    assert(result == 15);
}

#[test(should_fail)]
fn test_invalid_witness_rejected() {
    let _ = main(5, 999); // should fail the circuit's assertions
}
```

**Why it matters:** A circuit with only happy-path tests can silently
accept malformed or malicious witnesses without anyone noticing, because
nothing in the test suite ever exercises the rejection path the circuit is
supposed to enforce.

**Remediation:** Add at least one `#[test(should_fail)]` (or
`should_fail_with`) test per circuit that exercises a witness the circuit
is expected to reject, alongside the existing happy-path tests.

**Fixture requirements:**
- *Vulnerable fixture A*: a project with zero `#[test]` functions.
- *Vulnerable fixture B*: a project with one or more `#[test]` functions,
  none using `should_fail`/`should_fail_with`.
- *Safe fixture*: a project with at least one happy-path `#[test]` and at
  least one `#[test(should_fail)]`.
- Suggested fixture paths: `fixtures/noir/vulnerable/zk-test-001-no-tests/`,
  `fixtures/noir/vulnerable/zk-test-001-no-negative/`,
  `fixtures/noir/safe/zk-test-001/`.

---

## Implementation priority

Order follows CLAUDE.md's Step 4/7 sequencing and the "static scanner MVP"
exit criteria in `docs/roadmap.md` (at least 5 of 7 rules before 0.1.0):

1. `NOIR-PUBLIC-001` — single-function scope, no cross-call reasoning,
   already scheduled first in Step 4.
2. `NOIR-CONSTRAINT-001` — similar mechanics to `NOIR-PUBLIC-001`
   (binding-then-usage tracking within one function).
3. `ZK-TEST-001` — highest-confidence, lowest-effort rule (pure attribute
   presence/absence); good early win for credibility.
4. `ZK-HASH-001` — needed as a building block before `ZK-NULLIFIER-001`,
   since nullifier detection reuses the hash-call heuristic.
5. `ZK-NULLIFIER-001` — depends on `ZK-HASH-001`'s detection logic.
6. `NOIR-RANGE-001` — more heuristic surface area (casts, indexing,
   subtraction); expect more fixture iteration.
7. `ZK-REPLAY-001` — project-level (not single-function) scope; most
   complex to implement cleanly, expect to land last.

## Expected false positives across the rule set (summary)

- Custom assertion/range-check wrapper functions not matching built-in
  keyword lists (`NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`).
- Cross-function and cross-file dataflow that the single-pass heuristics
  cannot follow (`NOIR-PUBLIC-001`, `NOIR-RANGE-001`, `ZK-HASH-001`).
- Naming-convention-only detections matching unrelated code
  (`ZK-NULLIFIER-001`, `ZK-REPLAY-001`).
- Replay/nullifier protection implemented outside Noir source entirely
  (`ZK-REPLAY-001`, partially `ZK-NULLIFIER-001`).
- External (non-`#[test]`) negative-test harnesses not recognized
  (`ZK-TEST-001`).

Each of these is captured in the rule's own "False-positive notes" above;
this summary exists so `security-reviewer` (Step 8) has one place to check
that no false-positive class was silently dropped between rule sections.

## Required fixtures (concrete deferred work for Step 5)

Per CLAUDE.md principle 9 ("every new rule must ship with at least one
vulnerable fixture and one safe fixture"), the fixture set required to
exercise this taxonomy is:

| Rule | Vulnerable fixture(s) | Safe fixture(s) |
|---|---|---|
| NOIR-PUBLIC-001 | 1 | 1 |
| NOIR-CONSTRAINT-001 | 1 | 1 (plus inline-no-binding variant) |
| NOIR-RANGE-001 | 2 (index, cast) | 2 (matching safe variants) + loop-counter non-finding case |
| ZK-HASH-001 | 1 (two colliding commitment shapes) | 1 |
| ZK-NULLIFIER-001 | 2 (unhashed reuse, hash without tag) | 1 |
| ZK-REPLAY-001 | 1 (project-level) | 1 (project-level) |
| ZK-TEST-001 | 2 (no tests, happy-path-only tests) | 1 |

This table is the acceptance checklist `fixtures-test-engineer` should use
in Step 5; it does not replace per-rule "Fixture requirements" sections
above, which specify file shape, not just count.

## Suggested test names

Concrete unit/integration test names for `zkguard-rules`, so Step 4/7 does
not have to invent naming conventions mid-implementation:

- `noir_public_001_flags_unused_pub_input`
- `noir_public_001_allows_constrained_pub_input`
- `noir_public_001_no_finding_on_helper_function_params` (false-positive guard)
- `noir_constraint_001_flags_unasserted_boolean_binding`
- `noir_constraint_001_allows_asserted_boolean_binding`
- `noir_constraint_001_allows_inline_assert_no_binding` (false-positive guard)
- `noir_range_001_flags_unbounded_index`
- `noir_range_001_flags_narrowing_cast_without_bound`
- `noir_range_001_allows_bounded_index`
- `noir_range_001_no_finding_on_for_loop_counter` (false-positive guard)
- `zk_hash_001_flags_untagged_colliding_commitments`
- `zk_hash_001_allows_domain_tagged_hash`
- `zk_nullifier_001_flags_unhashed_raw_nullifier`
- `zk_nullifier_001_flags_untagged_hashed_nullifier`
- `zk_nullifier_001_allows_domain_tagged_nullifier`
- `zk_replay_001_flags_value_transfer_with_no_uniqueness_binding`
- `zk_replay_001_allows_value_transfer_with_nullifier`
- `zk_replay_001_no_finding_on_non_value_transfer_circuit` (false-positive guard)
- `zk_test_001_flags_project_with_zero_tests`
- `zk_test_001_flags_project_with_only_happy_path_tests`
- `zk_test_001_allows_project_with_should_fail_test`

## Out of scope for this document (deferred, not vague)

- The `Finding` struct's exact Rust representation: deferred to Step 3
  (`zk-project-architect`), per `docs/roadmap.md` Phase 3. This document
  only fixes the *mapping* of taxonomy fields onto that struct.
- Actual fixture files and `Nargo.toml` contents: deferred to Step 5
  (`fixtures-test-engineer`), per `docs/roadmap.md` Phase 5. "Fixture
  requirements" above specify acceptance criteria, not file contents.
- Parser/AST implementation choices (regex vs. lightweight AST walker):
  deferred to Step 4/7 (`noir-static-analyzer`). This document fixes
  detection *intent*, not implementation technique.
- SARIF severity/confidence mapping: deferred to whichever step adds SARIF
  output (explicitly out of scope for 0.1.0 per `docs/roadmap.md`).
