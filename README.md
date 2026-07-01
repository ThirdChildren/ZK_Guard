# zk-guard

`zk-guard` is a best-effort static security scanner for zero-knowledge
application source code. The first production target is
[Noir](https://noir-lang.org/). Circom and zkVM guest-code support are
future extensions (see `docs/roadmap.md`).

**This is developer tooling, not a formal verifier.** A finding describes a
*suspicious pattern in source code*. It is not proof that a circuit is
exploitable, formally under-constrained, or that an attack is realistic
against any specific deployment. See `docs/rule-taxonomy.md` for each
rule's detection strategy, severity/confidence rationale, and known
false-positive classes.

## Status

Pre-1.0 (0.2.0 line). **Six rules are implemented end-to-end** and
registered in `crates/zkguard-rules/src/registry.rs`:

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `NOIR-PUBLIC-001` | high | medium | A `pub` parameter of `fn main` that never reaches an `assert`/`assert_eq`/`constrain` expression, directly or via one intermediate `let` binding. |
| `NOIR-CONSTRAINT-001` | high | medium | A computed boolean/equality comparison bound to a `let` that is never passed to `assert`/`assert_eq`/`constrain`. |
| `NOIR-RANGE-001` | medium | low | Array/slice indexing, narrowing integer casts, or unsigned subtraction using a non-constant value with no apparent range-check idiom in the same function. |
| `ZK-HASH-001` | medium | medium | A hash/commitment call built from an inline array literal with no apparent domain/context tag argument. |
| `ZK-NULLIFIER-001` | high | low | A nullifier-like binding (by naming convention) that is either unhashed or hashed with no apparent domain tag. |
| `ZK-TEST-001` | low | medium | **Project-level:** a project that declares `fn main` but has no negative test: no `#[test(should_fail)]`/`should_fail_with` and no `#[test]` named fail/invalid/reject/negative/should_fail. |

See `docs/rule-taxonomy.md` for each rule's full detection strategy,
false-positive notes, and fixture requirements.

**One MVP rule from the rule taxonomy is deferred, not implemented:**
`ZK-REPLAY-001` (project-level replay/uniqueness-binding check). It is
documented in `docs/rule-taxonomy.md` and tracked in `docs/roadmap.md`;
`zk-guard rules list` will not show it until it lands.

The CLI, exit codes, and JSON/Markdown/SARIF report formats described below
are stable for the current rule set and are not expected to change shape as
more rules are added; only the rule registry grows.

## Installation

From the workspace root:

```bash
cargo build --release -p zkguard-cli
# binary at target/release/zk-guard
```

Or run directly without installing:

```bash
cargo run -p zkguard-cli -- <command> [args]
```

The rest of this document uses `zk-guard` as shorthand for either
`./target/release/zk-guard` or `cargo run -p zkguard-cli --`.

## Usage

### Scan a Noir project

```bash
zk-guard scan ./path/to/noir-project
```

`<path>` may be a Noir project directory (containing `Nargo.toml`/`src/`)
or a single `.nr` file. Discovery never executes anything found in the
scanned tree, never follows symlinks, and never performs network access
(see `docs/architecture.md`'s "Goals and non-goals").

Default output is plain text to stdout. This is the real output of
`zk-guard scan fixtures/noir/vulnerable/noir-public-001`:

```text
[HIGH] Public input declared but unused in a constraint-relevant expression (NOIR-PUBLIC-001)
  location:   fixtures/noir/vulnerable/noir-public-001/src/main.nr:10
  confidence: medium
  evidence:   pub claimed_total: Field
  why:        A public input that never reaches an assert/constrain is not actually bound by the proof. A malicious prover can set it to any value, defeating the purpose of making it public in the first place. This is the canonical "under-constrained circuit" bug class in ZK audits.
  fix:        Bind every public input to at least one constraint that a malicious prover cannot satisfy arbitrarily. If a public input is intentionally informational only, document that decision in code comments next to the parameter and accept the finding as a documented exception.

Summary:
  files scanned: 1
  rules run:     5
  CRITICAL:  0
  HIGH:      1
  MEDIUM:    0
  LOW:       0
  INFO:      0
  total:     1
```

`rules run` reflects the current registry size (5), not just the rule that
produced a finding; every scan runs every registered rule against every
discovered source file.

### Machine-readable output (CI)

```bash
zk-guard scan ./path/to/noir-project --format json
```

Emits the scan result as pretty-printed JSON to stdout. Field names and
lowercase `severity`/`confidence` strings follow the documented reporting
schema (see `docs/rule-taxonomy.md`), so the shape is stable for CI
parsing. This is the real
output of
`zk-guard scan fixtures/noir/vulnerable/zk-nullifier-001-unhashed --format json`:

```json
{
  "findings": [
    {
      "rule_id": "ZK-NULLIFIER-001",
      "title": "Nullifier-like value generated without a visible domain separator",
      "severity": "high",
      "confidence": "low",
      "file": "fixtures/noir/vulnerable/zk-nullifier-001-unhashed/src/main.nr",
      "line": 13,
      "column": null,
      "evidence": "nullifier = secret (this value is reused directly with no hash at all, which is a stronger structural signal of missing domain separation than an untagged hash)",
      "why_it_matters": "A nullifier without a domain separator can potentially be replayed across different circuits, actions, or deployments that share the same underlying secret/index inputs, weakening the uniqueness property the nullifier is meant to guarantee.",
      "remediation": "Always mix a fixed, action/circuit-specific domain constant into nullifier computation, in addition to (not instead of) the nullifier actually being checked against a set of previously-seen values by the verifier/contract integration."
    }
  ],
  "files_scanned": 1,
  "rules_run": [
    "NOIR-PUBLIC-001",
    "NOIR-CONSTRAINT-001",
    "NOIR-RANGE-001",
    "ZK-HASH-001",
    "ZK-NULLIFIER-001"
  ],
  "suppressed_count": 0
}
```

`suppressed_count` reports how many findings were hidden by a suppression
(see Configuration below); with `--show-suppressed`, a `suppressed` array of
those findings is also included.

### SARIF output (GitHub code scanning)

```bash
zk-guard scan ./path/to/noir-project --format sarif --output zkguard.sarif
```

Emits a [SARIF][sarif] 2.1.0 log: every registered rule becomes a
`reportingDescriptor` and every finding a `result` with a stable `ruleId`,
`level`, `message`, and `physicalLocation`/`region.startLine`. Upload it with
`github/codeql-action/upload-sarif` to surface findings in the GitHub
Security tab and as inline PR annotations. See [`docs/sarif.md`](docs/sarif.md)
for the full field mapping and a ready-to-copy GitHub Actions workflow
([`examples/github-actions/zkguard-sarif.yml`](examples/github-actions/zkguard-sarif.yml)).
SARIF is supported by `scan` only.

[sarif]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

### Markdown report (PR comments, CI artifacts)

```bash
zk-guard scan ./path/to/noir-project --format markdown --output report.md
```

Without `--output`, Markdown is printed to stdout instead. The Markdown
report is written to render cleanly in GitHub's Markdown viewer: a summary
table of finding counts by severity, followed by one section per finding
covering rule ID, title, severity, confidence, file:line, evidence, why it
matters, and remediation.

### Choosing a failure threshold

```bash
zk-guard scan ./path/to/noir-project --fail-on high
```

`--fail-on` (default: `low`, i.e. any finding fails the scan) sets the
minimum severity that causes a nonzero exit code. Findings below the
threshold are still reported in the output; they just don't flip the exit
code. Valid values: `critical`, `high`, `medium`, `low`, `info`. `--fail-on`
overrides a `fail_on` set in `zkguard.toml` (see Configuration below).

### Configuration and suppressions (`zkguard.toml`)

`zk-guard` needs no configuration, but an optional `zkguard.toml` in the
project root can disable rules, set a default `fail_on`, and suppress
specific findings (with a required reason). Config never changes what a rule
detects, only which rules run and which findings are shown.

```toml
fail_on = "high"

[rules]
"NOIR-RANGE-001" = false     # disable a rule

[[suppress]]
rule   = "NOIR-PUBLIC-001"
path   = "src/main.nr"
reason = "claimed_total is intentionally informational"
```

Findings can also be suppressed inline, on the flagged line or the line above
it:

```rust
let idx = i as u32; // zkguard:ignore NOIR-RANGE-001 reason="bounded by assert above"
```

Every suppression requires a non-empty `reason`. Suppressed findings are
counted in every report (`suppressed_count`); pass `--show-suppressed` to also
list them (with reason and source). See [`docs/configuration.md`](docs/configuration.md)
for the full reference.

### List registered rules

```bash
zk-guard rules list
zk-guard rules list --format json
zk-guard rules list --format markdown
```

This is the real output of `zk-guard rules list`:

```text
RULE_ID              SEVERITY    CONFIDENCE  TITLE
NOIR-PUBLIC-001      high        medium      Public input declared but unused in a constraint-relevant expression
                     Detects `pub` parameters of `fn main` that never reach an assert/assert_eq/constrain expression, directly or via one intermediate `let` binding.
NOIR-CONSTRAINT-001  high        medium      Computed boolean/equality/range check not asserted
                     Detects `let <ident> = <comparison>;` bindings inside `fn main` whose resulting boolean is never passed to assert/assert_eq/constrain, directly or via one intermediate `let` binding.
NOIR-RANGE-001       medium      low         Numeric value used in a security-sensitive context without an obvious range check
                     Detects array/slice indexing by a non-constant, non-loop-counter identifier, narrowing integer casts, and unsigned subtraction inside `fn main` with no apparent range-check idiom (assert with a bound, or a range_check/assert_max_bits/ lt/lte helper call) referencing the same identifier.
ZK-HASH-001          medium      medium      Hash commitment built from ambiguous concatenation or missing domain tag
                     Detects calls to hash/commitment functions (callee path containing `hash`, `sha256`, or `pedersen`) built from an inline array literal with no apparent domain/context tag argument, downgrading confidence when no corroborating same-arity call exists elsewhere in the file.
ZK-NULLIFIER-001     high        low         Nullifier-like value generated without a visible domain separator
                     Detects `let`/function bindings whose name matches a nullifier naming convention (nullifier, null_hash, spent_tag) where the computed value is either not the output of a hash at all, or is a hash call with no apparent domain/context tag argument.
ZK-TEST-001          low         medium      Circuit has an entry point but no negative test
                     Project-level: flags a Noir project that declares `fn main` but has no negative test: no `#[test(should_fail)]`/`should_fail_with` attribute and no `#[test]` whose name contains fail/invalid/reject/negative/should_fail. Never runs nargo; a purely textual check over discovered `.nr` sources.
```

### Validate the fixture tree

```bash
zk-guard fixtures validate
```

Confirms every fixture project under `fixtures/noir/{vulnerable,safe}/`
(or a directory passed via `--path`) discovers cleanly: readable `.nr`
sources, no traversal errors, at least one source file per fixture
directory. This is a fast filesystem sanity check; it does not re-run
rules against fixtures and assert expected findings (that is covered by
`cargo test --workspace`, specifically `zkguard-rules`' fixture
integration tests).

```bash
zk-guard fixtures validate --path /some/other/fixtures/root
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan (or `rules list` / `fixtures validate`) completed and found no findings at or above the `--fail-on` threshold (default: `low`). |
| `1` | Scan completed and found at least one finding at or above the `--fail-on` threshold. CI pipelines should treat this as "gate failed." |
| `2` | Invalid CLI usage or unreadable input: bad flags, a scan path that does not exist, or a path that exists but cannot be read. Nothing was scanned. |
| `3` | Internal scanner error not attributable to user input (e.g. a report-rendering failure, or an I/O error reading a file that existed moments ago). |

`zk-guard rules list` and `zk-guard fixtures validate` never return `1`:
they have no "findings" concept, only success (`0`) or usage/internal
error (`2`/`3`).

See `crates/zkguard-cli/src/exit_code.rs` for the authoritative,
code-level documentation of this scheme.

## CI example

```bash
zk-guard scan ./circuits --format json --output scan-result.json
echo "exit code: $?"   # 1 if any finding was at or above the fail-on threshold
```

A nonzero exit code from `zk-guard scan` is the intended CI gating signal;
parse `scan-result.json` for finding detail in a CI annotation step.

## Limitations

**`zk-guard` is a best-effort, heuristic static scanner. It is not a formal
verifier, not an SMT solver, and not a substitute for a manual security
audit.** A finding is "this source pattern looks suspicious," never "this
circuit is exploitable" or "this circuit is provably under-constrained."
Treat every finding as a lead to investigate, not a confirmed bug: severity
and confidence describe the scanner's own uncertainty about the detection,
not a guarantee about real-world impact. See `docs/rule-taxonomy.md`'s
"Disclaimer" and each rule's "False-positive notes" for the specific known
gaps behind this general statement.

Concretely:

- **6 of 7** MVP rules from the rule taxonomy are implemented
  (`NOIR-PUBLIC-001`, `NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`,
  `ZK-HASH-001`, `ZK-NULLIFIER-001`, `ZK-TEST-001`). `ZK-REPLAY-001` is
  specified in `docs/rule-taxonomy.md` but not yet implemented; it does
  not appear in `zk-guard rules list` and will never be flagged.
- Detection is text/shape-level heuristics, not full dataflow or a parsed
  AST. Most rules are single-function; `ZK-TEST-001` is project-level (it
  aggregates `#[test]` attributes across files). Custom assertion/range-
  check helpers, cross-function flow, naming-convention detections
  (`ZK-NULLIFIER-001`), and test coverage via an external harness outside
  Noir's `#[test]` (`ZK-TEST-001`) are documented false-positive/false-
  negative sources, not bugs.
- Noir only. Circom and zkVM guest-code support are explicitly out of
  scope for now (see `docs/roadmap.md`).
- SARIF 2.1.0 output (`--format sarif`, see [`docs/sarif.md`](docs/sarif.md))
  and `zkguard.toml` config + suppressions (see
  [`docs/configuration.md`](docs/configuration.md)) are available.
- No cryptographic soundness claims of any kind are made about a scanned
  circuit, regardless of how many (or how few) findings a scan produces.
  A clean scan (exit code `0`) means "the implemented heuristics found
  nothing," not "this circuit is safe."

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

These three commands are the project's quality gates and are enforced in
CI on every push and pull request (`.github/workflows/ci.yml`).
CI also runs `zk-guard fixtures validate` against the checked-in fixture
tree as a fourth gate (see "Continuous integration" below).

See `docs/architecture.md` for crate boundaries and the scan pipeline, and
`docs/rule-taxonomy.md` for the rule specification format used by every
rule in `zkguard-rules`.

### Running the heavy fuzz campaign manually

`crates/zkguard-fuzz` has one deterministic, fast property-test suite that
runs as part of `cargo test --workspace` (no long-running fuzzing in
default CI, per `docs/roadmap.md`'s Phase 9 exit criteria). One heavier
proptest campaign is marked `#[ignore]` and is never run by `cargo test`
or CI by default. Run it manually before a release if you want extra
confidence:

```bash
cargo test -p zkguard-fuzz --release -- --ignored
```

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `master` and on every pull
request, with four jobs:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace` (the `#[ignore]`d heavy fuzz campaign above is
   never run here: default `cargo test` skips ignored tests, and CI does
   not pass `--ignored`/`--include-ignored`)
4. `cargo build --release -p zkguard-cli` followed by
   `./target/release/zk-guard fixtures validate` against the checked-in
   `fixtures/noir` tree

CI only builds and runs this repository's own code; it never executes
anything from a scanned target repository, makes no network calls beyond
crates.io and GitHub Actions itself, and uses no secrets, deploy keys, or
publishing tokens. There is no release/publish automation yet (see the
checklist below); a green CI run is required, but not sufficient, before
tagging a release.

## 0.2.0 release checklist

The honest, current state of the second release (see `CHANGELOG.md` for the
full history):

| Item | Status |
|---|---|
| `zk-guard scan` works on a Noir fixture directory | Done: verified against all 26 fixture projects under `fixtures/noir/`. |
| Rule coverage | Done: 6 of 7 MVP rules registered (`NOIR-PUBLIC-001`, `NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`, `ZK-HASH-001`, `ZK-NULLIFIER-001`, `ZK-TEST-001`); only `ZK-REPLAY-001` remains deferred. |
| Report formats | Done: JSON, Markdown, human, and SARIF 2.1.0 renderers, all pure and tested. |
| Configuration and suppressions | Done: optional `zkguard.toml` (rule enable/disable, `fail_on`, `[[suppress]]`) plus inline `// zkguard:ignore` directives, each requiring a reason. |
| Tests include vulnerable and safe fixtures | Done: every implemented rule has at least one vulnerable and one safe fixture; several have extra edge-case fixtures. |
| CI runs formatting, clippy, tests, and fixture validation | Done: `.github/workflows/ci.yml`. |
| README has install/usage/limitations/examples | Done: this document. |
| Docs state this is a best-effort scanner, not a formal verifier | Done: stated above and in `docs/rule-taxonomy.md`'s "Disclaimer." |

Known gaps tracked but intentionally **not** addressed in this release:

- A single unreadable/non-UTF-8 `.nr` file currently aborts an entire scan
  instead of being skipped with a warning. Logic fix, tracked separately.
- `ZK-REPLAY-001` is specified but not implemented; it will use the
  project-level `ProjectRule` mechanism added for `ZK-TEST-001`.
- No automated release/publish workflow. Building a release binary is a
  manual `cargo build --release -p zkguard-cli` step; there is no package
  upload, crates.io publish, or tagged-artifact automation, and none should
  be added without explicit approval.
