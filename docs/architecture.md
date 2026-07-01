# zk-guard architecture

Status: `0.1.0`, the first usable release (all ten steps of
`docs/agent-workflow.md` complete).
`zkguard-core` defines `Finding`, `Severity`, `Confidence`, `RuleMetadata`,
the `Rule` trait, and `ScanResult`; `zkguard-noir` does safe Noir discovery
and text heuristics; `zkguard-rules` implements five rules behind a
registry; `zkguard-report` renders JSON/Markdown/human output; `zkguard-cli`
exposes the `zk-guard` binary; and `zkguard-fuzz` holds deterministic
property tests. See "Current status" below.

## Goals and non-goals

zk-guard is a local, deterministic, best-effort static security scanner for
ZK application source code, starting with Noir. It is developer tooling: it
finds *suspicious patterns*, not formal proofs of correctness or
exploitability. See CLAUDE.md's "Non-negotiable design principles" for the
authoritative constraints; this document does not restate all of them, only
the ones that drive crate boundaries.

Non-goals: no new proving system, no database, no web server, no background
service, no network calls during a scan, no execution of code from the
scanned repository.

## Crate boundaries

The workspace is split so that the analysis engine never depends on the
CLI, and so that Noir-specific knowledge is isolated from generic rule
infrastructure and reporting.

```text
zkguard-core    -- domain types: Finding, Severity, Confidence, scanner
                   traits. No I/O, no CLI, no Noir-specific knowledge.
                   Depended on by every other crate.

zkguard-noir    -- Noir project discovery (Nargo.toml / src tree walking)
                   and Noir source representation. Depends on
                   zkguard-core only. No knowledge of rule logic or
                   report formats.

zkguard-rules   -- rule registry + rule implementations (NOIR-*, ZK-*).
                   Depends on zkguard-core and zkguard-noir. Produces
                   Finding values; has no awareness of how findings are
                   rendered or which CLI flags were used.

zkguard-report  -- JSON / Markdown / SARIF / human emitters. Depends on
                   zkguard-core only. Pure formatting of Finding values;
                   does not run rules or touch the filesystem of the
                   scanned project. (The SARIF emitter additionally takes
                   rule metadata, to list every rule as a
                   reportingDescriptor.)

zkguard-fuzz    -- optional, deterministic property/mutation tests layered
                   on top of zkguard-rules and zkguard-noir fixtures.
                   Not part of the default scan path. Added in Step 9,
                   after static rules stabilize.

zkguard-config  -- optional `zkguard.toml` loading + finding suppression
                   (0.2.0 line). Depends on zkguard-core only. Orchestration
                   *policy*, deliberately outside the analysis crates: it
                   decides which rules run, the fail-on severity, and which
                   findings are suppressed, but never changes rule detection.

zkguard-cli     -- binary `zk-guard`. Argument parsing and wiring only:
                   config -> discovery -> rules -> suppression -> report.
                   Depends on all of the above; nothing depends on
                   zkguard-cli.
```

Dependency direction is strictly one-way:

```text
zkguard-cli
  -> zkguard-rules -> zkguard-noir -> zkguard-core
  -> zkguard-report -> zkguard-core
  -> zkguard-noir -> zkguard-core
zkguard-fuzz -> zkguard-core (and, once it exists, test-only deps on
                zkguard-rules / zkguard-noir fixtures)
zkguard-config -> zkguard-core
```

`zkguard-core` has no dependents among analysis crates depending on it
transitively through the CLI — it is the leaf. This lets `zkguard-core` be
reused later for non-Noir targets (Circom, zkVM guest code) without dragging
in Noir-specific or CLI-specific code, per CLAUDE.md's framing of those as
future extensions.

## Data flow

The scan pipeline is linear and has no feedback loops:

```text
config -> discovery -> parse -> rules -> findings -> suppression -> report
```

`config` (`zkguard-config`) loads an optional `zkguard.toml` and filters the
rule registry to the enabled rules before anything runs. `suppression`
(also `zkguard-config`) partitions the raw findings into active vs suppressed
using inline `// zkguard:ignore` directives and `[[suppress]]` entries; only
active findings reach the report, and `ScanResult` carries the suppressed
count (and, with `--show-suppressed`, the suppressed findings). Neither step
changes what a rule detects. See `docs/configuration.md`.

1. **Discovery** (`zkguard-noir`): given a filesystem path, locate Noir
   projects (`Nargo.toml`, `src/`) using safe traversal — no following of
   symlink loops, no execution of anything found in the target repository.
2. **Parse** (`zkguard-noir`): build a source representation of each Noir
   project sufficient for rule matching (e.g. public input declarations,
   constraint/assert expressions, hash and nullifier call sites). This
   crate intentionally does not parse to a full verified Noir AST up front;
   parser depth grows only as specific rules need it (see "Premature
   complexity" below).
3. **Rules** (`zkguard-rules`): each rule reads the parsed representation
   and emits zero or more `Finding`s. Rules are independent of each other
   and registered in one registry keyed by `rule_id`.
4. **Findings** (`zkguard-core`): the `Finding` struct (implemented in Step
   3; see `crates/zkguard-core/src/finding.rs`) is the only artifact that
   crosses from analysis into reporting. Every finding carries rule_id,
   title, severity, confidence, location, evidence, why_it_matters, and
   remediation, per CLAUDE.md's reporting schema. Rules reach this struct
   through the `Rule` trait (`crates/zkguard-core/src/rule.rs`), which
   takes a placeholder `SourceView` (path + raw source text) until
   `zkguard-noir` introduces a richer Noir-specific representation in Step
   4.
5. **Report** (`zkguard-report`): renders a list of `Finding`s as JSON or
   Markdown. The CLI selects the format; the report crate has no opinion on
   CLI flags or output destinations beyond "give me findings, return
   bytes/text."

The CLI (`zkguard-cli`) is the only crate that touches `std::env`,
`clap`-style argument parsing, or process exit codes. It calls into
discovery, then rules, then report, in that order, and exits with a status
that reflects scan outcome.

## Why the core engine is independent of the CLI

CLAUDE.md design principle 7 requires the core analysis engine to be
independent from the CLI. Concretely:

- `zkguard-core`, `zkguard-noir`, and `zkguard-rules` must compile and have
  full test coverage without `zkguard-cli` in the dependency graph.
- This enables direct unit/integration testing of rules against fixtures
  without spawning the binary, keeps the door open for embedding the
  scanner in other tools (e.g. an editor extension or CI action) later
  without forking logic, and prevents argument-parsing concerns from
  leaking into rule logic.
- `zkguard-cli` is intentionally "thin": it should mostly call functions
  exposed by the other crates and format their results for a terminal.

## Avoiding premature complexity

- No full Noir compiler front-end is vendored or reimplemented. `zkguard-noir`
  extracts only what rules need, pattern-by-pattern, and documents
  assumptions (per CLAUDE.md principle 10) where it falls short of full
  semantic analysis.
- No plugin system, no dynamic rule loading, no scripting language for
  rules. Rules are Rust functions/structs registered at compile time.
- No persistence layer. A scan is a single in-process pipeline run; nothing
  is cached to disk between runs in the MVP.
- Fuzzing and Circom/zkVM support are explicitly deferred extensions, not
  scaffolded ahead of time. (SARIF output was added in the 0.2.0 line; see
  `zkguard_report::sarif` and `docs/sarif.md`.)

## Current status

`zkguard-core` contains the real domain model: `Finding`, `Severity`,
`Confidence`, `RuleMetadata`, the `Rule` trait, the `SourceView` input
type, and `ScanResult`. `zkguard-noir` implements safe Noir project
discovery and the text-level heuristics the rules need. `zkguard-rules`
implements five rules end-to-end — `NOIR-PUBLIC-001`, `NOIR-CONSTRAINT-001`,
`NOIR-RANGE-001`, `ZK-HASH-001`, and `ZK-NULLIFIER-001` — and exposes a
`registry()` function (`crates/zkguard-rules/src/registry.rs`) that is the
single source of truth for "which rules exist," consumed by both
`zkguard-cli`'s `scan` and `rules list` commands. The two remaining MVP
taxonomy rules, `ZK-REPLAY-001` and `ZK-TEST-001`, are specified in
`docs/rule-taxonomy.md` but not yet implemented (`ZK-REPLAY-001` is
project-level and will need cross-file aggregation or a `Rule`-trait change
when scheduled).

`zkguard-report` implements four pure renderers: `json` (machine-readable,
matches CLAUDE.md's reporting schema field names exactly), `markdown`
(GitHub-readable summary + per-finding sections), `human` (the default
terminal output) — all three `&ScanResult -> String` with no I/O — plus
`sarif` (SARIF 2.1.0 for GitHub code scanning; added in the 0.2.0 line),
which is `(&ScanResult, &[RuleMetadata]) -> Result<String, _>` because it
also lists every rule as a `reportingDescriptor`. See `docs/sarif.md`.

`zkguard-cli` (Step 6) implements `zk-guard scan`, `zk-guard rules list`,
and `zk-guard fixtures validate` via `clap`'s derive API
(`crates/zkguard-cli/src/cli.rs`), with command logic in
`crates/zkguard-cli/src/commands/` and a documented exit-code policy in
`crates/zkguard-cli/src/exit_code.rs` (also mirrored in `README.md`). The
binary remains a thin orchestration layer: it calls `zkguard_noir::discover`,
`zkguard_rules::registry()`, and
`zkguard_report::{json,markdown,human,sarif}::render` and contains no
discovery, parsing, or rule logic of its own.

`zkguard-fuzz` (Step 9) is no longer a placeholder: it holds deterministic,
bounded `proptest` property tests over the registry — no-panic/totality,
determinism, finding well-formedness, and directional safe/vulnerable
shape checks — that run inside `cargo test --workspace`. One heavier
campaign is `#[ignore]`d and never runs in default CI. `.github/workflows/ci.yml`
(Step 10) gates every push/PR on `cargo fmt --check`, `cargo clippy
-D warnings`, `cargo test --workspace`, and `zk-guard fixtures validate`.
See `docs/roadmap.md` for the phased plan and the post-0.1.0 follow-ups
(config/suppressions, `ZK-TEST-001`, `ZK-REPLAY-001`, Circom/zkVM). SARIF
output is already implemented (0.2.0 line).
