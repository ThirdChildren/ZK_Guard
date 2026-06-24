# zk-guard architecture

Status: architecture skeleton plus core domain model (Steps 1 and 3 of
`docs/agent-workflow.md`). `zkguard-core` now defines `Finding`, `Severity`,
`Confidence`, `RuleMetadata`, the `Rule` trait, and `ScanResult` (see
"Current status" below). No Noir discovery/parsing or concrete rule
implementations exist yet — those remain Step 4+.

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

zkguard-report  -- JSON / Markdown (later SARIF) emitters. Depends on
                   zkguard-core only. Pure formatting of Finding values;
                   does not run rules or touch the filesystem of the
                   scanned project.

zkguard-fuzz    -- optional, deterministic property/mutation tests layered
                   on top of zkguard-rules and zkguard-noir fixtures.
                   Not part of the default scan path. Added in Step 9,
                   after static rules stabilize.

zkguard-cli     -- binary `zk-guard`. Argument parsing and wiring only:
                   discovery -> rules -> report. Depends on all of the
                   above; nothing depends on zkguard-cli.
```

Dependency direction is strictly one-way:

```text
zkguard-cli
  -> zkguard-rules -> zkguard-noir -> zkguard-core
  -> zkguard-report -> zkguard-core
  -> zkguard-noir -> zkguard-core
zkguard-fuzz -> zkguard-core (and, once it exists, test-only deps on
                zkguard-rules / zkguard-noir fixtures)
```

`zkguard-core` has no dependents among analysis crates depending on it
transitively through the CLI — it is the leaf. This lets `zkguard-core` be
reused later for non-Noir targets (Circom, zkVM guest code) without dragging
in Noir-specific or CLI-specific code, per CLAUDE.md's framing of those as
future extensions.

## Data flow

The scan pipeline is linear and has no feedback loops:

```text
discovery -> parse -> rules -> findings -> report
```

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
- SARIF output, fuzzing, and Circom/zkVM support are explicitly deferred
  extensions, not scaffolded ahead of time.

## Current status

`zkguard-core` now contains the real domain model: `Finding`, `Severity`,
`Confidence`, `RuleMetadata`, the `Rule` trait, the placeholder
`SourceView` input type, and `ScanResult`. `zkguard-noir`, `zkguard-rules`,
`zkguard-report`, and `zkguard-fuzz` remain empty placeholders with no
scanner logic — they compile against `zkguard-core` but do not yet
implement discovery, rules, or report formatting. See `docs/roadmap.md` for
the phased plan that fills in the rest of this architecture.
