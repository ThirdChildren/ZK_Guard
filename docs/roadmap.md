# zk-guard roadmap

This roadmap maps CLAUDE.md's MVP scope and 0.1.0 definition of done onto
the phased steps in `docs/agent-workflow.md`. Each phase lists its exit
criteria so an agent (or reviewer) can tell when a phase is actually done,
not just started.

## Maturity levels

zk-guard moves through these maturity levels. Do not skip ahead — each
level should be working and tested before the next starts.

1. **Empty repo** -- no workspace exists.
2. **Skeleton workspace** -- crates compile, no scanner logic.
3. **Static scanner MVP** -- domain model + Noir discovery + first rules
   working against fixtures, no CLI yet.
4. **CLI/reporting MVP** -- `zk-guard scan` works end-to-end with JSON and
   Markdown output. This is the 0.1.0 release target.
5. **Fuzzing extension** -- deterministic property/mutation tests layered
   on top of stable static rules.
6. **Release hardening** (current) -- CI, packaging, docs polish, broader
   rule coverage.

## Phase 1 - Architecture skeleton (complete)

Maps to Step 1 of `docs/agent-workflow.md`.

- [x] Cargo workspace with the six crates from CLAUDE.md's suggested layout.
- [x] Each crate compiles as a documented placeholder; no `Finding`, no
      rule logic, no parsing.
- [x] `docs/architecture.md` describing crate boundaries and data flow.
- [x] `docs/roadmap.md` (this file).
- [x] `.gitignore` for Rust build artifacts.
- Exit criteria: `cargo fmt --all`, `cargo build --workspace`,
  `cargo test --workspace`, and
  `cargo clippy --workspace --all-targets -- -D warnings` all pass with zero
  rule logic implemented.

## Phase 2 - Rule taxonomy

Maps to Step 2 (`zk-vulnerability-taxonomist`).

- [x] `docs/rule-taxonomy.md` covering the seven MVP rules:
      `NOIR-PUBLIC-001`, `NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`,
      `ZK-NULLIFIER-001`, `ZK-REPLAY-001`, `ZK-HASH-001`, `ZK-TEST-001`.
- [x] For each rule: severity, confidence, detection strategy,
      false-positive notes, vulnerable pattern, safe pattern, fixture
      requirements.
- Exit criteria: every MVP rule has an unambiguous, testable definition
  that Step 4/7 can implement without re-deriving intent. **Met** — no
  rule logic or fixtures were implemented in this phase; Step 3
  (`zk-project-architect`) still defines `Finding`/`Severity`/`Confidence`
  before Step 4 can implement against this taxonomy.

## Phase 3 - Core domain model (complete)

Maps to Step 3 (`zk-project-architect`).

- [x] `zkguard-core`: `Finding`, `Severity`, `Confidence`, `RuleMetadata`,
      the `Rule` trait, `SourceView`, and `ScanResult` per CLAUDE.md's
      reporting schema and `docs/rule-taxonomy.md`'s field mapping.
- [x] Minimal, testable — no rule registry, no Noir parsing, no CLI/report
      wiring added ahead of need.
- Exit criteria: `zkguard-core` has unit tests for the data model (13
  tests: severity ordering, lowercase serde round-trips for `Finding`/
  `Severity`/`Confidence`, `ScanResult` severity counting/sorting, `Rule`
  trait object-safety); `zkguard-noir` and `zkguard-rules` placeholders
  still compile against it. **Met** — `cargo fmt --all`, `cargo build
  --workspace`, `cargo test --workspace`, and `cargo clippy --workspace
  --all-targets -- -D warnings` all pass.

## Phase 4 - First static rule (static scanner MVP begins) (complete)

Maps to Step 4 (`noir-static-analyzer`).

- [x] Noir project discovery in `zkguard-noir` (find `Nargo.toml` / `src/`,
      safe traversal, no symlink loops, no script execution).
- [x] `NOIR-PUBLIC-001` implemented in `zkguard-rules`.
- [x] One vulnerable + one safe fixture under `fixtures/noir/`, with unit
      tests.
- Exit criteria: a rule runs end-to-end against a fixture directory and
  produces a correct `Finding` (or no finding) without going through the
  CLI. **Met.**

## Phase 5 - Fixture coverage (complete)

Maps to Step 5 (`fixtures-test-engineer`).

- [x] Fixture review for all rules implemented so far.
- [x] Regression tests added for any gaps.
- Exit criteria: every implemented rule has at least one vulnerable and one
  safe fixture, per CLAUDE.md non-negotiable design principle 9. **Met** —
  23 fixture projects under `fixtures/noir/`, including edge-case and
  false-positive-guard fixtures, exercised by `zkguard-rules`' integration
  tests.

## Phase 6 - CLI and reports (CLI/reporting MVP, 0.1.0 target)

Maps to Step 6 (`cli-reporting-engineer`).

- [x] `zk-guard scan <path>` (default human-readable output).
- [x] `--format json`, `--format markdown --output report.md`.
- [x] `zk-guard rules list`.
- [x] `zk-guard fixtures validate`.
- [x] Documented exit codes.
- Exit criteria: matches CLAUDE.md's "Definition of done for the first
  usable release" — `zk-guard scan` works on a fixture directory, JSON and
  Markdown both work, README documents installation/usage/limitations.
  **Met** — all three output formats (human/JSON/Markdown), `rules list`,
  and `fixtures validate` ship, with the exit-code scheme documented in
  `crates/zkguard-cli/src/exit_code.rs` and `README.md`.

## Phase 7 - Additional rules (complete)

Maps to Step 7 (`noir-static-analyzer`), interleaved with Phase 6 as
needed since 0.1.0 requires at least 5 rules.

- [x] `NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`, `ZK-HASH-001`,
      `ZK-NULLIFIER-001` implemented with fixtures and tests (0.1.0).
- [x] `ZK-TEST-001` implemented as a project-level rule (0.2.0; see the
      0.2.0 section below).
- [ ] `ZK-REPLAY-001` — still deferred (project-level; planned for 0.3.0).
- Exit criteria: at least 5 of the 7 MVP rules implemented with fixtures
  and tests, satisfying the 0.1.0 rule-count requirement. **Met at 0.1.0**
  with 5 rules; 6 are implemented as of 0.2.0.

## Phase 8 - Security review (complete)

Maps to Step 8 (`security-reviewer`), run before any 0.1.0 tag.

- [x] Review for dangerous execution behavior, misleading findings, missing
      fixtures, unsafe filesystem traversal, overclaimed guarantees.
- Exit criteria: review result is "pass" or "pass-with-issues" with issues
  tracked, not "fail". **Met** — verdict `pass-with-issues`; the one
  medium finding still open is the unreadable/non-UTF-8 `.nr` file aborting
  a whole scan (tracked in the README's known-gaps list).

## Phase 9 - Fuzzing extension (complete)

Maps to Step 9 (`fuzzing-harness-engineer`). Only starts after static rules
are stable (Phase 7/8 complete).

- [x] Deterministic property-based tests for existing static rules in
      `zkguard-fuzz` (no-panic/totality, determinism, finding
      well-formedness, directional safe/vulnerable shapes), fixed-seed
      `proptest`.
- [x] No long-running fuzzing added to default CI — one heavier campaign is
      `#[ignore]`d and only run manually
      (`cargo test -p zkguard-fuzz --release -- --ignored`).
- Exit criteria: fuzz/property tests run in normal `cargo test` time
  budgets and catch at least one class of bug a hand-written fixture
  wouldn't. **Met** — `cargo test -p zkguard-fuzz` runs in seconds.

## Phase 10 - Release hardening (complete)

Maps to Step 10 (`ci-release-engineer`).

- [x] GitHub Actions: `cargo fmt --check`, `cargo clippy -D warnings`,
      `cargo test --workspace`, fixture validation (`.github/workflows/ci.yml`).
- [x] README: installation, usage, examples, limitations, and an explicit
      statement that this is a best-effort scanner, not a formal verifier.
- [x] 0.1.0 release checklist satisfied end-to-end (see `README.md`).
- Exit criteria: CI is green on a clean clone; tagging 0.1.0 requires no
  manual undocumented steps. **Met** for the implemented scope; `0.1.0` is
  cut in `CHANGELOG.md` and ready to tag.

## Explicitly out of scope for 0.1.0

- Circom and zkVM guest-code support (future extension per CLAUDE.md).
- SARIF report emission (future extension for `zkguard-report`).
- Any network calls, telemetry, or remote rule updates.
- Auto-execution of anything inside a scanned repository.

## 0.2.0 (released)

The 0.2.0 line made zk-guard usable in real CI. All targets shipped:

- [x] **SARIF report output** (`zk-guard scan --format sarif`) in
      `zkguard-report`, for GitHub code-scanning / CI integration alongside
      the existing JSON and Markdown emitters. Every rule is emitted as a
      `reportingDescriptor`; every finding as a `result` with a stable
      `ruleId`, `level`, `message`, and `physicalLocation`/`region.startLine`.
      See `docs/sarif.md` and `examples/github-actions/zkguard-sarif.yml`.
- [x] **Configuration file** (`zkguard.toml`) in `zkguard-config`: per-rule
      enable/disable, `fail_on` (CLI takes precedence); plus **suppressions**
      (inline `// zkguard:ignore RULE_ID reason="..."` and file-based), each
      requiring a non-empty reason, with `--show-suppressed` and a
      `suppressed_count` in reports. See `docs/configuration.md`.
- [x] **`ZK-TEST-001`** (negative/`should_fail` test-coverage check) — the
      sixth MVP taxonomy rule. Implemented as a project-level rule via the new
      `zkguard_core::ProjectRule` trait (it aggregates `#[test]` attributes
      across a project's `.nr` files); gated on `fn main`, recognizing both
      the `should_fail` attribute and negatively-named tests. See
      `docs/rule-taxonomy.md`.

`ZK-REPLAY-001` (project-level replay/uniqueness binding) remains specified
but unimplemented after 0.2.0 (see the 0.3.0 plan below). The `ProjectRule`
trait added for `ZK-TEST-001` is the mechanism it will use.

## 0.3.0 (planned)

The 0.3.0 line hardens the scanner and closes the MVP rule set. Targets:

a. **Robust discovery (skip-with-warning).** A single unreadable / non-UTF-8
   `.nr` file currently aborts the whole scan (security-review finding M1).
   Make discovery skip such a file with a warning and keep scanning the rest,
   surfacing the skipped paths in `ScanResult`/stderr.
b. **`ZK-REPLAY-001`** (project-level replay/uniqueness binding) — the last
   unimplemented MVP taxonomy rule. Will build on the `ProjectRule` trait to
   aggregate nullifier/nonce/uniqueness signals across a project's `.nr`
   files.
c. **Evaluation corpus.** A curated set of real-world-shaped Noir projects
   (beyond the unit fixtures) to measure true/false-positive rates per rule
   and catch regressions in detection quality, not just in code.
d. **`docs/security-review.md` refresh.** A follow-up review pass over the
   0.2.0/0.3.0 surface (new `zkguard-config`, SARIF, project rules),
   re-checking the security boundaries rather than trusting the 0.1.0 audit.

`ZK-REPLAY-001` is the only MVP rule from `docs/rule-taxonomy.md` not yet
implemented; everything else in the MVP taxonomy is shipped.
