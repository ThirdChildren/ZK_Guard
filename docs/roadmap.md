# zk-guard roadmap

This roadmap maps CLAUDE.md's MVP scope and 0.1.0 definition of done onto
the phased steps in `docs/agent-workflow.md`. Each phase lists its exit
criteria so an agent (or reviewer) can tell when a phase is actually done,
not just started.

## Maturity levels

zk-guard moves through these maturity levels. Do not skip ahead — each
level should be working and tested before the next starts.

1. **Empty repo** -- no workspace exists.
2. **Skeleton workspace** (this phase) -- crates compile, no scanner logic.
3. **Static scanner MVP** -- domain model + Noir discovery + first rules
   working against fixtures, no CLI yet.
4. **CLI/reporting MVP** -- `zk-guard scan` works end-to-end with JSON and
   Markdown output. This is the 0.1.0 release target.
5. **Fuzzing extension** -- deterministic property/mutation tests layered
   on top of stable static rules.
6. **Release hardening** -- CI, packaging, docs polish, broader rule
   coverage.

## Phase 1 - Architecture skeleton (current)

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

## Phase 4 - First static rule (static scanner MVP begins)

Maps to Step 4 (`noir-static-analyzer`).

- [ ] Noir project discovery in `zkguard-noir` (find `Nargo.toml` / `src/`,
      safe traversal, no symlink loops, no script execution).
- [ ] `NOIR-PUBLIC-001` implemented in `zkguard-rules`.
- [ ] One vulnerable + one safe fixture under `fixtures/noir/`, with unit
      tests.
- Exit criteria: a rule runs end-to-end against a fixture directory and
  produces a correct `Finding` (or no finding) without going through the
  CLI.

## Phase 5 - Fixture coverage

Maps to Step 5 (`fixtures-test-engineer`).

- [ ] Fixture review for all rules implemented so far.
- [ ] Regression tests added for any gaps.
- Exit criteria: every implemented rule has at least one vulnerable and one
  safe fixture, per CLAUDE.md non-negotiable design principle 9.

## Phase 6 - CLI and reports (CLI/reporting MVP, 0.1.0 target)

Maps to Step 6 (`cli-reporting-engineer`).

- [ ] `zk-guard scan <path>` (default human-readable output).
- [ ] `--format json`, `--format markdown --output report.md`.
- [ ] `zk-guard rules list`.
- [ ] `zk-guard fixtures validate`.
- [ ] Documented exit codes.
- Exit criteria: matches CLAUDE.md's "Definition of done for the first
  usable release" — `zk-guard scan` works on a fixture directory, JSON and
  Markdown both work, README documents installation/usage/limitations.

## Phase 7 - Additional rules

Maps to Step 7 (`noir-static-analyzer`), interleaved with Phase 6 as
needed since 0.1.0 requires at least 5 rules.

- [ ] `NOIR-CONSTRAINT-001`, `NOIR-RANGE-001`, `ZK-HASH-001`,
      `ZK-NULLIFIER-001` (and `ZK-REPLAY-001`, `ZK-TEST-001` if time
      allows before 0.1.0; otherwise immediately after).
- Exit criteria: at least 5 of the 7 MVP rules implemented with fixtures
  and tests, satisfying the 0.1.0 rule-count requirement.

## Phase 8 - Security review

Maps to Step 8 (`security-reviewer`), run before any 0.1.0 tag.

- [ ] Review for dangerous execution behavior, misleading findings, missing
      fixtures, unsafe filesystem traversal, overclaimed guarantees.
- Exit criteria: review result is "pass" or "pass-with-issues" with issues
  tracked, not "fail".

## Phase 9 - Fuzzing extension (post-0.1.0)

Maps to Step 9 (`fuzzing-harness-engineer`). Only starts after static rules
are stable (Phase 7/8 complete).

- [ ] Deterministic property-based tests for existing static rules in
      `zkguard-fuzz`.
- [ ] No long-running fuzzing added to default CI.
- Exit criteria: fuzz/property tests run in normal `cargo test` time
  budgets and catch at least one class of bug a hand-written fixture
  wouldn't.

## Phase 10 - Release hardening

Maps to Step 10 (`ci-release-engineer`).

- [ ] GitHub Actions: `cargo fmt --check`, `cargo clippy -D warnings`,
      `cargo test --workspace`, fixture validation.
- [ ] README: installation, usage, examples, limitations, and an explicit
      statement that this is a best-effort scanner, not a formal verifier.
- [ ] 0.1.0 release checklist satisfied end-to-end.
- Exit criteria: CI is green on a clean clone; tagging 0.1.0 requires no
  manual undocumented steps.

## Explicitly out of scope for 0.1.0

- Circom and zkVM guest-code support (future extension per CLAUDE.md).
- SARIF report emission (future extension for `zkguard-report`).
- Any network calls, telemetry, or remote rule updates.
- Auto-execution of anything inside a scanned repository.
