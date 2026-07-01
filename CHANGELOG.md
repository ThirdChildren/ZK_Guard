# Changelog

All notable changes to `zk-guard` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Robust discovery (security-review M1).** A single unreadable or non-UTF-8
  `.nr` file no longer aborts the entire scan. Discovery now skips such a file
  and records it as a `zkguard_core::SkippedFile` (`path`, `reason`, and
  `kind`: `non_utf8` / `unreadable` / `other_io`) in `NoirProject::skipped`,
  continuing to scan the rest of the tree. The CLI surfaces skipped files as
  warnings on stderr and in the report: a new additive `skipped` array in JSON
  (omitted when empty), a "Warnings (skipped files)" section and summary count
  in human output, and a "Skipped files" table in Markdown. SARIF is
  unchanged (skips are not security results). Skipped files never affect the
  exit code, which still depends only on findings. Rule semantics are
  unchanged, and the scanner still executes nothing, follows no symlinks, and
  makes no network calls.

### Changed

- **Docs cleanup for the 0.3.0 line.** `docs/architecture.md`,
  `docs/roadmap.md`, `docs/rule-taxonomy.md`, and `docs/security-review.md`
  updated to the real post-0.2.0 state: six implemented rules (per-file plus
  the project-level `ZK-TEST-001`), the `zkguard-config` crate, SARIF output,
  and the `ProjectRule` mechanism, with `ZK-REPLAY-001` marked as the only
  specified-but-unimplemented MVP rule. Added a 0.3.0 roadmap section
  (skip-with-warning discovery, `ZK-REPLAY-001`, an eval corpus, a
  security-review refresh) and a "Post-v0.2.0 status" note recording that the
  stale-README finding (M2) is resolved and the unreadable-file finding (M1)
  is still open. README scan/JSON examples regenerated to the current
  six-rule output.
- **GitHub Action example** (`examples/github-actions/zkguard-sarif.yml` and
  `docs/sarif.md`) now uses `github/codeql-action/upload-sarif@v4`.

## [0.2.0] - 2026-07-01

Second release: makes zk-guard usable in real CI. Adds SARIF output,
optional `zkguard.toml` configuration with finding suppressions, and the
project-level `ZK-TEST-001` rule (6 of 7 MVP rules now implemented). Still a
best-effort static scanner, **not a formal verifier**.

### Added

- **`ZK-TEST-001` rule** (test hygiene) — flags a Noir project that declares
  `fn main` but has no negative test: no `#[test(should_fail)]` /
  `should_fail_with` attribute and no `#[test]` whose name contains
  fail/invalid/reject/negative/should_fail. It is the first **project-level**
  rule, added via a new `zkguard_core::ProjectRule` trait (it aggregates
  `#[test]` attributes across all `.nr` files rather than scanning one file
  in isolation). Never runs `nargo`; a purely textual check. Severity `low`,
  confidence `medium`. Ships with vulnerable (no-tests, happy-path-only) and
  safe fixtures. `rules list`, SARIF `reportingDescriptor`s, `rules_run`, and
  config enable/disable all cover it. `ZK-REPLAY-001` remains the only
  unimplemented MVP rule.
- **`zkguard.toml` configuration + suppressions** — new `zkguard-config`
  crate. An optional `zkguard.toml` in the project root can enable/disable
  rules per `rule_id`, set a default `fail_on` severity (overridden by the CLI
  `--fail-on` flag), and suppress findings. Suppressions come from inline
  `// zkguard:ignore RULE_ID reason="..."` directives (on the flagged line or
  the line above) or `[[suppress]]` entries (rule + path, optional line); each
  requires a non-empty reason. Reports include a `suppressed_count` in every
  format, and `--show-suppressed` additionally lists suppressed findings
  (with reason and source). Rule detection semantics are unchanged; SARIF,
  JSON, Markdown, and human output stay backward compatible (JSON/human/
  Markdown gain only additive suppression fields/lines). See
  `docs/configuration.md`.
- **SARIF 2.1.0 output** — `zk-guard scan --format sarif` emits a SARIF log
  for GitHub code scanning / CI upload (`github/codeql-action/upload-sarif`).
  Every registered rule becomes a `reportingDescriptor`; every finding a
  `result` with a stable `ruleId`, `level`, `message`, and
  `physicalLocation`/`region.startLine`, using repository-relative paths.
  New `zkguard_report::sarif` module (golden + unit tested), `docs/sarif.md`,
  and an example workflow at `examples/github-actions/zkguard-sarif.yml`.
  `rules list --format sarif` is a usage error (SARIF encodes scan results,
  not the registry). JSON, Markdown, and human output are unchanged.

## [0.1.0] - 2026-07-01

First usable release of `zk-guard`, a best-effort static security scanner
for zero-knowledge application source code (Noir first). This is developer
tooling that flags suspicious source patterns — **not a formal verifier**,
and findings are not proof of exploitability.

### Added

- **Workspace** — Cargo workspace with six crates: `zkguard-core`
  (domain model), `zkguard-noir` (discovery + heuristics), `zkguard-rules`
  (rules + registry), `zkguard-report` (renderers), `zkguard-fuzz`
  (property tests), and `zkguard-cli` (the `zk-guard` binary). The analysis
  engine is independent of the CLI.
- **Domain model** — `Finding`, `Severity` (`critical`/`high`/`medium`/
  `low`/`info`), `Confidence` (`high`/`medium`/`low`), `RuleMetadata`, the
  `Rule` trait, `SourceView`, and `ScanResult`, with lowercase serde output
  matching the documented reporting schema (see `docs/rule-taxonomy.md`).
- **Noir discovery** — safe filesystem traversal that locates `Nargo.toml`
  and `.nr` sources without following symlinks, executing target content,
  or making network calls.
- **Rules (5 of 7 MVP)** — `NOIR-PUBLIC-001`, `NOIR-CONSTRAINT-001`,
  `NOIR-RANGE-001`, `ZK-HASH-001`, and `ZK-NULLIFIER-001`, each with
  metadata, vulnerable and safe fixtures, and unit + integration tests.
- **CLI** — `zk-guard scan`, `zk-guard rules list`, and
  `zk-guard fixtures validate`, with `--format human|json|markdown`,
  `--output`, and `--fail-on`, plus a documented exit-code scheme
  (`0` clean / `1` findings / `2` usage / `3` internal).
- **Reports** — pure JSON, Markdown, and human/terminal renderers over
  `ScanResult`.
- **Fixtures** — 23 fixture projects under `fixtures/noir/`, including
  edge-case and false-positive-guard fixtures.
- **Property tests** — deterministic, fixed-seed `proptest` suites in
  `zkguard-fuzz` (no-panic/totality, determinism, finding well-formedness,
  directional safe/vulnerable shapes). One heavier campaign is `#[ignore]`d
  and only run manually.
- **CI** — `.github/workflows/ci.yml` gating every push/PR on
  `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace`,
  and `zk-guard fixtures validate`.
- **Docs** — `docs/architecture.md`, `docs/roadmap.md`,
  `docs/rule-taxonomy.md`, and a `README.md` with installation, usage,
  examples, limitations, and a 0.1.0 release checklist.

### Known limitations

- `ZK-REPLAY-001` and `ZK-TEST-001` are specified in
  `docs/rule-taxonomy.md` but **not yet implemented**. `ZK-REPLAY-001` is
  project-level and will need cross-file aggregation or a `Rule`-trait
  change.
- Detection is text/shape-level heuristics over single functions in most
  rules — not full dataflow or cross-file analysis. Custom helper
  functions, cross-function flow, and naming-only detection are documented
  false-positive/false-negative sources.
- A single unreadable/non-UTF-8 `.nr` file currently aborts an entire scan
  instead of being skipped with a warning (security-review finding M1).
- Noir only — Circom and zkVM guest code are out of scope for now.
- No SARIF output; JSON and Markdown only.
- No automated release/publish workflow.

[Unreleased]: https://github.com/ThirdChildren/ZK_Guard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ThirdChildren/ZK_Guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ThirdChildren/ZK_Guard/releases/tag/v0.1.0
