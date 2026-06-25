# Changelog

All notable changes to `zk-guard` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-unreleased]

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

[0.1.0-unreleased]: https://github.com/ThirdChildren/ZK_Guard
