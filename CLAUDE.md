# CLAUDE.md - zk-guard project instructions

## Project mission

Build `zk-guard`: an open-source security scanner for zero-knowledge applications. The first production target is Noir projects. Circom and zkVM guest-code support are future extensions.

The tool must help developers detect ZK-specific bugs before audit:

- under-constrained logic
- over-constrained logic
- unused or weakly-bound public inputs
- equality/range/hash checks computed but not asserted
- replay-prone nullifiers
- unsafe domain separation
- public/private input confusion
- brittle witness/test harnesses
- suspicious verifier integration patterns

Do not try to invent a new proving system. This project is developer tooling: static analysis, fixture-based testing, fuzzing harnesses, rule metadata, CI integration, and actionable reports.

## Non-negotiable design principles

1. Start narrow and useful: Noir first, static rules first, fuzzing second.
2. Every finding must include: `rule_id`, `title`, `severity`, `confidence`, `location`, `evidence`, `why_it_matters`, and `remediation`.
3. False positives are acceptable in early versions only if clearly marked with confidence.
4. Never execute arbitrary scripts from a target repository during scanning.
5. Prefer deterministic local analysis over network calls.
6. All scanner output must be machine-readable and human-readable.
7. Keep the core analysis engine independent from the CLI.
8. Treat test fixtures as first-class security examples.
9. Every new rule must ship with at least one vulnerable fixture and one safe fixture.
10. No vague TODOs. Convert open questions into concrete issues, tests, or documented assumptions.

## Suggested implementation stack

Use Rust unless there is a strong reason not to.

Recommended workspace layout:

```text
.
├── CLAUDE.md
├── README.md
├── Cargo.toml
├── crates/
│   ├── zkguard-cli/          # CLI entrypoint
│   ├── zkguard-core/         # shared domain types, scanner traits, findings
│   ├── zkguard-noir/         # Noir project discovery, parsing, rule adapters
│   ├── zkguard-rules/        # rule implementations and rule registry
│   ├── zkguard-fuzz/         # mutation/property/fuzzing harnesses
│   └── zkguard-report/       # JSON, SARIF, Markdown reporters
├── fixtures/
│   └── noir/
│       ├── vulnerable/
│       └── safe/
├── docs/
│   ├── architecture.md
│   ├── rule-taxonomy.md
│   ├── roadmap.md
│   └── threat-model.md
└── tests/
    ├── cli/
    └── integration/
```

## Initial MVP scope

The MVP is not a complete ZK verifier. The MVP is a credible scanner with a small, well-tested rule set.

### MVP commands

```bash
zk-guard scan ./path/to/noir-project
zk-guard scan ./path/to/noir-project --format json
zk-guard scan ./path/to/noir-project --format markdown --output report.md
zk-guard rules list
zk-guard fixtures validate
```

### MVP rule families

Implement these before adding exotic features:

1. `NOIR-PUBLIC-001`: public input declared but never used in a constraint-relevant expression.
2. `NOIR-CONSTRAINT-001`: boolean/equality/range expression computed but not asserted/constrained.
3. `NOIR-RANGE-001`: numeric value used in security-sensitive context without obvious range check.
4. `ZK-NULLIFIER-001`: nullifier-like value generated without visible domain separator.
5. `ZK-REPLAY-001`: proof/action pattern appears to lack nonce, nullifier, or uniqueness binding.
6. `ZK-HASH-001`: hash commitment built from ambiguous concatenation or missing domain tag.
7. `ZK-TEST-001`: circuit has no negative tests or no failing-witness tests.

Each rule needs:

- rule metadata in code
- short documentation in `docs/rule-taxonomy.md`
- vulnerable fixture
- safe fixture
- unit test
- integration test when possible

## Development workflow for Claude Code

Use the subagents in `.claude/agents/` deliberately. Do not let one general agent implement everything.

Recommended step order:

1. Ask `zk-project-architect` to create or update the implementation plan and architecture docs.
2. Ask `zk-vulnerability-taxonomist` to refine rule taxonomy and fixture requirements.
3. Ask `noir-static-analyzer` to implement project discovery, source scanning, rule interfaces, and first Noir rules.
4. Ask `fixtures-test-engineer` to build vulnerable/safe fixtures and regression tests.
5. Ask `cli-reporting-engineer` to expose the scanner through CLI and reports.
6. Ask `fuzzing-harness-engineer` to add mutation/property-based checks only after static rules are stable.
7. Ask `security-reviewer` to review the implementation before merging major changes.
8. Ask `ci-release-engineer` to add CI, release packaging, and documentation polish.

When a task is complex, require the agent to produce a short plan first, then implement, then run tests.

## Quality gates

Before any task is considered done:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

If the repository is not initialized yet, create a minimal Rust workspace first and make these commands pass.

## Reporting schema

Use this conceptual finding model across the codebase:

```rust
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: PathBuf,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub evidence: String,
    pub why_it_matters: String,
    pub remediation: String,
}
```

Severity values: `critical`, `high`, `medium`, `low`, `info`.

Confidence values: `high`, `medium`, `low`.

## Security boundaries

This project analyzes potentially hostile repositories. Agents must not add code that:

- executes target repository install scripts automatically
- downloads dependencies without explicit user approval
- sends source code to external services
- treats scanner findings as proof of exploitability
- claims cryptographic soundness without formal evidence

Use safe filesystem traversal. Avoid following symlink loops. Avoid deleting user files.

## Definition of done for the first usable release

Version `0.1.0` is ready when:

- `zk-guard scan` works on a Noir fixture directory
- at least 5 rules are implemented
- JSON and Markdown reports work
- tests include vulnerable and safe fixtures
- CI runs formatting, clippy, and tests
- README contains installation, usage, limitations, and examples
- docs clearly state that this is a best-effort security scanner, not a formal verifier

## Tone and behavior expected from Claude Code

Be direct. Prefer small verified steps over large speculative rewrites. When uncertain about ZK semantics, write a test fixture or document the assumption. Do not over-engineer the parser before rule value is proven. Make the first release useful, even if imperfect.
