//! `zkguard-cli`: CLI entrypoint (binary name `zk-guard`).
//!
//! This crate contains CLI wiring only: argument parsing (`cli` module),
//! dispatching to `zkguard-noir` / `zkguard-rules` / `zkguard-report`
//! (`commands` module), and process exit codes (`exit_code` module). Per
//! CLAUDE.md design principle 7, the core analysis engine (`zkguard-core`,
//! `zkguard-noir`, `zkguard-rules`) stays independent of this crate; this
//! crate depends on them, never the other way around. `main` itself is
//! intentionally a few lines: parse arguments, dispatch, exit.
//!
//! ## Commands implemented
//!
//! - `zk-guard scan <path> [--format human|json|markdown] [--output FILE]
//!   [--fail-on SEVERITY]`
//! - `zk-guard rules list [--format human|json|markdown]`
//! - `zk-guard fixtures validate [--path DIR]`
//!
//! See `crate::exit_code` for the documented exit-code policy and
//! `README.md` for end-user usage examples.

mod cli;
mod commands;
mod exit_code;

use clap::Parser;

use cli::{Cli, Command, FixturesCommand, RulesCommand};

fn main() {
    let cli = Cli::parse();

    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();

    let code = match &cli.command {
        Command::Scan(args) => commands::scan::run(args, &mut stdout, &mut stderr),
        Command::Rules(RulesCommand::List(args)) => {
            commands::rules::run(args, &mut stdout, &mut stderr)
        }
        Command::Fixtures(FixturesCommand::Validate(args)) => {
            commands::fixtures::run(args, &mut stdout, &mut stderr)
        }
    };

    std::process::exit(code);
}
