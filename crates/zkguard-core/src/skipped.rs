//! Partial-scan warnings: files discovery could not read.
//!
//! A [`SkippedFile`] records a `.nr` source that was located but could not be
//! turned into a [`crate::SourceView`] (unreadable, or not valid UTF-8). It is
//! a **robustness/availability** signal, never a security finding: a hostile
//! or malformed repository must not be able to abort an entire scan with one
//! bad file, but the skipped file is surfaced so the result is honestly
//! "partial" rather than silently incomplete. See `docs/security-review.md`
//! finding M1.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Why a file was skipped during discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipKind {
    /// The file's bytes are not valid UTF-8 (`std::io::ErrorKind::InvalidData`).
    NonUtf8,
    /// The file could not be read (e.g. permission denied, not found).
    Unreadable,
    /// Any other I/O error while reading the file.
    OtherIo,
}

/// A source file that discovery located but could not read, with the reason.
///
/// This is a warning, not a [`crate::Finding`]: it carries no severity or
/// confidence and never affects the scan's exit code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkippedFile {
    /// Path to the file that was skipped.
    pub path: PathBuf,
    /// Human-readable reason (the underlying I/O error message).
    pub reason: String,
    /// Coarse classification of the skip.
    pub kind: SkipKind,
}

impl SkippedFile {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, reason: impl Into<String>, kind: SkipKind) -> Self {
        Self {
            path: path.into(),
            reason: reason.into(),
            kind,
        }
    }
}
