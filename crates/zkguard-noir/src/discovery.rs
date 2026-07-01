//! Safe Noir project discovery.
//!
//! Per CLAUDE.md's "Security boundaries" and `docs/architecture.md`'s
//! "Discovery" stage, this module only:
//!
//! - walks the filesystem under a user-given root path,
//! - locates `Nargo.toml` (Noir project marker) and `.nr` source files,
//! - reads `.nr` file contents into [`SourceView`] values.
//!
//! It never executes anything found in the scanned repository, never
//! follows symlinks (avoiding both symlink loops and accidental escapes
//! outside the given root), and never performs network access. This is the
//! Step 4 integration point `zkguard-core` documented in
//! [`zkguard_core::SourceView`]'s doc comment: "Step 4 ... is expected to
//! either use this type directly ... or introduce a richer Noir-specific
//! source representation."  For now we use `SourceView` directly — no rule
//! implemented so far needs more than raw text plus a path.

use std::fs;
use std::path::{Path, PathBuf};

use zkguard_core::{SkipKind, SkippedFile, SourceView};

/// File extension Noir source files use.
const NOIR_SOURCE_EXTENSION: &str = "nr";

/// Filename Noir uses to mark a package root.
const NARGO_MANIFEST_FILENAME: &str = "Nargo.toml";

/// Errors that can occur during discovery.
///
/// Kept small and explicit per CLAUDE.md principle 10 (no vague failure
/// modes): every variant says exactly what went wrong instead of
/// collapsing into a generic "discovery failed" message.
#[derive(Debug)]
pub enum DiscoveryError {
    /// The given root path does not exist on disk.
    RootNotFound(PathBuf),
    /// An I/O error occurred while reading a directory entry or file.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryError::RootNotFound(path) => {
                write!(f, "scan root does not exist: {}", path.display())
            }
            DiscoveryError::Io { path, source } => {
                write!(f, "I/O error reading {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for DiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DiscoveryError::RootNotFound(_) => None,
            DiscoveryError::Io { source, .. } => Some(source),
        }
    }
}

/// A discovered Noir project rooted at the directory containing its
/// `Nargo.toml`, if one was found.
///
/// `manifest_path` is `None` when the scan root is a single `.nr` file (or
/// a directory tree with `.nr` files but no `Nargo.toml`) — discovery still
/// collects source files in that case rather than failing, since rules
/// only need [`SourceView`]s, not a validated package manifest. Whether a
/// project "looks like" a full Nargo package is a concern for a later,
/// more opinionated discovery pass, not this minimal Step 4 scope.
#[derive(Debug, Clone, PartialEq)]
pub struct NoirProject {
    /// Path to `Nargo.toml`, if discovery found exactly one governing the
    /// scanned root. `None` for ad hoc / manifest-less scans (e.g. a single
    /// loose `.nr` file passed directly).
    pub manifest_path: Option<PathBuf>,
    /// Every `.nr` source file found under the scan root, as a
    /// [`SourceView`] ready to feed into [`zkguard_core::Rule::check`].
    pub sources: Vec<SourceView>,
    /// `.nr` files that were located but could not be read (unreadable or
    /// non-UTF-8). Discovery skips them and keeps going rather than aborting
    /// the whole scan (security-review finding M1); the caller surfaces them
    /// as warnings. Empty on a clean scan.
    pub skipped: Vec<SkippedFile>,
}

impl NoirProject {
    /// Number of `.nr` source files successfully read.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.sources.len()
    }
}

/// Discovers a Noir project (or loose collection of `.nr` files) under
/// `root`.
///
/// Behavior by `root` shape:
/// - `root` is a single file: if it has the `.nr` extension, returns a
///   project containing exactly that file and no manifest. Any other file
///   extension yields an empty `sources` list (not an error — the caller
///   asked to scan a specific path, and "no Noir source here" is a valid,
///   reportable outcome, not a failure).
/// - `root` is a directory: walks the tree (depth-first, deterministic
///   order) collecting every `.nr` file and recording the first
///   `Nargo.toml` found at or above the shallowest matching directory as
///   `manifest_path`.
/// - `root` does not exist: returns [`DiscoveryError::RootNotFound`] rather
///   than panicking, per the Step 4 task's explicit requirement.
///
/// Safety properties (CLAUDE.md "Security boundaries"):
/// - Never follows symlinks (neither for directories nor files), which
///   makes symlink loops impossible by construction and prevents the walk
///   from escaping `root` through a symlink pointing outside it.
/// - Never executes, interprets, or shells out to anything found in the
///   scanned tree.
/// - Never performs network access.
/// - Only reads files inside `root`; the walk never follows `..` or
///   absolute symlink targets because symlinks are skipped entirely.
pub fn discover(root: impl AsRef<Path>) -> Result<NoirProject, DiscoveryError> {
    let root = root.as_ref();

    let root_meta = fs::symlink_metadata(root).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            DiscoveryError::RootNotFound(root.to_path_buf())
        } else {
            DiscoveryError::Io {
                path: root.to_path_buf(),
                source,
            }
        }
    })?;

    if root_meta.is_symlink() {
        // Refuse to treat a symlinked root as a traversal entry point at
        // all — the caller-provided root itself must be a real file or
        // directory, consistent with "never follow symlinks" below.
        return Ok(NoirProject {
            manifest_path: None,
            sources: Vec::new(),
            skipped: Vec::new(),
        });
    }

    if root_meta.is_file() {
        let mut sources = Vec::new();
        let mut skipped = Vec::new();
        if is_noir_source(root) {
            read_noir_source(root, &mut sources, &mut skipped);
        }
        return Ok(NoirProject {
            manifest_path: None,
            sources,
            skipped,
        });
    }

    let mut sources = Vec::new();
    let mut skipped = Vec::new();
    let mut manifest_path = None;
    walk_dir(root, &mut sources, &mut skipped, &mut manifest_path)?;

    // Deterministic output: callers (including tests) should not depend on
    // OS-specific directory iteration order.
    sources.sort_by(|a, b| a.path.cmp(&b.path));
    skipped.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(NoirProject {
        manifest_path,
        sources,
        skipped,
    })
}

/// Recursively walks `dir`, pushing every discovered `.nr` file into
/// `sources` and recording the first `Nargo.toml` encountered into
/// `manifest_path`.
///
/// Symlinked entries (files or directories) are skipped entirely — this is
/// the core of the "no symlink loops, no escaping the root" safety
/// property, applied uniformly rather than via loop/visited-set tracking,
/// which would still allow escaping the root via a symlink target outside
/// it even if it prevented infinite loops.
fn walk_dir(
    dir: &Path,
    sources: &mut Vec<SourceView>,
    skipped: &mut Vec<SkippedFile>,
    manifest_path: &mut Option<PathBuf>,
) -> Result<(), DiscoveryError> {
    let entries = fs::read_dir(dir).map_err(|source| DiscoveryError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| DiscoveryError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();

        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            // A file disappearing between readdir and stat (e.g. a racing
            // process in the scanned tree) is not a scan failure — skip it.
            Err(_) => continue,
        };

        if meta.is_symlink() {
            // Never follow symlinks: prevents loops and prevents escaping
            // `root` via a symlink that points outside it.
            continue;
        }

        if meta.is_dir() {
            walk_dir(&path, sources, skipped, manifest_path)?;
        } else if meta.is_file() {
            if is_nargo_manifest(&path) && manifest_path.is_none() {
                *manifest_path = Some(path.clone());
            }
            if is_noir_source(&path) {
                read_noir_source(&path, sources, skipped);
            }
        }
    }

    Ok(())
}

fn is_noir_source(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == NOIR_SOURCE_EXTENSION)
}

fn is_nargo_manifest(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == NARGO_MANIFEST_FILENAME)
}

/// Reads one `.nr` file into `sources`, or records it in `skipped` if it
/// cannot be read (unreadable) or is not valid UTF-8. A per-file read failure
/// never aborts the scan (security-review finding M1): a single hostile or
/// malformed file must not deny scanning the rest of the project.
fn read_noir_source(path: &Path, sources: &mut Vec<SourceView>, skipped: &mut Vec<SkippedFile>) {
    match fs::read_to_string(path) {
        Ok(contents) => sources.push(SourceView::new(path.to_path_buf(), contents)),
        Err(err) => skipped.push(SkippedFile::new(
            path.to_path_buf(),
            err.to_string(),
            classify_read_error(&err),
        )),
    }
}

/// Maps a `read_to_string` failure to a coarse [`SkipKind`]. A non-UTF-8 file
/// surfaces as `InvalidData` from `read_to_string`.
fn classify_read_error(err: &std::io::Error) -> SkipKind {
    match err.kind() {
        std::io::ErrorKind::InvalidData => SkipKind::NonUtf8,
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound => SkipKind::Unreadable,
        _ => SkipKind::OtherIo,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "zkguard-noir-discovery-test-{name}-{}-{}",
            std::process::id(),
            // crude per-test uniqueness without pulling in a dependency
            name.len()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn missing_root_returns_clear_error_not_panic() {
        let mut missing = std::env::temp_dir();
        missing.push("zkguard-noir-discovery-definitely-does-not-exist-xyz");
        let _ = fs::remove_dir_all(&missing);

        let result = discover(&missing);
        assert!(matches!(result, Err(DiscoveryError::RootNotFound(_))));
    }

    #[test]
    fn discovers_nargo_project_with_src_tree() {
        let root = temp_dir("project");
        fs::write(root.join("Nargo.toml"), "[package]\nname = \"demo\"\n").expect("write");
        fs::create_dir_all(root.join("src")).expect("mkdir src");
        fs::write(root.join("src/main.nr"), "fn main() {}\n").expect("write main.nr");
        fs::create_dir_all(root.join("src/utils")).expect("mkdir utils");
        fs::write(root.join("src/utils/helpers.nr"), "fn helper() {}\n").expect("write");
        // Non-Noir file must be ignored.
        fs::write(root.join("README.md"), "not noir source").expect("write readme");

        let project = discover(&root).expect("discover");

        assert_eq!(project.manifest_path, Some(root.join("Nargo.toml")));
        assert_eq!(project.file_count(), 2);
        assert!(project
            .sources
            .iter()
            .any(|s| s.path == root.join("src/main.nr")));
        assert!(project
            .sources
            .iter()
            .any(|s| s.path == root.join("src/utils/helpers.nr")));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn single_nr_file_root_is_supported() {
        let root = temp_dir("single-file");
        let file = root.join("only.nr");
        fs::write(&file, "fn main() {}\n").expect("write");

        let project = discover(&file).expect("discover");
        assert_eq!(project.manifest_path, None);
        assert_eq!(project.file_count(), 1);
        assert_eq!(project.sources[0].path, file);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn single_non_noir_file_root_yields_no_sources_not_an_error() {
        let root = temp_dir("single-non-noir-file");
        let file = root.join("notes.txt");
        fs::write(&file, "irrelevant").expect("write");

        let project = discover(&file).expect("discover");
        assert_eq!(project.file_count(), 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn non_utf8_file_is_skipped_not_fatal() {
        let root = temp_dir("non-utf8");
        fs::write(root.join("Nargo.toml"), "[package]\nname = \"demo\"\n").expect("write");
        fs::create_dir_all(root.join("src")).expect("mkdir src");
        // Valid source alongside a non-UTF-8 `.nr` file.
        fs::write(root.join("src/main.nr"), "fn main() {}\n").expect("write main");
        fs::write(root.join("src/broken.nr"), [0x66, 0x6e, 0xff, 0xfe, 0x00])
            .expect("write broken");

        let project = discover(&root).expect("discovery must not fail on a bad file");

        // The valid file is still scanned.
        assert_eq!(project.file_count(), 1);
        assert!(project
            .sources
            .iter()
            .any(|s| s.path == root.join("src/main.nr")));

        // The bad file is recorded as skipped, classified as non-UTF-8.
        assert_eq!(project.skipped.len(), 1);
        assert_eq!(project.skipped[0].path, root.join("src/broken.nr"));
        assert_eq!(project.skipped[0].kind, SkipKind::NonUtf8);
        assert!(!project.skipped[0].reason.is_empty());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_project_has_no_skipped_files() {
        let root = temp_dir("clean-no-skips");
        fs::write(root.join("main.nr"), "fn main() {}\n").expect("write");
        let project = discover(&root).expect("discover");
        assert!(project.skipped.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_directory_is_not_followed() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("symlink-root");
        let real_target = temp_dir("symlink-target");
        fs::write(real_target.join("evil.nr"), "fn main() {}\n").expect("write");

        let link_path = root.join("linked");
        symlink(&real_target, &link_path).expect("create symlink");

        let project = discover(&root).expect("discover");
        assert_eq!(
            project.file_count(),
            0,
            "must not follow a symlinked directory into another tree"
        );

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&real_target);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_file_is_skipped() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("symlink-file-root");
        let real_target = temp_dir("symlink-file-target");
        let real_file = real_target.join("real.nr");
        fs::write(&real_file, "fn main() {}\n").expect("write");

        let link_path = root.join("link.nr");
        symlink(&real_file, &link_path).expect("create symlink");

        let project = discover(&root).expect("discover");
        assert_eq!(project.file_count(), 0, "must not follow a symlinked file");

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&real_target);
    }
}
