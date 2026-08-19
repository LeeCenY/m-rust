//! Containment checks for config-supplied provider paths (issue #429).
//!
//! A `path:` on a rule- or proxy-provider is attacker-influenced whenever the
//! config document arrives over the REST API (`PUT /configs`), so every path
//! read or written on behalf of a provider must stay inside the provider
//! cache directory — mirroring mihomo's `C.Path.IsSafePath` guard.

use std::path::{Component, Path, PathBuf};

/// Resolve `requested` against `base` and require the result to stay inside
/// `base`.
///
/// Robust to `..` traversal (paths are lexically normalized before the prefix
/// check), absolute paths (allowed only when they already point inside
/// `base`), and symlink tricks (the deepest existing ancestor of both sides
/// is canonicalized and containment is re-checked on the resolved forms).
///
/// Returns the normalized absolute path that callers must use for the actual
/// I/O, so the checked path and the opened path cannot diverge lexically.
pub(crate) fn resolve_contained(base: &Path, requested: &Path) -> Result<PathBuf, String> {
    let abs_base = normalize_absolute(base)?;
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        abs_base.join(requested)
    };
    let abs_joined = normalize_absolute(&joined)?;
    if !abs_joined.starts_with(&abs_base) {
        return Err(format!(
            "path '{}' escapes the provider directory '{}'",
            requested.display(),
            base.display()
        ));
    }
    // A symlink already present under `base` could still redirect the I/O
    // outside of it; compare the symlink-resolved forms as well.
    let canon_base = canonicalize_existing_prefix(&abs_base);
    let canon_joined = canonicalize_existing_prefix(&abs_joined);
    if !canon_joined.starts_with(&canon_base) {
        return Err(format!(
            "path '{}' escapes the provider directory '{}' via a symlink",
            requested.display(),
            base.display()
        ));
    }
    Ok(abs_joined)
}

/// Make `path` absolute (against the current directory) and lexically fold
/// `.` / `..` components. A `..` at the root is dropped (as the OS would),
/// so an under-flowing traversal can never gain components.
fn normalize_absolute(path: &Path) -> Result<PathBuf, String> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot resolve current directory: {e}"))?
            .join(path)
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => out.push(comp),
            Component::CurDir => {}
            // `pop()` refuses to remove the root/prefix, so this saturates
            // at the filesystem root instead of underflowing.
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Normal(c) => out.push(c),
        }
    }
    Ok(out)
}

/// Canonicalize the deepest existing ancestor of `path` (resolving symlinks)
/// and re-append the — already lexically normalized — non-existing remainder.
fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    let mut existing = path;
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(canon) => {
                let mut out = canon;
                for c in suffix.iter().rev() {
                    out.push(c);
                }
                return out;
            }
            Err(_) => match existing.parent() {
                Some(parent) => {
                    if let Some(name) = existing.file_name() {
                        suffix.push(name.to_os_string());
                    }
                    existing = parent;
                }
                None => return path.to_path_buf(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_path_inside_base_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let got = resolve_contained(dir.path(), Path::new("sub/rules.yaml")).unwrap();
        let base = normalize_absolute(dir.path()).unwrap();
        assert_eq!(got, base.join("sub").join("rules.yaml"));
    }

    #[test]
    fn absolute_path_inside_base_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("rules.yaml");
        let got = resolve_contained(dir.path(), &inside).unwrap();
        assert_eq!(got, inside);
    }

    #[test]
    fn dotdot_traversal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_contained(dir.path(), Path::new("../../etc/pwned")).unwrap_err();
        assert!(err.contains("escapes"), "unexpected: {err}");
    }

    #[test]
    fn nested_dotdot_traversal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_contained(dir.path(), Path::new("a/b/../../../evil")).unwrap_err();
        assert!(err.contains("escapes"), "unexpected: {err}");
    }

    #[test]
    fn absolute_path_outside_base_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_contained(dir.path(), Path::new("/etc/cron.d/pwned")).unwrap_err();
        assert!(err.contains("escapes"), "unexpected: {err}");
    }

    #[test]
    fn dotdot_stays_inside_base_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let got = resolve_contained(dir.path(), Path::new("sub/../rules.yaml")).unwrap();
        assert!(got.ends_with("rules.yaml"));
        assert!(!got.to_string_lossy().contains(".."));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected() {
        let outside = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), base.path().join("link")).unwrap();
        let err = resolve_contained(base.path(), Path::new("link/pwned")).unwrap_err();
        assert!(err.contains("symlink"), "unexpected: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_base_still_contains_its_own_files() {
        // e.g. macOS `/tmp` -> `/private/tmp`: base given via the symlink,
        // target expressed through the same symlink must stay accepted.
        let real = tempfile::tempdir().unwrap();
        let holder = tempfile::tempdir().unwrap();
        let alias = holder.path().join("alias");
        std::os::unix::fs::symlink(real.path(), &alias).unwrap();
        resolve_contained(&alias, Path::new("rules.yaml")).expect("contained path must resolve");
    }
}
