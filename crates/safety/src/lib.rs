//! Safety engine: the last line of defence before anything is removed.
//!
//! * [`platform`] – every OS-specific path and file check.
//! * [`protected_paths`] – locations that must never be cleaned.
//! * [`validator`] – re-validates a path immediately before removal.
//! * [`quarantine`] – reversible removal (Trash or RustClean quarantine).

pub mod platform;
pub mod protected_paths;
pub mod quarantine;
pub mod validator;

pub use platform::{Os, app_data_dir, app_log_dir, home_dir};
pub use protected_paths::ProtectionRules;
pub use quarantine::{
    QuarantineRemover, QuarantineSession, RemovalError, RemovalMethod, Remover, TrashRemover,
    list_quarantine_sessions, purge_quarantine_session, quarantine_root, restore_quarantine,
};
pub use validator::{FileFingerprint, PathValidator, ValidationError};

use std::borrow::Cow;
use std::path::{Component, Path};

use unicode_normalization::UnicodeNormalization;

/// Component-wise `starts_with` that ignores case and Unicode normalisation
/// form.
///
/// Used for **protection** checks on every platform: over-matching a
/// protected location is the safe direction. macOS (APFS) and Windows
/// (NTFS) are case-insensitive by default, and the same name can be stored
/// precomposed (NFC, "é") or decomposed (NFD, "e" + accent), so a protected
/// `~/Documents` under a home such as `/Users/José` must match either way.
pub(crate) fn starts_with_ci(path: &Path, prefix: &Path) -> bool {
    let mut path_c = path.components();
    for p in prefix.components() {
        match path_c.next() {
            Some(c) if component_eq(c, p, true) => {}
            _ => return false,
        }
    }
    true
}

/// `starts_with` using the platform file system's own name equality.
///
/// Used to decide whether a path lies inside an **approved** cleanup root:
/// on case-sensitive Linux, `~/.cache/Foo` and `~/.cache/foo` are different
/// directories, so folding case there would widen the approved scope.
pub(crate) fn starts_with_fs(path: &Path, prefix: &Path) -> bool {
    let fold = platform::CURRENT.case_insensitive_fs();
    let mut path_c = path.components();
    for p in prefix.components() {
        match path_c.next() {
            Some(c) if component_eq(c, p, fold) => {}
            _ => return false,
        }
    }
    true
}

fn component_eq(a: Component<'_>, b: Component<'_>, fold_case: bool) -> bool {
    match (a, b) {
        (Component::Normal(a), Component::Normal(b)) => {
            names_eq(a.as_encoded_bytes(), b.as_encoded_bytes(), fold_case)
        }
        // Drive prefixes (`C:` vs `c:`) are always case-insensitive.
        (Component::Prefix(a), Component::Prefix(b)) => a
            .as_os_str()
            .as_encoded_bytes()
            .eq_ignore_ascii_case(b.as_os_str().as_encoded_bytes()),
        (a, b) => a == b,
    }
}

fn names_eq(a: &[u8], b: &[u8], fold_case: bool) -> bool {
    // Fast path: pure ASCII has a single normal form.
    if a.is_ascii() && b.is_ascii() {
        return if fold_case {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        };
    }
    let norm = |bytes: &[u8]| -> Cow<'_, str> {
        let s = String::from_utf8_lossy(bytes);
        let nfd: String = s.nfd().collect();
        Cow::Owned(if fold_case { nfd.to_lowercase() } else { nfd })
    };
    norm(a) == norm(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_ci_is_component_wise_and_case_insensitive() {
        assert!(starts_with_ci(
            Path::new("/Users/a/Documents/x"),
            Path::new("/users/A/documents")
        ));
        assert!(starts_with_ci(Path::new("/Users/a"), Path::new("/Users/a")));
        // Not a prefix match on partial component names.
        assert!(!starts_with_ci(
            Path::new("/Users/a/DocumentsOld"),
            Path::new("/Users/a/Documents")
        ));
        assert!(!starts_with_ci(Path::new("/Users"), Path::new("/Users/a")));
    }

    #[test]
    fn unicode_normal_forms_match() {
        let nfc = "/Users/Jos\u{e9}/Documents/x"; // é precomposed
        let nfd = "/Users/Jose\u{301}"; // e + combining acute
        assert!(starts_with_ci(Path::new(nfc), Path::new(nfd)));
        assert!(starts_with_ci(
            Path::new("/Users/J\u{d6}RG/Documents"),
            Path::new("/Users/j\u{f6}rg")
        ));
        assert!(!starts_with_ci(Path::new(nfc), Path::new("/Users/Jose")));
    }

    #[test]
    fn fs_match_follows_platform_case_rules() {
        let same = starts_with_fs(Path::new("/h/.cache/Foo/x"), Path::new("/h/.cache/foo"));
        assert_eq!(same, platform::CURRENT.case_insensitive_fs());
        assert!(starts_with_fs(
            Path::new("/h/Jos\u{e9}/x"),
            Path::new("/h/Jose\u{301}")
        ));
    }
}
