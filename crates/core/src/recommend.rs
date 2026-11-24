//! Smart recommendations: which scanned files RustClean suggests deleting.
//!
//! Deliberately conservative. A file is recommended only if it is
//! classified `Safe` **and** has not been modified recently, so data an app
//! is actively writing is never suggested. `Review`, `Unknown` and
//! `Protected` files are never recommended; recommendation only ever narrows
//! what is selectable and changes nothing about how files are removed.

use std::time::{Duration, SystemTime};

use crate::classifier::SafetyClass;
use crate::scanner::{Candidate, DAY};

/// Files modified more recently than this are not recommended.
pub const RECENT: Duration = DAY;

/// Whether `c` is recommended for deletion, with a user-facing reason
/// either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recommendation {
    Recommended(String),
    NotRecommended(String),
}

impl Recommendation {
    pub fn is_recommended(&self) -> bool {
        matches!(self, Recommendation::Recommended(_))
    }

    pub fn reason(&self) -> &str {
        match self {
            Recommendation::Recommended(r) | Recommendation::NotRecommended(r) => r,
        }
    }
}

pub fn recommend(c: &Candidate, now: SystemTime) -> Recommendation {
    use Recommendation::*;
    match c.class {
        SafetyClass::Safe => {}
        SafetyClass::Review => {
            return NotRecommended("needs your review first".into());
        }
        _ => return NotRecommended("cannot be removed".into()),
    }
    let Some(modified) = c.fingerprint.modified else {
        return NotRecommended("modification time unknown".into());
    };
    match now.duration_since(modified) {
        Ok(age) if age >= RECENT => {
            let days = age.as_secs() / DAY.as_secs();
            Recommended(if days == 1 {
                "safe cache data, unchanged for 1 day".into()
            } else {
                format!("safe cache data, unchanged for {days} days")
            })
        }
        _ => NotRecommended("changed in the last 24 hours; may be in use".into()),
    }
}

pub fn is_recommended(c: &Candidate, now: SystemTime) -> bool {
    recommend(c, now).is_recommended()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustclean_safety::FileFingerprint;
    use std::path::PathBuf;

    fn cand(class: SafetyClass, modified: Option<SystemTime>) -> Candidate {
        Candidate {
            path: PathBuf::from("/h/c/f"),
            size: 1,
            disk_usage: 1,
            category: "C".into(),
            context: None,
            class,
            reason: None,
            fingerprint: FileFingerprint {
                size: 1,
                modified,
                inode: 0,
                device: 0,
            },
            target_root: PathBuf::from("/h/c"),
        }
    }

    #[test]
    fn only_old_safe_files_are_recommended() {
        let now = SystemTime::now();
        let old = Some(now - 10 * DAY);
        let r = recommend(&cand(SafetyClass::Safe, old), now);
        assert!(r.is_recommended());
        assert!(r.reason().contains("10 days"));
        assert!(is_recommended(
            &cand(SafetyClass::Safe, Some(now - DAY)),
            now
        ));
        for (class, m) in [
            (SafetyClass::Safe, Some(now - Duration::from_secs(3600))),
            (SafetyClass::Safe, Some(now + DAY)), // clock skew: future mtime
            (SafetyClass::Safe, None),
            (SafetyClass::Review, old),
            (SafetyClass::Unknown, old),
            (SafetyClass::Protected, old),
        ] {
            assert!(!is_recommended(&cand(class, m), now), "{class:?} {m:?}");
        }
    }
}
