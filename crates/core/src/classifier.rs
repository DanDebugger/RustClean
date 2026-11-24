//! File classification into SAFE / REVIEW / PROTECTED / UNKNOWN.

use std::path::Path;

use rustclean_safety::ProtectionRules;
use serde::{Deserialize, Serialize};

use crate::scanner::ScanTarget;

/// Safety classification of a discovered file.
///
/// Variants are ordered from least to most restrictive, so combining two
/// classifications is `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SafetyClass {
    /// Eligible for cleanup.
    Safe,
    /// Eligible only with additional, explicit confirmation.
    Review,
    /// Must not be automatically deleted; cannot be selected.
    Unknown,
    /// Can never be deleted.
    Protected,
}

impl SafetyClass {
    pub fn label(self) -> &'static str {
        match self {
            SafetyClass::Safe => "Safe",
            SafetyClass::Review => "Review",
            SafetyClass::Unknown => "Unknown",
            SafetyClass::Protected => "Protected",
        }
    }

    /// Whether a user may select this file for cleanup at all.
    pub fn is_selectable(self) -> bool {
        matches!(self, SafetyClass::Safe | SafetyClass::Review)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub class: SafetyClass,
    pub reason: Option<String>,
}

impl Classification {
    pub fn new(class: SafetyClass, reason: impl Into<Option<String>>) -> Self {
        Self {
            class,
            reason: reason.into(),
        }
    }

    /// Returns the more restrictive of two classifications.
    pub fn most_restrictive(self, other: Classification) -> Classification {
        if other.class > self.class {
            other
        } else {
            self
        }
    }
}

/// Domain-specific classification (e.g. Chrome's protected profile data).
pub trait Classifier: Send + Sync {
    fn classify(&self, path: &Path, is_symlink: bool, target: &ScanTarget) -> Classification;
}

/// Rules that apply to every scan regardless of domain: protected
/// locations, symlinks, and the target's default class.
pub struct BaseClassifier {
    rules: ProtectionRules,
}

impl BaseClassifier {
    pub fn new(rules: ProtectionRules) -> Self {
        Self { rules }
    }
}

impl Classifier for BaseClassifier {
    fn classify(&self, path: &Path, is_symlink: bool, target: &ScanTarget) -> Classification {
        if let Some(reason) = self.rules.protection_reason(path) {
            return Classification::new(SafetyClass::Protected, reason);
        }
        if is_symlink {
            return Classification::new(SafetyClass::Unknown, "symbolic link".to_string());
        }
        if !path.starts_with(&target.root) {
            return Classification::new(SafetyClass::Unknown, "outside scan target".to_string());
        }
        Classification::new(target.default_class, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn target(root: &str) -> ScanTarget {
        ScanTarget::new("Test", PathBuf::from(root), SafetyClass::Safe)
    }

    #[test]
    fn most_restrictive_wins() {
        let safe = Classification::new(SafetyClass::Safe, None);
        let prot = Classification::new(SafetyClass::Protected, "x".to_string());
        assert_eq!(
            safe.clone().most_restrictive(prot.clone()).class,
            SafetyClass::Protected
        );
        assert_eq!(prot.most_restrictive(safe).class, SafetyClass::Protected);
    }

    #[test]
    fn base_classifier_rules() {
        let c = BaseClassifier::new(ProtectionRules::for_home("/Users/a"));
        let t = target("/Users/a/Library/Caches/X");
        assert_eq!(
            c.classify(Path::new("/Users/a/Library/Caches/X/f"), false, &t)
                .class,
            SafetyClass::Safe
        );
        assert_eq!(
            c.classify(Path::new("/Users/a/Library/Caches/X/l"), true, &t)
                .class,
            SafetyClass::Unknown
        );
        assert_eq!(
            c.classify(Path::new("/Users/a/Documents/f"), false, &t)
                .class,
            SafetyClass::Protected
        );
        assert_eq!(
            c.classify(Path::new("/Users/a/Library/Caches/Y/f"), false, &t)
                .class,
            SafetyClass::Unknown
        );
    }
}
