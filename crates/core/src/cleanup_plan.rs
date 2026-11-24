//! Cleanup plans: the only bridge between a scan and a cleanup.
//!
//! A [`CleanupPlan`] is built from user-selected candidates. It cannot be
//! executed until it is turned into an [`ApprovedPlan`] by
//! [`CleanupPlan::approve`], which is the code-level record of the user's
//! explicit confirmation.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rustclean_safety::{FileFingerprint, RemovalMethod};
use thiserror::Error;

use crate::classifier::SafetyClass;
use crate::scanner::Candidate;

#[derive(Debug, Clone)]
pub struct PlannedItem {
    pub path: PathBuf,
    pub fingerprint: FileFingerprint,
    pub size: u64,
    pub disk_usage: u64,
    pub category: String,
    pub class: SafetyClass,
    pub approved_root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CleanupPlan {
    items: Vec<PlannedItem>,
    /// Selected items that were refused (Protected/Unknown), with reasons.
    rejected: Vec<(PathBuf, String)>,
    pub method: RemovalMethod,
    pub dry_run: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("nothing selected for cleanup")]
    Empty,
    #[error("{0} selected file(s) need review; confirm them explicitly")]
    ReviewNotAcknowledged(usize),
}

impl CleanupPlan {
    /// Builds a plan from selected candidates. Files that are not selectable
    /// (Protected, Unknown) are never included, whatever the selection says.
    pub fn from_selection<'a>(
        selected: impl IntoIterator<Item = &'a Candidate>,
        method: RemovalMethod,
        dry_run: bool,
    ) -> Self {
        let mut items = Vec::new();
        let mut rejected = Vec::new();
        for c in selected {
            if c.class.is_selectable() {
                items.push(PlannedItem {
                    path: c.path.clone(),
                    fingerprint: c.fingerprint,
                    size: c.size,
                    disk_usage: c.disk_usage,
                    category: c.category.clone(),
                    class: c.class,
                    approved_root: c.target_root.clone(),
                });
            } else {
                rejected.push((c.path.clone(), format!("classified {}", c.class.label())));
            }
        }
        Self {
            items,
            rejected,
            method,
            dry_run,
        }
    }

    pub fn items(&self) -> &[PlannedItem] {
        &self.items
    }

    pub fn rejected(&self) -> &[(PathBuf, String)] {
        &self.rejected
    }

    pub fn review_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.class == SafetyClass::Review)
            .count()
    }

    pub fn total_size(&self) -> u64 {
        self.items.iter().map(|i| i.size).sum()
    }

    pub fn total_disk_usage(&self) -> u64 {
        self.items.iter().map(|i| i.disk_usage).sum()
    }

    pub fn approved_roots(&self) -> BTreeSet<PathBuf> {
        self.items.iter().map(|i| i.approved_root.clone()).collect()
    }

    /// Records the user's explicit confirmation. Plans containing
    /// Review-class files additionally require `review_acknowledged`.
    pub fn approve(self, review_acknowledged: bool) -> Result<ApprovedPlan, PlanError> {
        if self.items.is_empty() {
            return Err(PlanError::Empty);
        }
        let review = self.review_count();
        if review > 0 && !review_acknowledged {
            return Err(PlanError::ReviewNotAcknowledged(review));
        }
        Ok(ApprovedPlan { plan: self })
    }
}

/// A plan the user explicitly confirmed. Only constructible via
/// [`CleanupPlan::approve`].
#[derive(Debug, Clone)]
pub struct ApprovedPlan {
    plan: CleanupPlan,
}

impl std::ops::Deref for ApprovedPlan {
    type Target = CleanupPlan;
    fn deref(&self) -> &CleanupPlan {
        &self.plan
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn candidate(path: &str, class: SafetyClass) -> Candidate {
        Candidate {
            path: PathBuf::from(path),
            size: 10,
            disk_usage: 4096,
            category: "Cat".into(),
            context: None,
            class,
            reason: None,
            fingerprint: FileFingerprint {
                size: 10,
                modified: None,
                inode: 1,
                device: 1,
            },
            target_root: PathBuf::from("/root"),
        }
    }

    #[test]
    fn protected_and_unknown_are_never_planned() {
        let cs = [
            candidate("/root/a", SafetyClass::Safe),
            candidate("/root/b", SafetyClass::Protected),
            candidate("/root/c", SafetyClass::Unknown),
        ];
        let plan = CleanupPlan::from_selection(&cs, RemovalMethod::Trash, true);
        assert_eq!(plan.items().len(), 1);
        assert_eq!(plan.rejected().len(), 2);
    }

    #[test]
    fn empty_plan_cannot_be_approved() {
        let cs = [candidate("/root/b", SafetyClass::Protected)];
        let plan = CleanupPlan::from_selection(&cs, RemovalMethod::Trash, false);
        assert_eq!(plan.approve(true).unwrap_err(), PlanError::Empty);
    }

    #[test]
    fn review_items_need_acknowledgement() {
        let cs = [
            candidate("/root/a", SafetyClass::Safe),
            candidate("/root/r", SafetyClass::Review),
        ];
        let plan = CleanupPlan::from_selection(&cs, RemovalMethod::Trash, false);
        assert_eq!(
            plan.clone().approve(false).unwrap_err(),
            PlanError::ReviewNotAcknowledged(1)
        );
        assert!(plan.approve(true).is_ok());
    }
}
