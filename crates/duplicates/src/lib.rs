//! Duplicate file finder.

pub mod finder;

pub use finder::{DuplicateGroup, DuplicatesModule, find_duplicates, mark_duplicates};
