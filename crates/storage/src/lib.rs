//! Storage engine: folder-size analysis and the large-file finder.

pub mod analyzer;
pub mod large_files;

pub use analyzer::{FolderSize, folder_sizes};
pub use large_files::{
    DataFileClassifier, LargeFilesModule, data_file_reason, file_kind, personal_roots,
};
