//! Folder-size analysis (read-only).

use std::fs;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use rustclean_core::Progress;
use rustclean_safety::platform;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct FolderSize {
    pub path: PathBuf,
    /// Bytes allocated on disk.
    pub size: u64,
    pub files: u64,
    /// Entries that could not be read (permissions).
    pub unreadable: u64,
    pub is_dir: bool,
}

/// Sizes of the direct children of `root`, largest first. Never follows
/// symlinks or crosses into another file system.
pub fn folder_sizes(root: &Path, progress: &Progress) -> Vec<FolderSize> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    let mut out: Vec<FolderSize> = children
        .par_iter()
        .filter_map(|child| {
            let meta = fs::symlink_metadata(child).ok()?;
            if meta.file_type().is_symlink() {
                return None;
            }
            if !meta.is_dir() {
                let size = platform::disk_usage(&meta);
                progress.add(1, size);
                return Some(FolderSize {
                    path: child.clone(),
                    size,
                    files: 1,
                    unreadable: 0,
                    is_dir: false,
                });
            }
            let mut fsz = FolderSize {
                path: child.clone(),
                size: 0,
                files: 0,
                unreadable: 0,
                is_dir: true,
            };
            for entry in WalkDir::new(child)
                .follow_links(false)
                .same_file_system(true)
            {
                if progress.is_cancelled() {
                    break;
                }
                match entry {
                    Ok(e) if e.file_type().is_file() => {
                        if let Ok(m) = e.metadata() {
                            let s = platform::disk_usage(&m);
                            fsz.size += s;
                            fsz.files += 1;
                            progress.add(1, s);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => fsz.unreadable += 1,
                }
            }
            Some(fsz)
        })
        .collect();
    out.sort_by(|a, b| b.size.cmp(&a.size));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_children_largest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let r = tmp.path();
        fs::create_dir_all(r.join("big/sub")).unwrap();
        fs::create_dir_all(r.join("small")).unwrap();
        fs::write(r.join("big/sub/a"), vec![1u8; 100_000]).unwrap();
        fs::write(r.join("small/b"), vec![1u8; 10]).unwrap();
        fs::write(r.join("file"), vec![1u8; 50_000]).unwrap();
        let sizes = folder_sizes(r, &Progress::new());
        let names: Vec<_> = sizes
            .iter()
            .map(|s| s.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["big", "file", "small"]);
        assert_eq!(sizes[0].files, 1);
        assert!(sizes[0].is_dir && !sizes[1].is_dir);
    }
}
