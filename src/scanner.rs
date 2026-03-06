use crate::rules::{CleanupRule, SafetyLevel};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub rule_name: String,
    pub safety_level: SafetyLevel,
    pub files: Vec<FileInfo>,
    pub total_size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
}

pub struct Scanner {
    rules: Vec<CleanupRule>,
}

impl Scanner {
    pub fn new(rules: Vec<CleanupRule>) -> Self {
        Self { rules }
    }

    pub fn scan(&self, deep: bool) -> Vec<ScanResult> {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg} {pos} items found")
                .unwrap(),
        );
        pb.set_message(if deep {
            "Deep Scanning..."
        } else {
            "Scanning..."
        });

        let rules = self.rules.clone();

        rules
            .into_par_iter()
            .map(|rule| {
                let mut results = ScanResult {
                    rule_name: rule.name.clone(),
                    safety_level: rule.safety_level.clone(),
                    files: Vec::new(),
                    total_size: 0,
                };

                let is_recursive = rule.recursive_search.unwrap_or(false);

                for root_path in &rule.paths {
                    if !root_path.exists() {
                        continue;
                    }

                    if is_recursive {
                        WalkDir::new(root_path)
                            .into_iter()
                            .filter_map(|e| e.ok())
                            .for_each(|entry| {
                                if entry.file_type().is_dir() {
                                    let folder_name = entry.file_name().to_string_lossy();
                                    if rule.patterns.contains(&folder_name.to_string()) {
                                        let size = self.calculate_dir_size(entry.path());
                                        results.total_size += size;
                                        results.files.push(FileInfo {
                                            path: entry.path().to_path_buf(),
                                            size,
                                        });
                                        pb.inc(1);
                                    }
                                }
                            });
                    } else {
                        // Standard file pattern search
                        for entry in WalkDir::new(root_path).follow_links(false).into_iter() {
                            match entry {
                                Ok(entry) => {
                                    if entry.file_type().is_file() {
                                        let file_name = entry.file_name().to_string_lossy();

                                        // Simple pattern matching: if "*" or matches any pattern
                                        let matches = rule.patterns.contains(&"*".to_string())
                                            || rule.patterns.iter().any(|p| {
                                                if p.contains('*') {
                                                    // Very basic glob: starts_with or ends_with
                                                    let clean_p = p.replace('*', "");
                                                    if p.starts_with('*') {
                                                        file_name.ends_with(&clean_p)
                                                    } else {
                                                        file_name.starts_with(&clean_p)
                                                    }
                                                } else {
                                                    file_name == *p
                                                }
                                            });

                                        if matches {
                                            if let Ok(metadata) = entry.metadata() {
                                                let size = metadata.len();
                                                results.total_size += size;
                                                results.files.push(FileInfo {
                                                    path: entry.path().to_path_buf(),
                                                    size,
                                                });
                                                pb.inc(1);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Log access errors for debugging (visible if user looks closely)
                                    // This helps identify "Access Denied" on Prefetch etc.
                                    if let Some(inner) = e.io_error() {
                                        if inner.kind() == std::io::ErrorKind::PermissionDenied {
                                            // Silently skip but we could track this if needed
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                results
            })
            .collect()
    }

    fn calculate_dir_size(&self, path: &Path) -> u64 {
        WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    }

    pub fn scan_large_files(&self, min_size: u64) -> Vec<FileInfo> {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template(
                    "{spinner:.yellow} [{elapsed_precise}] Searching for large files... {pos}",
                )
                .unwrap(),
        );

        let large_files = Arc::new(Mutex::new(Vec::new()));

        let skip_dirs = vec![
            r"C:\Windows\WinSxS",
            r"C:\Windows\System32",
            r"C:\Program Files\WindowsApps",
        ];

        WalkDir::new(r"C:\")
            .into_iter()
            .filter_entry(|e| {
                let path = e.path().to_string_lossy();
                !skip_dirs.iter().any(|d| path.starts_with(d))
            })
            .filter_map(|e| e.ok())
            .for_each(|entry| {
                if entry.file_type().is_file() {
                    if let Ok(metadata) = entry.metadata() {
                        let size = metadata.len();
                        if size > min_size {
                            large_files.lock().unwrap().push(FileInfo {
                                path: entry.path().to_path_buf(),
                                size,
                            });
                        }
                    }
                }
                pb.inc(1);
            });

        let mut results = Arc::try_unwrap(large_files).unwrap().into_inner().unwrap();
        results.sort_by(|a, b| b.size.cmp(&a.size));
        results
    }

    pub fn find_duplicates(&self, min_size: u64) -> HashMap<String, Vec<FileInfo>> {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template(
                    "{spinner:.cyan} [{elapsed_precise}] Hashing potential duplicates... {pos}",
                )
                .unwrap(),
        );

        // Group by size first to avoid unnecessary hashing
        let mut size_groups: HashMap<u64, Vec<PathBuf>> = HashMap::new();

        let skip_dirs = vec![
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ];

        WalkDir::new(r"C:\")
            .into_iter()
            .filter_entry(|e| {
                let path = e.path().to_string_lossy();
                !skip_dirs.iter().any(|d| path.starts_with(d))
            })
            .filter_map(|e| e.ok())
            .for_each(|entry| {
                if entry.file_type().is_file() {
                    if let Ok(metadata) = entry.metadata() {
                        let size = metadata.len();
                        if size > min_size {
                            size_groups
                                .entry(size)
                                .or_default()
                                .push(entry.path().to_path_buf());
                        }
                    }
                }
                pb.inc(1);
            });

        let duplicates = Arc::new(Mutex::new(HashMap::new()));

        size_groups
            .into_par_iter()
            .filter(|(_, paths)| paths.len() > 1)
            .for_each(|(size, paths)| {
                let mut hash_groups: HashMap<String, Vec<FileInfo>> = HashMap::new();
                for path in paths {
                    if let Ok(hash) = self.hash_file(&path) {
                        hash_groups
                            .entry(hash)
                            .or_default()
                            .push(FileInfo { path, size });
                    }
                }

                let mut guard = duplicates.lock().unwrap();
                for (hash, files) in hash_groups {
                    if files.len() > 1 {
                        guard.insert(hash, files);
                    }
                }
            });

        Arc::try_unwrap(duplicates).unwrap().into_inner().unwrap()
    }

    fn hash_file(&self, path: &Path) -> io::Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 65536]; // 64KB buffer

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }
}
