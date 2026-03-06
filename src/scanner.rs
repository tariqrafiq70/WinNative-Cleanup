use crate::rules::{CleanupRule, SafetyLevel};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Serialize;
use std::path::PathBuf;
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
                .template("{spinner:.green} [{elapsed_precise}] {msg} {pos} files found")
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

                for root_path in rule.paths {
                    if !root_path.exists() {
                        continue;
                    }

                    for entry in WalkDir::new(&root_path)
                        .follow_links(false)
                        .into_iter()
                        .filter_map(|e| e.ok())
                    {
                        if entry.file_type().is_file() {
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
                results
            })
            .collect()
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
}
