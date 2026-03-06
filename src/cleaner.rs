use crate::rules::SafetyLevel;
use crate::scanner::ScanResult;
use colored::Colorize;
use human_bytes::human_bytes;
use std::fs;
use std::io::{self, Write};

pub struct Cleaner {
    dry_run: bool,
    auto_confirm: bool,
}

impl Cleaner {
    pub fn new(dry_run: bool, auto_confirm: bool) -> Self {
        Self {
            dry_run,
            auto_confirm,
        }
    }

    pub fn clean(&self, results: &[ScanResult]) -> io::Result<()> {
        let mut total_freed = 0;
        let mut total_files = 0;
        let mut skipped_in_use = 0;
        let mut skipped_access_denied = 0;

        for res in results {
            if res.files.is_empty() {
                continue;
            }

            let level_str = match res.safety_level {
                SafetyLevel::Safe => "[Safe to Delete]".green(),
                SafetyLevel::Caution => "[Caution]".yellow(),
                SafetyLevel::Warning => "[Warning]".red().bold(),
            };

            println!("\nCleaning: {} {}", res.rule_name.bold(), level_str);

            if !self.auto_confirm {
                print!(
                    "Proceed with cleaning {} files ({})? [y/N]: ",
                    res.files.len(),
                    human_bytes(res.total_size as f64)
                );
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                if input.trim().to_lowercase() != "y" {
                    println!("Skipping {}", res.rule_name);
                    continue;
                }
            }

            for file in &res.files {
                if self.dry_run {
                    println!("DRY RUN: Would delete {}", file.path.display());
                    total_freed += file.size;
                    total_files += 1;
                } else {
                    match fs::remove_file(&file.path) {
                        Ok(_) => {
                            total_freed += file.size;
                            total_files += 1;
                        }
                        Err(e) => {
                            if let Some(code) = e.raw_os_error() {
                                if code == 32 {
                                    skipped_in_use += 1;
                                } else if code == 5 {
                                    skipped_access_denied += 1;
                                } else {
                                    eprintln!(
                                        "{} Failed to delete {}: {}",
                                        "Error:".red(),
                                        file.path.display(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        println!("\n{}", "Cleanup Summary".bold().green());
        println!("{:-<30}", "");
        println!("Files deleted:      {}", total_files);
        println!(
            "Space freed:       {}",
            human_bytes(total_freed as f64).cyan()
        );

        if skipped_in_use > 0 || skipped_access_denied > 0 {
            println!("{:-<30}", "");
            if skipped_in_use > 0 {
                println!(
                    "Files skipped (In Use): {}",
                    skipped_in_use.to_string().yellow()
                );
            }
            if skipped_access_denied > 0 {
                println!(
                    "Files skipped (Access Denied): {}",
                    skipped_access_denied.to_string().red()
                );
                println!(
                    "{} Try running the terminal as Administrator to clean more files.",
                    "Tip:".blue()
                );
            }
        }

        Ok(())
    }
}
