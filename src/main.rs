mod cleaner;
mod rules;
mod scanner;
mod tui;

use crate::scanner::FileInfo;
use crate::tui::TuiApp;
use clap::{Parser, Subcommand};
use cleaner::Cleaner;
use colored::Colorize;
use human_bytes::human_bytes;
use rules::{get_rules, SafetyLevel};
use scanner::Scanner;
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "diskcleaner")]
#[command(about = "V2: Advanced Windows Optimization Suite", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan the C drive and identify safe-to-delete files
    Scan,
    /// Detailed report of recoverable space
    Report {
        /// Export report to JSON
        #[arg(short, long)]
        json: bool,
    },
    /// Clean discovered files
    Clean {
        /// Show what would be deleted without actually deleting
        #[arg(short, long)]
        dry_run: bool,
        /// Automatically confirm deletion
        #[arg(short, long)]
        auto: bool,
    },
    /// Perform an aggressive deep scan for more space (includes Recycle Bin, etc.)
    DeepScan,
    /// Analyze the C drive for large files (>100MB)
    Analyze {
        /// Minimum file size in MB to report (default: 100)
        #[arg(short, long, default_value_t = 100)]
        min_size: u64,
        /// Export results to a file (txt or json)
        #[arg(short, long)]
        output: Option<String>,
        /// Export results as JSON
        #[arg(short, long)]
        json: bool,
    },
    /// Find and remove duplicate files (hashing-based)
    Dedupe {
        /// Minimum file size in MB to consider (default: 10)
        #[arg(short, long, default_value_t = 10)]
        min_size: u64,
    },
    /// Advanced system optimization (CompactOS, Windows.old)
    Optimize,
    /// Interactive Dashboard (TUI Mode)
    Dashboard,
    /// Schedule a weekly safe cleanup task
    Schedule,
}

fn is_admin() -> bool {
    std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn main() {
    let cli = Cli::parse();

    if !is_admin() {
        println!(
            "{}",
            "⚠ Warning: Not running as Administrator. Some system locations may be skipped."
                .yellow()
        );
    }

    let rules = get_rules();
    let scanner = Scanner::new(rules);

    match cli.command {
        Commands::Scan => {
            println!("{}", "Starting Standard Scan...".bold().green());
            let results = scanner.scan(false);
            display_scan_results(&results);
            prompt_for_dashboard(&scanner);
        }
        Commands::DeepScan => {
            println!("{}", "Starting Aggressive Deep Scan...".bold().magenta());
            let results = scanner.scan(true);
            display_scan_results(&results);
            prompt_for_dashboard(&scanner);
        }
        Commands::Report { json } => {
            let results = scanner.scan(false);
            if json {
                println!("{}", serde_json::to_string_pretty(&results).unwrap());
            } else {
                println!("{}", "Generating Detailed Report...".bold().green());
                for res in results {
                    if res.total_size == 0 {
                        continue;
                    }
                    let level_str = format_safety_level(&res.safety_level);
                    println!(
                        "\n{} [{}] ({})",
                        res.rule_name.bold().cyan(),
                        level_str,
                        human_bytes(res.total_size as f64)
                    );
                    for file in res.files.iter().take(10) {
                        println!("  {}", file.path.display());
                    }
                    if res.files.len() > 10 {
                        println!("  ... and {} more files", res.files.len() - 10);
                    }
                }
            }
        }
        Commands::Clean { dry_run, auto } => {
            let results = scanner.scan(true);
            let cleaner = Cleaner::new(dry_run, auto);
            if let Err(e) = cleaner.clean(&results) {
                eprintln!("{} Fatal error during cleaning: {}", "Error:".red(), e);
            }
        }
        Commands::Dedupe { min_size } => {
            println!(
                "{}",
                "Finding duplicate files using SHA256 hashing..."
                    .bold()
                    .cyan()
            );
            let duplicates = scanner.find_duplicates(min_size * 1024 * 1024);
            display_duplicates(&duplicates);
        }
        Commands::Optimize => {
            println!(
                "{}",
                "Checking for advanced system optimizations..."
                    .bold()
                    .yellow()
            );
            let results = scanner.scan(true);
            let opt_results: Vec<_> = results
                .into_iter()
                .filter(|r| r.rule_name == "Windows.old" || r.rule_name == "System Memory Dumps")
                .collect();

            if opt_results.is_empty() {
                println!(
                    "{}",
                    "No system-level optimizations found currently.".green()
                );
            } else {
                display_scan_results(&opt_results);
                println!(
                    "\n{} Run 'clean' to apply these optimizations.",
                    "Tip:".blue()
                );
            }
        }
        Commands::Analyze {
            min_size,
            output,
            json,
        } => {
            println!(
                "{}",
                format!("Searching for files larger than {} MB...", min_size)
                    .bold()
                    .yellow()
            );
            println!(
                "{}",
                "⚠ CAUTION: These files are NOT automatically classified as safe. Review manually!"
                    .on_red()
                    .white()
                    .bold()
            );

            let large_files = scanner.scan_large_files(min_size * 1024 * 1024);

            if let Some(file_path) = output {
                let mut content = String::new();
                if json {
                    content = serde_json::to_string_pretty(&large_files).unwrap();
                } else {
                    content.push_str(&format!("Large Files Report (> {} MB)\n", min_size));
                    content.push_str("RISK ASSESSMENT: These files were identified by size, not safety rules. Delete with caution.\n");
                    content.push_str(&format!("{:-<80}\n", ""));
                    content.push_str(&format!("{:<15} {:<}\n", "Size", "Path"));
                    for file in &large_files {
                        content.push_str(&format!(
                            "{:<15} {:<}\n",
                            human_bytes(file.size as f64),
                            file.path.display()
                        ));
                    }
                }

                match std::fs::write(&file_path, content) {
                    Ok(_) => println!(
                        "{} Full report written to: {}",
                        "Success:".green(),
                        file_path
                    ),
                    Err(e) => eprintln!("{} Failed to write report: {}", "Error:".red(), e),
                }
            } else {
                if json {
                    println!("{}", serde_json::to_string_pretty(&large_files).unwrap());
                } else {
                    println!("\n{:<15} {:<}", "Size".bold(), "Path".bold());
                    println!("{:-<60}", "");

                    for file in large_files.iter().take(20) {
                        println!(
                            "{:<15} {:<}",
                            human_bytes(file.size as f64).cyan(),
                            file.path.display()
                        );
                    }

                    if large_files.len() > 20 {
                        println!(
                            "\n... showing top 20 of {} large files found.",
                            large_files.len()
                        );
                    }
                }
            }
        }
        Commands::Dashboard => {
            println!("{}", "Launching Interactive Dashboard...".bold().cyan());
            let results = scanner.scan(true);
            let mut app = TuiApp::new(results);
            if let Err(e) = app.run() {
                eprintln!("{} TUI error: {}", "Error:".red(), e);
            } else {
                let selected = app.get_selected_results();
                if !selected.is_empty() {
                    println!("\nPreparing to clean selected categories...");
                    // auto_confirm = true because user already selected them in TUI
                    let cleaner = Cleaner::new(false, true);
                    if let Err(e) = cleaner.clean(&selected) {
                        eprintln!("{} Cleaning error: {}", "Error:".red(), e);
                    }
                }
            }
        }
        Commands::Schedule => {
            println!(
                "{}",
                "Scheduling a weekly safe cleanup task...".bold().green()
            );
            let exe_path = std::env::current_exe().unwrap();
            let script = format!(
                "$Action = New-ScheduledTaskAction -Execute '{}' -Argument 'clean --auto'; \
                 $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 11pm; \
                 Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName 'WinNativeCleanup' -Description 'Automated Disk Cleanup' -Force",
                exe_path.display()
            );

            match powershell_script::run(&script) {
                Ok(_) => println!(
                    "{}",
                    "Success: Task scheduled for every Sunday at 11 PM."
                        .green()
                        .bold()
                ),
                Err(e) => eprintln!(
                    "{} Failed to schedule task: {}. (Admin required)",
                    "Error:".red(),
                    e
                ),
            }
        }
    }
}

fn prompt_for_dashboard(scanner: &Scanner) {
    println!(
        "\n{} Press {} to open the Interactive Dashboard or {} to skip.",
        "Note:".blue().bold(),
        "Y".green().bold(),
        "N".red().bold()
    );

    use crossterm::event::{self, Event, KeyCode, KeyEventKind};

    loop {
        if let Ok(Event::Key(key)) = event::read() {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        println!("{}", "Launching Interactive Dashboard...".bold().cyan());
                        let results = scanner.scan(true);
                        let mut app = TuiApp::new(results);
                        if let Err(e) = app.run() {
                            eprintln!("{} TUI error: {}", "Error:".red(), e);
                        } else {
                            let selected = app.get_selected_results();
                            if !selected.is_empty() {
                                println!("\nPreparing to clean selected categories...");
                                // auto_confirm = true because user already selected them in TUI
                                let cleaner = Cleaner::new(false, true);
                                if let Err(e) = cleaner.clean(&selected) {
                                    eprintln!("{} Cleaning error: {}", "Error:".red(), e);
                                }
                            }
                        }
                        break;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        println!("Exiting.");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn format_safety_level(level: &SafetyLevel) -> String {
    match level {
        SafetyLevel::Safe => "Safe to Delete".green().to_string(),
        SafetyLevel::Caution => "Caution".yellow().to_string(),
        SafetyLevel::Warning => "Warning".red().bold().to_string(),
    }
}

fn get_level_width(level: &SafetyLevel) -> usize {
    match level {
        SafetyLevel::Safe => 14,
        SafetyLevel::Caution => 7,
        SafetyLevel::Warning => 7,
    }
}

fn display_scan_results(results: &[scanner::ScanResult]) {
    let mut total: u64 = 0;

    println!(
        "\n{:<35} {:<20} {:<15}",
        "Category".bold(),
        "Risk Level".bold(),
        "Recoverable".bold()
    );
    println!("{:-<75}", "");

    for res in results {
        total += res.total_size;

        let level_str = format_safety_level(&res.safety_level);
        let level_width = get_level_width(&res.safety_level);
        let level_padding = " ".repeat(20 - level_width);

        let size_raw = human_bytes(res.total_size as f64);
        let size_str = format!("{:<15}", size_raw).cyan();

        println!(
            "{:<35} {}{} {}",
            res.rule_name, level_str, level_padding, size_str
        );
    }

    println!("{:-<75}", "");
    println!(
        "{:<35} {:<20} {}",
        "Total".bold(),
        "",
        human_bytes(total as f64).green().bold()
    );
}

fn display_duplicates(duplicates: &HashMap<String, Vec<FileInfo>>) {
    if duplicates.is_empty() {
        println!("{}", "No duplicate files found.".green());
        return;
    }

    let mut total_potential_saving = 0;
    println!("\n{:<15} {:<}", "Space", "Original/Duplicates");
    println!("{:-<70}", "");

    for (_, files) in duplicates {
        let size = files[0].size;
        total_potential_saving += size * (files.len() as u64 - 1);

        println!(
            "{:<15} {}",
            human_bytes(size as f64).cyan(),
            files[0].path.display().to_string().bold()
        );
        for i in 1..files.len() {
            println!("{:<15} └── {}", "", files[i].path.display());
        }
        println!();
    }

    println!("{:-<70}", "");
    println!(
        "Total potential saving: {}",
        human_bytes(total_potential_saving as f64).green().bold()
    );
    println!(
        "{} Manual review is required before deleting duplicates.",
        "Warning:".red().bold()
    );
}
