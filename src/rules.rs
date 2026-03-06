use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SafetyLevel {
    Safe,    // No impact on system or user data
    Caution, // Useful for rollbacks or slightly slower app starts
    Warning, // May delete data some users expect to keep (e.g. Recycle Bin)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CleanupRule {
    pub name: String,
    pub description: String,
    pub paths: Vec<PathBuf>,
    pub patterns: Vec<String>,
    pub safety_level: SafetyLevel,
    pub recursive_search: Option<bool>, // If true, search for 'patterns' as folder names recursively
}

pub fn get_rules() -> Vec<CleanupRule> {
    let mut rules = get_default_rules();

    // Load custom rules from the 'rules' directory
    if let Ok(entries) = fs::read_dir("rules") {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.path().extension().map_or(false, |ext| ext == "json") {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    if let Ok(mut custom_rules) = serde_json::from_str::<Vec<CleanupRule>>(&content)
                    {
                        rules.append(&mut custom_rules);
                    }
                }
            }
        }
    }

    rules
}

fn get_default_rules() -> Vec<CleanupRule> {
    let mut rules = Vec::new();

    // Windows Temp
    rules.push(CleanupRule {
        name: "Windows Temp".to_string(),
        description: "Standard Windows temporary files".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows\Temp")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Safe,
        recursive_search: Some(false),
    });

    // User Temp (%TEMP%)
    if let Ok(temp) = env::var("TEMP") {
        let temp_path = PathBuf::from(temp);
        if temp_path.exists() {
            rules.push(CleanupRule {
                name: "User Temp".to_string(),
                description: "User-specific temporary files".to_string(),
                paths: vec![temp_path],
                patterns: vec!["*".to_string()],
                safety_level: SafetyLevel::Safe,
                recursive_search: Some(false),
            });
        }
    }

    // Prefetch (Requires Admin)
    let prefetch = PathBuf::from(r"C:\Windows\Prefetch");
    if prefetch.exists() {
        rules.push(CleanupRule {
            name: "Prefetch".to_string(),
            description: "Application launch cache and prefetch files".to_string(),
            paths: vec![prefetch],
            patterns: vec!["*".to_string()],
            safety_level: SafetyLevel::Warning,
            recursive_search: Some(false),
        });
    }

    // Windows Update Cache
    rules.push(CleanupRule {
        name: "Windows Update Cache".to_string(),
        description: "Downloaded Windows updates that are already installed".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows\SoftwareDistribution\Download")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Caution,
        recursive_search: Some(false),
    });

    // Delivery Optimization
    rules.push(CleanupRule {
        name: "Delivery Optimization Cache".to_string(),
        description: "Windows Update Peer-to-Peer download cache".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Caution,
        recursive_search: Some(false),
    });

    // Recycle Bin
    rules.push(CleanupRule {
        name: "Recycle Bin".to_string(),
        description: "Deleted files currently in the recycle bin".to_string(),
        paths: vec![PathBuf::from(r"C:\$Recycle.Bin")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Warning,
        recursive_search: Some(false),
    });

    // Browser Caches
    let local_appdata = env::var("LOCALAPPDATA").unwrap_or_default();
    if !local_appdata.is_empty() {
        // Edge
        let edge_cache = Path::new(&local_appdata).join(r"Microsoft\Edge\User Data\Default\Cache");
        if edge_cache.exists() {
            rules.push(CleanupRule {
                name: "Edge Cache".to_string(),
                description: "Microsoft Edge browser cache".to_string(),
                paths: vec![edge_cache],
                patterns: vec!["*".to_string()],
                safety_level: SafetyLevel::Safe,
                recursive_search: Some(false),
            });
        }

        // Chrome
        let chrome_cache = Path::new(&local_appdata).join(r"Google\Chrome\User Data\Default\Cache");
        if chrome_cache.exists() {
            rules.push(CleanupRule {
                name: "Chrome Cache".to_string(),
                description: "Google Chrome browser cache".to_string(),
                paths: vec![chrome_cache],
                patterns: vec!["*".to_string()],
                safety_level: SafetyLevel::Safe,
                recursive_search: Some(false),
            });
        }

        // Thumbnail Cache
        let thumb_cache = Path::new(&local_appdata).join(r"Microsoft\Windows\Explorer");
        if thumb_cache.exists() {
            rules.push(CleanupRule {
                name: "Windows Thumbnail Cache".to_string(),
                description: "Cached thumbnails for images and videos".to_string(),
                paths: vec![thumb_cache],
                patterns: vec!["thumbcache_*.db".to_string()],
                safety_level: SafetyLevel::Caution,
                recursive_search: Some(false),
            });
        }
    }

    // Windows Log Files
    rules.push(CleanupRule {
        name: "System Logs".to_string(),
        description: "System and application log files".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows\Logs")],
        patterns: vec![
            "*.log".to_string(),
            "*.etl".to_string(),
            "*.cab".to_string(),
        ],
        safety_level: SafetyLevel::Safe,
        recursive_search: Some(false),
    });

    // Crash Dumps & Mini Dumps
    rules.push(CleanupRule {
        name: "Crash Dumps".to_string(),
        description: "System memory dumps from crashes".to_string(),
        paths: vec![
            PathBuf::from(r"C:\Windows\Minidump"),
            PathBuf::from(r"C:\Windows\LiveKernelReports"),
        ],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Warning,
        recursive_search: Some(false),
    });

    // Windows.old (Leftover from updates)
    rules.push(CleanupRule {
        name: "Windows.old".to_string(),
        description: "Backups of previous Windows installations".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows.old")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Caution,
        recursive_search: Some(false),
    });

    // System Error Memory Dumps
    rules.push(CleanupRule {
        name: "System Memory Dumps".to_string(),
        description: "Memory dump files from system crashes".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows\MEMORY.DMP")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Warning,
        recursive_search: Some(false),
    });

    rules
}
