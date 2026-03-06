use serde::Serialize;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum SafetyLevel {
    Safe,    // No impact on system or user data
    Caution, // Useful for rollbacks or slightly slower app starts
    Warning, // May delete data some users expect to keep (e.g. Recycle Bin)
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct CleanupRule {
    pub name: String,
    pub description: String,
    pub paths: Vec<PathBuf>,
    pub patterns: Vec<String>,
    pub safety_level: SafetyLevel,
}

pub fn get_rules() -> Vec<CleanupRule> {
    let mut rules = Vec::new();

    // Windows Temp
    rules.push(CleanupRule {
        name: "Windows Temp".to_string(),
        description: "Standard Windows temporary files".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows\Temp")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Safe,
    });

    // User Temp
    if let Ok(temp) = env::var("TEMP") {
        rules.push(CleanupRule {
            name: "User Temp".to_string(),
            description: "User-specific temporary files".to_string(),
            paths: vec![PathBuf::from(temp)],
            patterns: vec!["*".to_string()],
            safety_level: SafetyLevel::Safe,
        });
    }

    // Windows Update Cache
    rules.push(CleanupRule {
        name: "Windows Update Cache".to_string(),
        description: "Downloaded Windows updates that are already installed".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows\SoftwareDistribution\Download")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Caution,
    });

    // Delivery Optimization
    rules.push(CleanupRule {
        name: "Delivery Optimization Cache".to_string(),
        description: "Windows Update Peer-to-Peer download cache".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Caution,
    });

    // Recycle Bin
    rules.push(CleanupRule {
        name: "Recycle Bin".to_string(),
        description: "Deleted files currently in the recycle bin".to_string(),
        paths: vec![PathBuf::from(r"C:\$Recycle.Bin")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Warning,
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
    });

    // Prefetch (Requires Admin)
    rules.push(CleanupRule {
        name: "Prefetch".to_string(),
        description: "Application launch cache".to_string(),
        paths: vec![PathBuf::from(r"C:\Windows\Prefetch")],
        patterns: vec!["*".to_string()],
        safety_level: SafetyLevel::Warning,
    });

    // Application specific caches (Spotify example)
    if !local_appdata.is_empty() {
        let spotify_cache = Path::new(&local_appdata).join(r"Spotify\Storage");
        if spotify_cache.exists() {
            rules.push(CleanupRule {
                name: "Spotify Cache".to_string(),
                description: "Cached music and data for Spotify".to_string(),
                paths: vec![spotify_cache],
                patterns: vec!["*".to_string()],
                safety_level: SafetyLevel::Safe,
            });
        }
    }

    rules
}
