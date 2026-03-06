# Windows Cleanup CLI (DiskCleaner)

A fast, safe, and aggressive Windows command-line utility designed to reclaim disk space on your C: drive without reinstalling Windows.

## 🚀 Features

- **Multi-threaded Scanning**: Lightning fast scanning using Rust's Rayon library.
- **Aggressive Deep Scan**: Targets obscure system caches, delivery optimization files, thumbnail databases, and the Recycle Bin.
- **Large File Analysis**: Scans your entire drive to identify the top space-consuming files (>100MB), helping you find hidden bloat.
- **Risk Assessment System**: Every cleaning rule is categorized by safety level:
    - ✅ **Safe to Delete**: Temporary files and logs that are safe for everyone.
    - ⚠️ **Caution**: System caches that might slightly affect app startup speed or update rollbacks.
    - 🛑 **Warning**: Files like the Recycle Bin or Prefetch that require user verification.
- **Safe by Design**: Uses a strict whitelist approach to ensure critical system files are never touched.
- **Noisy Log Suppression**: Gracefully handles files currently in use or protected by the system, providing a clean summary instead of terminal noise.

## 🛠 Installation

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)

### Build from source
```powershell
git clone https://github.com/yourusername/Windows-Cleanup-Cli.git
cd Windows-Cleanup-Cli
cargo build --release
```
The executable will be located at `target/release/windows-cleanup-cli.exe`.

## 📖 Usage

> [!IMPORTANT]
> Some operations require Administrator privileges to access system logs and the Recycle Bin. Run your terminal as Admin for the best results.

### 1. Basic Scan
Quickly identify common temporary files.
```powershell
.\windows-cleanup-cli.exe scan
```

### 2. Deep Scan (Aggressive)
Find significantly more space by targeting hidden system caches.
```powershell
.\windows-cleanup-cli.exe deep-scan
```

### 3. Analyze Drive
Find the largest files taking up space on your C: drive.
```powershell
# Show top 20 large files
.\windows-cleanup-cli.exe analyze

# Export full report to a text file
.\windows-cleanup-cli.exe analyze --output report.txt
```

### 4. Clean Disk
Safely delete the discovered files with risk-level confirmation.
```powershell
.\windows-cleanup-cli.exe clean

# Automatically confirm all prompt
.\windows-cleanup-cli.exe clean --auto
```

## 🛡 Security & Safety
DiskCleaner only interacts with specific, whitelisted directories. It does not perform "black magic" on your registry or critical system components. It is designed to be a transparent and reliable alternative to built-in Windows cleanup tools.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
