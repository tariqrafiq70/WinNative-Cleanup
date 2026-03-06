# WinNative-Cleanup V2 (Advanced Edition) 🚀

A high-performance, premium Windows optimization suite built in Rust. WinNative-Cleanup V2 goes beyond simple temporary file deletion, offering advanced deduplication, system optimization, and an interactive TUI dashboard.

![v2_dashboard](https://via.placeholder.com/800x450.png?text=WinNative-Cleanup+V2+Interactive+Dashboard)

## 🌟 New in V2

- **Interactive Dashboard (TUI)**: A full-screen graphical terminal interface to navigate, select, and clean your drive.
- **Deep Deduplication**: Identify identical files across your system using SHA256 hashing.
- **Developer Packs**: Recursive scanning for `node_modules`, Rust `target` folders, and build artifacts.
- **System Optimization**: Safe removal of `Windows.old`, kernel memory dumps, and Windows Update leftovers.
- **Plugin System**: Load custom cleanup rules from external JSON files in the `rules/` directory.
- **Automated Scheduling**: One-click integration with Windows Task Scheduler for weekly maintenance.

## 🚀 Getting Started

### Prerequisites
- Windows 10/11
- Administrator privileges (highly recommended for system-level cleaning)

### Installation
Download the latest release from the [Releases](https://github.com/tariqrafiq70/WinNative-Cleanup/releases) page or build from source:

```powershell
git clone https://github.com/tariqrafiq70/WinNative-Cleanup.git
cd WinNative-Cleanup
cargo build --release
```

### Usage

#### 🏁 Quick Scan
Perform a standard scan and choose to open the dashboard or clean directly.
```powershell
.\windows-cleanup-cli.exe scan
```

#### 📊 Interactive Dashboard
Launch the premium TUI to browse and select specific cleanup categories.
```powershell
.\windows-cleanup-cli.exe dashboard
```
- **Arrows**: Navigate list
- **Space**: Select/Deselect category
- **C**: Clean selected items
- **Q**: Quit

#### 👯 Find Duplicates
Find identical files larger than 50MB.
```powershell
.\windows-cleanup-cli.exe dedupe --min-size 50
```

#### 🛠 System Optimization
Target deep-level Windows components like `Windows.old`.
```powershell
.\windows-cleanup-cli.exe optimize
```

#### 📅 Automation
Schedule a safe, automated cleanup every Sunday at 11 PM.
```powershell
.\windows-cleanup-cli.exe schedule
```

## 🛡 Safety Levels

Every cleanup rule is categorized by risk:
- 🟢 **Safe**: No impact on system stability or user data.
- 🟡 **Caution**: May slightly slow down app restarts or remove rollback points.
- 🔴 **Warning**: Deletes data users may expect to keep (e.g., Recycle Bin).

## 🧩 Custom Rules
Create a `.json` file in the `rules/` folder to add your own paths:
```json
[
  {
    "name": "Custom Cache",
    "paths": ["C:\\MyApp\\Temp"],
    "patterns": ["*.log"],
    "safety_level": "Safe"
  }
]
```

## 📜 License
MIT License. Built with ❤️ using Rust.
