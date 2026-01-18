# Changelog

### 🚀 Performance
* **Native Parsing:** Replaced `aapt` subprocess calls with native Rust APK parsing using `apk-info`.
* **Speedup:** Analysis with labels (verbose mode) is now **~3x faster** (dropped from ~14s to ~5s on test device).
* **Parallelism:** Parsing is fully parallelized across all available cores.

### ✨ Features
* **Robust Label Extraction:** Can now extract labels for apps where `aapt` failed or returned missing data.
* **Dependency Removal:** The tool no longer requires `aapt` to be installed. It is now self-contained (requires `openssl` libraries on host).

### 🛠 Bug Fixes
* **Missing Labels:** Fixed an issue where some system apps showed no name due to `aapt` limitations or permission errors.

### 🎨 Styling
* **Cyan Highlights:** Application names are highlighted for better visibility.
* **Dynamic Summary:** Summary box adjusts colors based on status.

### 📝 Documentation
* **Updated Requirements:** Removed `aapt`. Added `openssl` (usually pre-installed or easily available).
