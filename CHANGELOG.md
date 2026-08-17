# Changelog

## [0.4.3] - 2026-08-17

### 🔒 Security
* **Command Injection Hardening:** Package/target names passed via `-o`/`-m` are now validated against a strict allowlist (ASCII alphanumerics, `.`, `_`, `-`) before being interpolated into a `su -c` shell command, closing a shell-injection vector.

### 🐛 Bug Fixes
* **`--help`/`--version` Under Root:** The root-privilege check now runs *after* argument parsing, so `--help` and `--version` no longer require root to print.
* **Multi-byte App Labels:** The label-length heuristic now counts characters instead of bytes, so labels containing CJK, emoji, or accented characters are no longer incorrectly rejected as "too long".
* **`aapt` Detection Reliability:** `aapt` availability is now probed by invoking it directly instead of via `which`, avoiding a mismatch between detection and actual invocation under `su`/`sudo` shells where `PATH` can differ.

### 🚀 Performance
* **Restored `aapt`-First Label Resolution:** A newer `apk-info-zip` release now performs full signature/certificate parsing per APK, making native-first label resolution significantly slower in practice. `aapt` is back to being tried first when available (checked once, cached), with native `apk-info` parsing as the fallback — total analysis time reduced from ~10.8s back to ~1.9s in verbose mode on the reference benchmark.
* **Release Profile Tuning:** Enabled `lto`, `codegen-units = 1`, and `strip` for a smaller, faster release binary.

### 🛠 Improvements
* **Deduplicated Optimization Logic:** The clear-profiles + compile sequence used by both `-o` and `-m` is now a single shared `optimize_package()` helper.
* **Consistent Error Handling:** Root-check failure now returns a proper `Result` instead of calling `process::exit` directly, matching the rest of the codebase.
* **Dependency Cleanup:** Replaced `once_cell::sync::Lazy` with `std::sync::LazyLock`, dropping the `once_cell` direct dependency.
* **Regex Cleanup:** Removed a vestigial `filter=` alternation that never matched real `dumpsys` output; the status-extraction regex was renamed for clarity.

---

## [0.4.2] - 2026-05-30

### ✨ Features
* **Optimize Missing Flag:** Added `-m` / `--optimize-missing` flag to batch-compile all user apps that lack `speed` or `speed-profile` dexopt status.
    * Automatically skips any package where at least one split part already has `speed` or `speed-profile`.
    * Re-fetches the dexopt dump after compilation and displays verbose block entries with updated statuses.
    * Shows the full summary box on completion.

### 🚀 Performance
* **Single Regex Pass:** Removed redundant `STATUS_RE` gate; `FILTER_EXTRACT_RE` now serves as both the line filter and status extractor in one pass.
* **Cached Terminal Width:** `terminal_size()` is now resolved once before the display loop instead of on every package in verbose mode.
* **Zero-Alloc Char Width:** Replaced per-character `String` allocation in the Unicode truncation path with `UnicodeWidthChar`, eliminating heap allocations in the hot loop.

---

## [0.3.1] - 2026-01-29

### 🛠 Improvements
* **Optimization Workflow:** 
    * Automatically enables verbose output (`-v`) after optimization for a cleaner and more detailed status view.
    * Automatically filters the results to the targeted package when optimizing a specific app, eliminating noise from other packages.

## [0.3.0] - 2026-01-29

### ✨ Features
* **Optimization Flag:** Added `-o` / `--optimize` flag to trigger app-specific or system-wide dexopt.
    * Use `-o <package_name>` to clear profiles and force compile a specific app.
    * Use `-o all` to trigger the system background dexopt job (`bg-dexopt-job`).
* **Root Enforcement:** Improved root access validation for administrative commands.

### 🛠 Improvements
* **CLI Options:** Updated help menus and argument parsing to include optimization targets.
* **Version Bump:** Formalized v0.3.0 release.

---

## [0.2.0] - 2026-01-18

### 🚀 Performance
* **Native Parsing:** Replaced `aapt` subprocess calls with native Rust APK parsing using `apk-info`.
* **Speedup:** Analysis with labels (verbose mode) is now **~3x faster**.
* **Parallelism:** Parsing is fully parallelized across all available cores.

### ✨ Features
* **Robust Label Extraction:** Can now extract labels for apps where `aapt` failed or returned missing data.
* **Dependency Removal:** The tool no longer requires `aapt` to be installed. It is now self-contained.

### 🛠 Bug Fixes
* **Missing Labels:** Fixed an issue where some system apps showed no name due to `aapt` limitations.

### 🎨 Styling
* **Cyan Highlights:** Application names are highlighted for better visibility.
* **Dynamic Summary:** Summary box adjusts colors based on status.
