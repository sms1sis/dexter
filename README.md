# DexOpt Analyzer

An advanced, high-performance Android DexOpt status analyzer written in Rust. This tool replaces slow shell scripts by efficiently parsing global package status from `dumpsys` and correlating it with installed apps.

## Features

- **Blazing Fast**: Captures global state in a single pass instead of per-package lookups.
- **Colorful CLI**: Visual status indicators (Green for speed, Yellow for verify, Red for APK execution).
- **Scope Selection**: Analyze User apps, System apps, or both.
- **Summary Report**: Get a professional breakdown of your device's optimization state.
- **Filtering**: Easily search for specific packages.

## Requirements

- **Termux** or a Linux environment on Android.
- **Root access** (`su` or `tsu`) is required to run `dumpsys package dexopt`.
- **aapt** (Android Asset Packaging Tool) is recommended for fetching application labels in verbose mode.
- **Rust/Cargo** (for building from source).

## Installation

```bash
git clone https://github.com/your-repo/dexopt_analyzer.git
cd dexopt_analyzer
cargo build --release
```

The binary will be available at `target/release/dexopt_analyzer`.

## Usage

Run the tool with root privileges:

```bash
# Analyze User apps (default)
su -c "./target/release/dexopt_analyzer"

# Analyze System apps
su -c "./target/release/dexopt_analyzer --type system"

# Analyze all apps with a filter
su -c "./target/release/dexopt_analyzer --type all --filter google"
```

### Options

```text
Usage: dexopt_analyzer [OPTIONS]

Options:
  -f, --filter <FILTER>  Filter output by a specific package name (partial match)
  -t, --type <TYPE>      Select which type of packages to analyze [default: user] [possible values: user, system, all]
  -v, --verbose          Verbose output (print raw lines found)
  -h, --help             Print help
  -V, --version          Print version
```

## License

MIT
