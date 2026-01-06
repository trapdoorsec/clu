`# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**CLU** is a containerized malware scanner for Python packages that monitors the PyPI feed for potentially malicious packages. It combines a multi-tier analysis approach: fast Rust-based heuristics → similarity matching → pattern-based scanning → semantic LLM analysis.

See ARCHITECTURE.md for detailed system design.

## Build & Test Commands

### Development
```bash
# Build debug binary
cargo build

# Build release binary (optimized)
cargo build --release

# Run tests
cargo test

# Run specific test file
cargo test --test injection_tests

# Run specific test
cargo test --test injection_tests test_name

# Code linting
cargo clippy

# Format code
cargo fmt --check

# Auto-format code
cargo fmt
```

### Running the Application
```bash
# Display help
cargo run -- --help

# Interactive setup (generates config.toml)
cargo run -- init

# Watch PyPI feed continuously
cargo run -- watch

# Watch with custom config
cargo run -- watch --config /path/to/config.toml

# Scan specific package (TODO: not fully implemented)
cargo run -- scan <package-name>
```

### Docker (Recommended for actual use)
```bash
# Build Docker image
docker-compose build

# Start service
docker-compose up -d

# View logs
docker-compose logs -f clu

# Run command in container
docker-compose exec clu clu scan requests

# Stop service
docker-compose down

# Clean all (including models)
docker-compose down -v
```

## Code Architecture

### Core Pipeline: 4-Stage Analysis System

CLU processes packages through a configurable pipeline with four analysis stages:

**Stage 1: Heuristics** (`src/analysis/heuristics.rs`)
- Rule-based metadata scanning (regex + keyword matching)
- Controlled by `heuristics.toml` rule definitions
- Very fast (~ms), enabled by default
- Loads rules at startup: name, type, field, keywords, risk_score

**Stage 2: Typosquat** (`src/analysis/typosquat.rs`)
- Levenshtein distance matching against popular packages
- Fetches top 30 packages from external endpoint
- Medium speed (~100ms), enabled by default
- Risk scaling: distance 1 char = 90 risk, distance 2 = 75, etc.

**Stage 3: GuardDog** (`src/analysis/guarddog.rs`)
- Pattern-based code scanning via Semgrep (stub implementation)
- Requires package download + extraction
- Disabled by default (slow)

**Stage 4: LLM Analysis** (`src/analysis/llm.rs`)
- Semantic analysis via Ollama (qwen2.5-coder)
- Requires package download + Python code extraction
- Disabled by default (very slow)
- Includes prompt injection detection sentinel

### Critical Data Structures

```rust
// Main analysis report (src/output/mod.rs)
pub struct AnalysisReport {
    pub package_name: String,
    pub heuristic_matches: Vec<HeuristicMatch>,
    pub typosquat_matches: Vec<TyposquatMatch>,
    pub llm_analysis: Option<LLMAnalysis>,
    pub guarddog_result: Option<GuardDogResult>,
    pub overall_risk_score: u8,  // 0-100
    pub recommendation: String,  // SAFE/REVIEW/BLOCK/CRITICAL
}

// Package metadata (src/feed/pypi.rs)
pub struct PythonPackage {
    pub title: Option<String>,        // Package name
    pub description: Option<String>,  // Long description
    pub author: Option<String>,       // Author name
    pub link: Option<String>,         // PyPI URL
    pub pub_date: Option<DateTime>,   // Release timestamp
}
```

### Risk Scoring

Aggregation logic in `src/analysis/mod.rs` (`analyze_package` function):
- Heuristic matches: scaled down (divided by 2)
- Typosquat matches: scaled down (divided by 2)
- Combined result capped at 100
- Recommendations: 0-30 SAFE (green) → 31-70 REVIEW (yellow) → 71-85 BLOCK (red) → 86-100 CRITICAL (purple)

### Key Configuration

Located in `config.toml`:
- `[feed]` - PyPI RSS endpoint, polling interval
- `[llm]` - Ollama endpoint + model name
- `[analysis]` - Thresholds (typosquat distance, min package length)
- `[output]` - Log level, TUI enable, webhook URL
- `[pipeline]` - Boolean flags for enabling/disabling each stage

Custom heuristic rules defined in `heuristics.toml` with format:
```toml
[[rules]]
name = "suspicious_author"
type = "metadata"
field = "author"
keywords = ["test", "admin", "root"]
risk_score = 50
description = "Suspicious author name"
```

### Output Formatters

Located in `src/output/formatters/`:
- `ColouredTextFormatter` - Colorized terminal output (fully implemented)
- `JsonFormatter` - JSON serialization (fully implemented)
- `TextFormatter` - Plain text (stub, minimal implementation)

All implement the `OutputFormatter` trait from `src/output/mod.rs`.

### Module Map

```
src/
├── main.rs          # CLI entry, watch/scan command routing
├── lib.rs           # Library exports
├── init.rs          # Interactive config setup (dialoguer prompts)
├── glitch.rs        # Matrix-style banner animation
├── analysis/        # Core analysis stages
│   ├── mod.rs      # Pipeline orchestration (analyze_package function)
│   ├── heuristics.rs
│   ├── typosquat.rs
│   ├── guarddog.rs
│   └── llm.rs
├── feed/           # PyPI RSS integration
│   ├── mod.rs     # fetch_rss, serialize_packages, watch_feed
│   └── pypi.rs    # PythonPackage struct
├── output/        # Result formatting
│   ├── mod.rs     # AnalysisReport, OutputFormatter trait
│   ├── webhook.rs # Slack/webhook integration
│   ├── tui.rs     # Terminal UI (minimal)
│   └── formatters/
└── config/        # Configuration parsing
    └── mod.rs     # Config, PipelineConfig structs

config/             # Runtime config files (not in version control)
├── config.toml
├── heuristics.toml
└── data/           # Runtime state
```

## Development Guidelines

### Package Download & Extraction (For GuardDog/LLM)

Both `guarddog.rs` and `llm.rs` require downloading PyPI packages. The implementation pattern should:
1. Download `.tar.gz` from PyPI using `reqwest`
2. Extract using `flate2` (decompression) + `tar` (archive)
3. Walk directory with `walkdir` to find `.py` files
4. Pass source code to analysis stage

See existing code using `tempfile`, `walkdir`, `tar`, and `flate2` for reference.

### Adding New Heuristic Rules

Rules are loaded dynamically from `heuristics.toml`:
1. Add new `[[rules]]` section to `heuristics.toml`
2. No code changes needed - the rule system reads all sections at startup
3. Each rule requires: name, type, field (for metadata matching), keywords/check condition, risk_score, description

### Risk Score Calibration

When modifying analysis stages, remember:
- Heuristics & Typosquat scores are divided by 2 before aggregation
- This prevents Stage 1 findings from dominating GuardDog/LLM results
- Final score is capped at 100
- Modify the scaling in `analyze_package()` if changing tier weights

### Testing

Current tests in `tests/injection_tests.rs` validate:
- LLM prompt injection detection (sentinel checking)
- Heuristic rule matching logic

Add new tests there for:
- Config loading
- RSS parsing
- Typosquat similarity calculation
- Output formatting

## Important Implementation Notes

### Async Runtime

All I/O operations use Tokio (async/await). Key functions:
- `watch_feed()` - Main loop that continuously polls RSS
- `fetch_rss()` - HTTP GET with reqwest
- `analyze_package()` - Orchestrates all analysis stages (can be parallelized)

### CLI Arguments

Defined in `src/main.rs` using clap derive macros. Commands:
- `init` - Calls `handle_init()` from `init.rs`
- `watch` - Calls `handle_watch()` from `main.rs`
- `scan <package>` - Calls `handle_scan()` (TODO)

### Feed Parsing

RSS feed parsed with `rss` crate. The `serialize_packages()` function converts RSS items to `PythonPackage` structs. Watch for:
- Missing fields (wrapped in `Option<T>`)
- Timestamp parsing from `pub_date`
- Link format variations

### Error Handling

Most functions return `Result<T, Box<dyn std::error::Error>>`. Errors are logged but don't stop the feed watcher loop (graceful degradation).

## Incomplete Features (TODOs)

1. **GuardDog integration** - Stub only, needs:
   - Package download logic
   - Semgrep rule integration
   - Result parsing

2. **LLM code extraction** - Stub only, needs:
   - Extracting Python source from packages
   - Handling multi-file packages
   - Streaming responses from Ollama

3. **Scan command** - CLI routing exists but handler unimplemented
   - Should load config, download/analyze package, output result

4. **TUI mode** - Minimal implementation
   - Config option exists but not fully built out

5. **Text formatter** - Only JSON and colored output fully implemented
   - Need plain text version for non-color terminals
