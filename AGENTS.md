`# AGENTS.md

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

# Run all tests
cargo test --lib

# Run tests with output
cargo test --lib -- --nocapture --test-threads=1

# Run injection detection tests
cargo test --test injection_tests -- --nocapture --test-threads=1

# Code linting
cargo clippy

# Check code formatting
cargo fmt --check

# Auto-format code
cargo fmt
```

Alternatively, use the Makefile for common tasks:
```bash
# Make targets (see 'make help' for full list)
make build          # Build debug binary
make release        # Build optimized release binary
make test           # Run all tests
make test-verbose   # Run tests with output
make test-injection # Run injection tests only
make check          # Run clippy linter
make fmt            # Check formatting
make fmt-fix        # Auto-format code
make all            # Build, test, and check (comprehensive)
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
    pub package_version: Option<String>,
    pub timestamp: String,
    pub ecosystem: Ecosystem,     // "pypi" | "npm"
    pub sha256: String,            // hex digest of downloaded artifact

    // Tier 1: Heuristics
    pub heuristic_matches: Vec<HeuristicMatch>,
    pub typosquat_matches: Vec<TypoSquatterMatch>,

    // Tier 2: LLM
    pub injection_detection: Option<PromptInjectionDetection>,
    pub llm_analysis: Option<LlmAnalysisResult>,

    // Tier 3: GuardDog
    pub guarddog_result: Option<GuardDogResult>,

    // Summary
    pub severity: u8,    // 1-25 (impact * likelihood)
    pub is_malicious: bool,
    pub recommendation: String,     // "BLOCK", "REVIEW", "SAFE"
}

// LLM semantic analysis result (src/analysis/llm.rs)
pub struct LlmAnalysisResult {
    pub is_malicious: bool,
    pub risk_score: u8,
    pub reasoning: String,
    pub confidence: f32,
}

// Prompt injection detection (src/analysis/llm.rs)
pub struct PromptInjectionDetection {
    pub injection_detected: bool,
    pub confidence: f32,
    pub evidence: Vec<String>,
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
- Recommendations: 0-30 SAFE → 31-70 REVIEW → 71-100 BLOCK
- `is_malicious` flag: true if risk_score >= THRESHOLD (typically 70+)

### Key Configuration

Located in `config.toml`:
- `[feed]` - PyPI RSS endpoint, polling interval, popular packages endpoint, update checking
- `[llm]` - Ollama endpoint, model name, request timeout
- `[analysis]` - Thresholds (typosquat distance, min package length)
- `[output]` - Log level, TUI enable, webhook URL
- `[cache]` - Pip package cache directory (used by GuardDog and LLM)
- `[pipeline]` - Boolean flags for enabling/disabling each stage (heuristics, typosquat, guarddog, llm)
- `[database]` - SQLite URL, enable/disable
- `[extraction]` - In-memory limits (max_total_bytes, max_file_bytes, max_entries)
- `[ecosystems]` - Per-ecosystem toggles (pypi_enabled, npm_enabled)
- `[sidecar]` - Scanner→API wiring: endpoint, token, timeout_secs, listen_addr

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
- `coloured_text.rs` - Colorized terminal output with risk scoring visualization (fully implemented)
- `json.rs` - JSON serialization for structured output (fully implemented)
- `text.rs` - Plain text formatter for non-color terminals

All implement the `Formatter` trait from `src/output/mod.rs`:
```rust
pub trait Formatter {
    fn format_report(&self, report: &AnalysisReport) -> String;
}
```

### Module Map

```
src/
├── main.rs          # CLI entry, watch/scan command routing, sidecar POST
├── lib.rs           # Library exports
├── init.rs          # Interactive config setup (dialoguer prompts)
├── glitch.rs        # Matrix-style banner animation
├── analysis/        # Core analysis stages
│   ├── mod.rs      # Pipeline orchestration (analyze_package function)
│   ├── heuristics.rs
│   ├── typosquat.rs
│   ├── guarddog.rs
│   ├── llm.rs
│   ├── package.rs  # Package download, in-memory extraction, sha256, source bundles
│   └── ollama_utils.rs # Ollama model checking and pulling
├── api/            # Sidecar REST API (clu-api binary)
│   ├── mod.rs      # Router, AppState, AppError, auth helper
│   ├── findings.rs # Finding CRUD handlers + DTOs
│   ├── health.rs   # GET /healthz
│   └── osm.rs      # OpenSourceMalware report export
├── bin/
│   └── clu-api.rs  # Sidecar binary: load config, open DB (WAL), serve axum
├── cli/            # Command-line interface
│   ├── mod.rs     # CLI command routing
│   └── args.rs    # Argument parsing (clap derive)
├── feed/          # Feed integration + ecosystem abstraction
│   ├── mod.rs     # fetch_rss, serialize_packages, watch_feed
│   ├── ecosystem.rs # Ecosystem enum, PackageRef, PyPIRegistry, NpmRegistry
│   ├── pypi.rs    # PythonPackage struct
│   └── npm.rs     # Stub for Phase 3
├── db/            # SQLite persistence (shared between scanner and API)
│   ├── mod.rs     # Database struct, analysis_reports, package_status, WAL mode
│   └── findings.rs # Finding, FindingStatus, FindingFilters, CRUD methods
├── output/        # Result formatting
│   ├── mod.rs     # AnalysisReport (with ecosystem + sha256), Formatter trait
│   ├── webhook.rs # Scanner → sidecar POST (fire-and-forget)
│   ├── tui.rs     # Terminal UI (minimal)
│   └── formatters/
│       ├── mod.rs
│       ├── coloured_text.rs
│       ├── json.rs
│       └── text.rs
└── config/        # Configuration parsing
    └── mod.rs     # Config, PipelineConfig, CacheConfig, SidecarConfig structs

config/             # Runtime config files (not in version control)
├── config.toml
├── heuristics.toml
└── data/           # Runtime state (cache, etc.)
```

## Development Guidelines

### Package Download & Extraction (For GuardDog/LLM)

Package download and extraction logic is centralized in `src/analysis/package.rs` (`PackageContents` struct):
1. Downloads `.tar.gz` or `.whl` directly from PyPI via `reqwest` (no pip cache, no disk writes)
2. Computes `sha256` over raw downloaded bytes before extraction
3. Extracts entirely in-memory using `flate2`/`tar` or `zip` with bounds enforcement (`ExtractionConfig`)
4. `sanitize_relative_path()` strips `..` and absolute path components (zip-slip defense)
5. `classify_file()` assigns `FileRole` per ecosystem (EntryScript/Config/Script/Source/Other)
6. `build_source_bundle()` orders by priority, truncates only low-priority files
7. Returns `PackageContents { files, ecosystem, sha256 }` — no `TempDir`, no disk writes

The extraction config is in `config.toml` under `[extraction]` (max_total_bytes, max_file_bytes, max_entries).

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

### Database (SQLite)

- Both `clu` (scanner) and `clu-api` (sidecar) share one SQLite database file
- WAL mode is enabled per-connection via `SqliteConnectOptions`; foreign keys are enforced
- `analysis_reports` table: immutable scan evidence, including `ecosystem` and `sha256` columns
- `findings` table: mutable triage state linked to `analysis_reports(id)` via `report_id` FK
- Scanner writes `analysis_reports` + `package_status`; API writes `findings`
- The scanner also POSTs to the sidecar when `[sidecar] endpoint` is configured

### CLI Arguments

Defined in `src/main.rs` using clap derive macros. Commands:
- `init` - Calls `handle_init()` from `init.rs`
- `watch` - Calls `handle_watch()` from `main.rs`
- `scan <package>` - Calls `handle_scan()` (TODO)

The `clu-api` binary is a separate entry point (`src/bin/clu-api.rs`) that starts the axum HTTP server.

### Sidecar API Safety

**The sidecar stores and serves data only.** No endpoint triggers package acquisition, download, or analysis. The API consumes already-produced `AnalysisReport`s via POST or directly from the SQLite database.

### Feed Parsing

RSS feed parsed with `rss` crate. The `serialize_packages()` function converts RSS items to `PythonPackage` structs. Watch for:
- Missing fields (wrapped in `Option<T>`)
- Timestamp parsing from `pub_date`
- Link format variations

### Error Handling

Most functions return `Result<T, Box<dyn std::error::Error>>`. Errors are logged but don't stop the feed watcher loop (graceful degradation).

## Incomplete Features (TODOs)

1. **GuardDog integration** - Pattern-based code scanning (disabled by default)
   - Semgrep rule integration needs completion
   - Currently a stub - needs actual pattern matching implementation

2. **LLM code extraction & analysis** - Semantic analysis via Ollama (disabled by default)
   - Package extraction implemented in `analysis/package.rs`
   - Core LLM analysis in `src/analysis/llm.rs` with prompt injection detection
   - Ollama model checking in `analysis/ollama_utils.rs`
   - Additional improvements for large packages and streaming responses

3. **Scan command** - CLI routing exists but handler incomplete
   - `handle_scan()` in `src/main.rs` marked as TODO
   - Should load config, download/analyze single package, output result

4. **TUI mode** - Minimal implementation in `src/output/tui.rs`
   - Config option exists (`enable_tui`)
   - Not fully built out - mostly placeholder code

5. **Text formatter** - Plain text version exists but may need enhancement
   - JSON and colored output fully implemented
   - Plain text version in `src/output/formatters/text.rs` available
