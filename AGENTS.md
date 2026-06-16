`# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**CLU** is a containerized malware scanner for Python packages that monitors the PyPI feed for potentially malicious packages. It combines a multi-tier analysis approach: fast Rust-based heuristics → similarity matching → pattern-based scanning → semantic LLM analysis.

See ARCHITECTURE.md for detailed system design.

## New Features

### Web UI
A new web frontend has been added to CLU providing:
- Dashboard with overview of findings and statistics
- Package analysis reports 
- Finding triage interface
- Audit logging
- Quarantine management
- Login authentication

### Notification Configuration
Enhanced notification support for:
- Discord webhooks
- Slack webhooks  
- Generic webhooks
- Startup health-check notifications

### Quarantine Feature
Package quarantine functionality that allows:
- Automatic quarantining of suspicious packages
- Quarantine management through web UI and API endpoints
- Integration with the sidecar API for triage workflows

### Health-Check Notifications
Startup notification system that sends a "🟢 CLU startup health-check" message to all configured notification channels when the scanner starts, confirming connectivity before processing any findings.

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

# Scan specific package
cargo run -- scan requests
cargo run -- scan requests --pkg-version 2.31.0
cargo run -- scan requests --format json
cargo run -- scan requests --format text

# Output format options: auto (default), color, text, json
cargo run -- watch --format text
cargo run -- watch --format json
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

**Stage 3: YARA** (`src/analysis/yara.rs`)
- Native Rust pattern-based code scanning using `yara-x` crate
- Rules loaded from `config/yara_rules/builtin/` (immutable) and `config/yara_rules/custom/` (user-defined)
- Rule metadata parsed from YARA meta fields: severity, description, ecosystem, risk_score
- Ecosystem filtering: rules with `meta.ecosystem = "pypi"` only match PyPI packages
- Hot-reload on filesystem changes and API mutations
- Disabled by default (enable with `[pipeline] yara = true`)
- API endpoints for CRUD, enable/disable, and rule testing

**Stage 4: LLM Analysis** (`src/analysis/llm.rs`)
- Semantic analysis via Ollama (qwen2.5-coder)
- Requires package download + Python code extraction
- Disabled by default (very slow)
- Includes prompt injection detection sentinel
- Ollama model checking in `analysis/ollama_utils.rs`
- `is_malicious` is **derived from severity** (`severity >= 6`), not parsed from the LLM response
- Consistency gate detects contradictions between structured fields and free-text reasoning
- Conflicted results are flagged with `conflicted=true` and confidence is halved
- Unparseable responses are discarded (severity=0, confidence=25, conflicted=true)

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

    // Tier 2: YARA
    pub yara_result: Option<YaraScanResult>,

    // Tier 3: LLM
    pub injection_detection: Option<PromptInjectionDetection>,
    pub llm_analysis: Option<LlmAnalysisResult>,

    // Summary

    // Summary
    pub severity: u8,    // 1-25 (risk-weighted: static_risk / 10)
    pub is_malicious: bool,
    pub recommendation: String,     // "IGNORE", "INSPECT"
}

// LLM semantic analysis result (src/analysis/llm.rs)
pub struct LlmAnalysisResult {
    pub impact: ImpactLevel,       // NONE(1)…CRITICAL(5)
    pub likelihood: LikelihoodLevel, // NONE(1)…IMMINENT(5)
    pub severity: u8,               // impact * likelihood (1-25)
    pub reasoning: String,          // free-text explanation from LLM
    pub confidence: f32,            // 0-100, halved if conflicted
    pub conflicted: bool,          // true if LLM response contradicts itself
}
// is_malicious is derived: severity >= 6
// JSON serialization includes "is_malicious" computed field for API compatibility

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

Aggregation logic in `src/main.rs` (`analyze_package` function) and `src/analysis/mod.rs` (`compute_static_severity`):

Static severity is computed from risk-score sums rather than raw finding counts. Each heuristic rule, typosquat match, and YARA rule match carries its own `risk_score` (0-100 scale). The total risk is summed across all tiers and divided by 10 to produce a 1-25 severity:

```
heuristic_risk = sum of all HeuristicMatch.risk_score
typosquat_risk = sum of all TypoSquatterMatch.risk_score
yara_risk      = YaraScanResult.risk_score

static_risk  = heuristic_risk + typosquat_risk + yara_risk
severity     = max(1, min(25, static_risk / 10))   if static_risk > 0, else 1
is_malicious = static_risk >= 70
```

Key implications:
- `missing_author` (risk_score=30) alone → severity 3 → **IGNORE** (≤4)
- `eval_base64` (risk_score=90) alone → severity 9 → **INSPECT**
- `dangerous_operations` (risk_score=95) alone → severity 9 → **INSPECT**
- `missing_author` + `missing_description` (30+35=65) → severity 6 → **INSPECT**
- typosquat distance 1 (risk_score=90) → severity 9 → **INSPECT**

The LLM can escalate but NEVER de-escalate below the static floor. Final severity = `max(llm.severity, static_severity)`. Final `is_malicious` = `llm.is_malicious() OR static_is_malicious` (where `llm.is_malicious()` = `llm.severity >= 6`).

If the LLM result is `conflicted=true` (structured fields contradict free-text reasoning), confidence is halved but the severity still contributes to the floor. A warning is logged for triage.

Recommendations: severity 0-4 → "IGNORE", severity 5+ → "INSPECT"

### Key Configuration

Located in `config.toml`:
- `[feed]` - PyPI RSS endpoint, polling interval, popular packages endpoint, update checking
- `[llm]` - Ollama endpoint, model name, request timeout
- `[analysis]` - Thresholds (typosquat distance, min package length)
- `[output]` - Log level, TUI enable, webhook URL
- `[cache]` - Pip package cache directory (used by LLM)
- `[pipeline]` - Boolean flags for enabling/disabling each stage (heuristics, typosquat, yara, llm)
- `[yara]` - YARA rules directory, max file size, timeout
- `[database]` - SQLite URL, enable/disable
- `[extraction]` - In-memory limits (max_total_bytes, max_file_bytes, max_entries)
- `[ecosystems]` - Per-ecosystem toggles (pypi_enabled, npm_enabled)
- `[sidecar]` - Scanner→API wiring: endpoint, token, timeout_secs, listen_addr
- `[notifications]` - Alert webhooks: enabled, slack_webhook, discord_webhook, generic_webhook, min_severity, timeout_secs

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
- `coloured_text.rs` - Colorized terminal output with risk scoring visualization
- `json.rs` - JSON serialization for structured output
- `text.rs` - Plain text formatter for non-color terminals / log files / CI

All implement the `Formatter` trait from `src/output/mod.rs`:
```rust
pub trait Formatter {
    fn format_report(&self, report: &AnalysisReport) -> String;
}
```

Format selection via `--format <auto|color|text|json>` on both `scan` and `watch` commands.
`auto` uses color when stdout is a TTY, plain text otherwise.

### Notifications

Located in `src/output/notify.rs`:
- Severity-gated Slack/Discord/generic webhook notifications
- Configured via `[notifications]` in `config.toml`
- Only fires when `report.severity >= min_severity` (default 13, i.e., HIGH+)
- Fire-and-forget async, same pattern as `webhook.rs`

### Sidecar API

Located in `src/api/`:
- `mod.rs` - Router, AppState (with `PrometheusHandle`), AppError, auth helper
- `findings.rs` - Finding CRUD handlers + DTOs, increments `clu_findings_total` metric
- `health.rs` - `GET /healthz` liveness probe
- `metrics.rs` - `GET /metrics` Prometheus exposition
- `osm.rs` - OpenSourceMalware report export
- `audit.rs` - Audit log handlers for tracking user actions
- `rules.rs` - YARA rules CRUD, enable/disable, test endpoints

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
│   ├── yara.rs     # YARA scanning engine (yara-x crate, rule management)
│   ├── llm.rs      # LLM analysis with consistency gate (is_malicious derived from severity)
│   ├── package.rs  # Package download, in-memory extraction, sha256, source bundles
│   └── ollama_utils.rs # Ollama model checking and pulling
├── api/            # Sidecar REST API (clu-api binary)
│   ├── mod.rs      # Router, AppState, AppError, auth helper
│   ├── findings.rs # Finding CRUD handlers + DTOs
│   ├── health.rs   # GET /healthz
│   ├── metrics.rs  # GET /metrics (Prometheus)
│   ├── osm.rs      # OpenSourceMalware report export
│   ├── audit.rs    # Audit log handlers for tracking user actions
│   ├── quarantine.rs # Quarantine management handlers
│   └── rules.rs    # YARA rules CRUD, enable/disable, test
├── bin/
│   └── clu-api.rs  # Sidecar binary: load config, open DB (WAL), serve axum
├── cli/            # Command-line interface
│   ├── mod.rs     # CLI command routing
│   └── args.rs    # Argument parsing (clap derive)
├── feed/          # Feed integration + ecosystem abstraction
│   ├── mod.rs     # fetch_rss, serialize_packages, watch_feed
│   ├── ecosystem.rs # Ecosystem enum, PackageRef, PyPIRegistry, NpmRegistry
│   ├── pypi.rs    # PythonPackage struct
│   └── npm.rs    # npm _changes feed client + metadata resolution
├── db/            # SQLite persistence (shared between scanner and API)
│   ├── mod.rs     # Database struct, analysis_reports, package_status, WAL mode
│   └── findings.rs # Finding, FindingStatus, FindingFilters, CRUD methods
│   └── audit.rs   # Audit log database operations
│   └── quarantine.rs # Quarantine database operations
├── output/        # Result formatting
│   ├── mod.rs     # AnalysisReport (with ecosystem + sha256), Formatter trait
│   ├── webhook.rs # Scanner → sidecar POST (fire-and-forget)
│   ├── notify.rs  # Slack/Discord/generic webhook notifications
│   ├── tui.rs     # Terminal UI (stub)
│   └── formatters/
│       ├── mod.rs
│       ├── coloured_text.rs
│       ├── json.rs
│       └── text.rs
└── config/        # Configuration parsing
    └── mod.rs     # Config, PipelineConfig, CacheConfig, SidecarConfig, NotificationsConfig, YaraConfig

config/             # Runtime config files (not in version control)
├── config.toml
├── heuristics.toml
├── yara_rules/      # YARA rule definitions
│   ├── builtin/    # Immutable built-in rules (shipped with CLU)
│   └── custom/     # User-defined rules (CRUD via API)
└── data/           # Runtime state (cache, etc.)
```

## Development Guidelines

### Package Download & Extraction (For YARA/LLM)

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
- This prevents Stage 1 findings from dominating YARA/LLM results
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
- Database migration renames `guarddog_result` → `yara_result` in stored JSON and `guarddog` → `yara` in package_status. Runs automatically on first boot; log message: `Running YARA migration: renaming guarddog_result → yara_result in stored reports`
- `findings` table: mutable triage state linked to `analysis_reports(id)` via `report_id` FK
- Scanner writes `analysis_reports` + `package_status`; API writes `findings`
- The scanner also POSTs to the sidecar when `[sidecar] endpoint` is configured

### CLI Arguments

Defined in `src/main.rs` using clap derive macros. Commands:
- `init` - Calls `handle_init()` from `init.rs`
- `watch` - Calls `handle_watch()` from `main.rs`
- `scan <package>` - Calls `handle_scan()`, supports `--pkg-version` and `--format` flags

The `clu-api` binary is a separate entry point (`src/bin/clu-api.rs`) that starts the axum HTTP server.

### Sidecar API Safety

**The sidecar stores and serves data only.** No endpoint triggers package acquisition, download, or analysis. The API consumes already-produced `AnalysisReport`s via POST or directly from the SQLite database. The `/metrics` endpoint exposes Prometheus counters (`clu_findings_total`) for monitoring.

### Feed Parsing

- **PyPI**: RSS feed parsed with `rss` crate. The `serialize_packages()` function converts RSS items to `PythonPackage` structs.
- **npm**: Uses CouchDB `_changes` replication feed for real-time package updates, then resolves metadata from the npm registry API. Implemented in `src/feed/npm.rs`.

Watch for:
- Missing fields (wrapped in `Option<T>`)
- Timestamp parsing from `pub_date`
- npm cursor-based pagination (since_cursor field on NpmRegistry)
- Link format variations

### Error Handling

Most functions return `Result<T, Box<dyn std::error::Error>>`. Errors are logged but don't stop the feed watcher loop (graceful degradation).

## Incomplete Features (TODOs)

1. **YARA rules management** - Pattern-based code scanning via native Rust (disabled by default)
   - Built-in rules in `config/yara_rules/builtin/` are immutable via API
   - Custom rules in `config/yara_rules/custom/` can be CRUD'd via API
   - Rule metadata parsed from YARA meta fields (severity, description, ecosystem, risk_score)
   - Ecosystem filtering reduces false positives (rules with `meta.ecosystem = "pypi"` only match PyPI)
   - API endpoints: `GET/POST /api/rules`, `PATCH /api/rules/{name}/enable`, `POST /api/rules/test`

2. **LLM code extraction & analysis** - Semantic analysis via Ollama (disabled by default)
   - Package extraction implemented in `analysis/package.rs`
   - Core LLM analysis in `src/analysis/llm.rs` with prompt injection detection
   - Ollama model checking in `analysis/ollama_utils.rs`
   - Additional improvements for large packages and streaming responses

3. **TUI mode** - Minimal implementation in `src/output/tui.rs`
   - Config option exists (`enable_tui`)
   - Not fully built out - mostly placeholder code

4. **npm scope 3b+** - Download, extraction, and full analysis pipeline for npm packages
   - Feed + metadata (scope 3a) implemented in `src/feed/npm.rs`
   - Package download and YARA/LLM analysis not yet supported for npm
