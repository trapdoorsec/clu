# CLU Architecture

## Overview

**CLU** (Containerized malware scanner for Python and npm packages) is a multi-tier security analysis system that monitors the PyPI and npm feeds for potentially malicious packages. It employs a layered approach combining fast heuristic analysis, similarity matching, pattern-based scanning, and semantic LLM analysis to detect threats.

## System Architecture

```
┌──────────────────────────────────┐   ┌──────────────────────────────┐
│         PyPI RSS Feed            │   │     npm _changes Feed        │
└───────────────┬──────────────────┘   └──────────────┬───────────────┘
                 │                                      │
                 └──────────────┬───────────────────────┘
                                │
                                ▼
                       ┌────────────────┐
                       │  Feed Watcher  │  (watch_feed)
                       │  Multi-Eco     │
                       └────────┬───────┘
                                │
                                ▼
                       ┌────────────────────────────────┐
                       │   analyze_package()            │
                       │   Main Analysis Pipeline       │
                       └────────┬───────────────────────┘
                                │
           ┌────────────────────┼────────────────────┬──────────────┐
           │                    │                    │              │
           ▼                    ▼                    ▼              ▼
     ┌────────┐          ┌────────┐          ┌────────┐      ┌────────┐
     │Tier 1: │          │Tier 1: │          │Tier 2: │      │Tier 2: │
     │Heur.   │          │Typo.   │          │YARA    │      │  LLM   │
     │(fast)  │          │(API)   │          │(rules)  │      │(slow)  │
     └────┬───┘          └────┬───┘          └────┬───┘      └────┬───┘
          │                   │                    │              │
          └───────────────────┼────────────────────┴──────────────┘
                              │
                              ▼
                     ┌────────────────────┐
                     │  Risk Aggregation  │
                     │  & Recommendation  │
                     └────────┬───────────┘
                              │
                   ┌──────────┼──────────┐
                   │          │          │
                   ▼          ▼          ▼
           ┌──────────┐ ┌──────────┐ ┌──────────────┐
           │ Display  │ │ Sidecar  │ │ Notifications│
           │(color/   │ │   API    │ │(Slack/Discord│
           │text/json)│ │ + Metrics│ │  /webhook)   │
           └──────────┘ └──────────┘ └──────────────┘
```

## Core Components

### 1. Feed System (`src/feed/`)

**Responsibility:** Fetch and parse package feeds from multiple ecosystems

**Files:**
- `mod.rs` - Feed orchestration, RSS parsing
- `ecosystem.rs` - `Ecosystem` enum, `PackageRef`, `PyPIRegistry`, `NpmRegistry`, `FeedResult`
- `pypi.rs` - PyPI package data structures
- `npm.rs` - npm `_changes` feed client, metadata resolution, `semver_cmp`

**Key Functions:**
- `fetch_rss(url)` - Async HTTP fetch of RSS feed
- `serialize_packages(channel)` - Parse RSS XML into package structs
- `watch_feed()` - Main loop that polls feed at interval
- `NpmRegistry::fetch_feed()` - Fetches npm `_changes` feed and resolves metadatas

**Data Structure:**
```rust
pub struct PythonPackage {
    pub title: Option<String>,           // Package name
    pub link: Option<String>,            // PyPI page URL
    pub description: Option<String>,     // Package description
    pub author: Option<String>,          // Author name
    pub pub_date: Option<DateTime>,      // Publication date
}
```

### 2. Analysis Pipeline (`src/analysis/`)

The analysis system uses a **4-stage pipeline** with configurable enable/disable:

#### **Stage 1: Heuristic Analysis** (`heuristics.rs`)
- **Type:** Rule-based metadata analysis
- **Speed:** Very fast (~ms per package)
- **Default:** Enabled
- **Inputs:** Package metadata (name, author, description, etc.)
- **Outputs:** Risk score matches against configured rules

**Implementation:**
- Loads rules from `heuristics.toml`
- Each rule has a name, type (metadata), field path, keywords, risk_score
- Applies regex/keyword matching against package fields
- Returns matched rules with risk scores (0-100 each)

**Example Rules:**
- `suspicious_keywords` (75 risk) - detects "eval", "exec", "base64"
- `eval_base64_found` (90 risk) - specific pattern matching
- `missing_author` (30 risk) - empty author field
- `ip_address_in_description` (60 risk) - obfuscation indicator

#### **Stage 2: Typosquat Detection** (`typosquat.rs`)
- **Type:** Levenshtein distance matching
- **Speed:** Medium (~100ms, requires external API call)
- **Default:** Enabled
- **Inputs:** Package name, list of popular packages
- **Outputs:** Similarity matches with confidence scores

**Implementation:**
- Fetches top 30 PyPI packages from external endpoint
- Calculates Levenshtein distance between new package and popular ones
- Risk score based on distance:
  - Distance 1 char: 90 risk
  - Distance 2 chars: 75 risk
  - Distance 3 chars: 60 risk
  - Distance 4+ chars: 40 risk

**Example:** "reqeusts" → similar to "requests" (1 char away) = 90 risk

#### **Stage 3: YARA Analysis** (`yara.rs`)
- **Type:** Pattern-based code scanning using native Rust YARA engine (`yara-x` crate)
- **Speed:** Medium (~sub-second to seconds, requires package download)
- **Default:** Disabled (enable with `[pipeline] yara = true`)
- **Inputs:** Package source code (extracted in-memory)
- **Outputs:** Rule matches with severity, risk_score, and description

**Implementation:**
- Rules loaded from `config/yara_rules/builtin/` (immutable) and `config/yara_rules/custom/` (user-defined)
- Rule metadata parsed from YARA `meta` fields: `severity`, `description`, `ecosystem`, `risk_score`
- Ecosystem filtering: rules with `meta.ecosystem = "pypi"` only match PyPI packages
- Hot-reload on filesystem changes and API mutations
- CRUD API endpoints for custom rule management
- Package download & extraction in `analysis/package.rs`

> **Deprecation notice:** This stage replaces the former GuardDog analysis (which spawned an external `guarddog` CLI subprocess). Existing databases are migrated automatically on startup: field names `guarddog_result` → `yara_result` and status values `guarddog` → `yara` are rewritten in-place. Example log message:
> ```
> Running YARA migration: renaming guarddog_result → yara_result in stored reports
> ```

#### **Stage 4: LLM Analysis** (`llm.rs`)
- **Type:** Semantic code analysis via LLM
- **Speed:** Very slow (~seconds per package)
- **Default:** Disabled
- **Inputs:** Extracted Python source code
- **Outputs:** LLM verdict + confidence score + injection detection

**Implementation:**
- Core LLM analysis in `src/analysis/llm.rs` (complete with injection detection)
- Package download & extraction in `analysis/package.rs` (complete)
- Ollama health check & model management in `analysis/ollama_utils.rs` (complete)
- Prompt injection detection sentinel (implemented)
- Downloads package from PyPI, extracts Python source code
- Sends code to Ollama (qwen2.5-coder model or configured alternative)
- LLM analyzes for malicious behavior patterns
- Detects prompt injection attempts
- Returns risk score (0-100), reasoning, and confidence
- Includes `PromptInjectionDetection` struct with evidence

### 3. Configuration System (`src/config/`)

**File:** `config.toml`

**Structure:**
```toml
[feed]
endpoint = "https://pypi.org/rss/packages.xml"
poll_interval = "30s"
check_updates = false
popular_packages_endpoint = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

[llm]
endpoint = "http://localhost:11434"  # Ollama
model = "qwen2.5-coder:7b"
request_timeout = 30

[analysis]
typosquat_distance_threshold = 2
min_package_length = 4

[output]
log_level = "info"
enable_tui = false
webhook = "https://hooks.slack.com/..."  # Scanner → sidecar URL

[cache]
pip_cache_dir = "/tmp/pip-cache"  # For storing downloaded packages

[pipeline]
heuristics = true    # Enable Stage 1 (default: true)
typosquat = true     # Enable Stage 2 (default: true)
guarddog = false     # DEPRECATED — use "yara" below; migration runs automatically
yara = false          # Enable Stage 3 (default: false)
llm = false           # Enable Stage 4 (default: false)

[database]
url = "sqlite:data/clu.db"
enabled = true

[extraction]
max_total_bytes = 10_000_000
max_file_bytes = 1_000_000
max_entries = 500

[ecosystems]
pypi_enabled = true
npm_enabled = true

[sidecar]
endpoint = "http://localhost:3000"
token = ""
timeout_secs = 10
listen_addr = "0.0.0.0:3000"

[notifications]
enabled = false
slack_webhook = ""
discord_webhook = ""
generic_webhook = ""
min_severity = 13     # Only notify on HIGH+ severity
timeout_secs = 10
```

**Pipeline Config:**
- Each stage can be enabled (true) or disabled (false)
- Controlled via `PipelineConfig` struct with boolean fields
- Defaults allow fast heuristics only

### 4. Output System (`src/output/`)

**Responsibility:** Format and deliver analysis results

**Formatters:**
- `ColouredTextFormatter` - Colorized terminal output with risk scoring visualization
- `JsonFormatter` - JSON serialization for structured output
- `TextFormatter` - Plain text for non-color terminals, log files, and CI

**Format Selection:** `--format auto|color|text|json` on both `scan` and `watch` commands. `auto` uses color when stdout is a TTY, plain text otherwise.

**Notifications (`notify.rs`):**
- Severity-gated Slack/Discord/generic webhook notifications
- Configured via `[notifications]` in `config.toml`
- Only fires when `report.severity >= min_severity` (default 13, i.e., HIGH+)
- Fire-and-forget async, same pattern as `webhook.rs`

**Sidecar Webhook (`webhook.rs`):**
- Scanner POSTs `AnalysisReport` to sidecar when `[sidecar] endpoint` is configured

**Data Structure:**
```rust
pub struct AnalysisReport {
    pub package_name: String,
    pub package_version: Option<String>,
    pub timestamp: String,
    pub ecosystem: Ecosystem,     // "pypi" | "npm"
    pub sha256: String,            // hex digest of downloaded artifact
    pub heuristic_matches: Vec<HeuristicMatch>,
    pub typosquat_matches: Vec<TypoSquatterMatch>,
    pub injection_detection: Option<PromptInjectionDetection>,
    pub llm_analysis: Option<LlmAnalysisResult>,
    pub yara_result: Option<YaraScanResult>,
    pub severity: u8,    // 1-25 (risk-weighted: static_risk / 10)
    pub is_malicious: bool,
    pub recommendation: String,  // "IGNORE", "INSPECT"
}
```

### 5. CLI System (`src/main.rs` + `src/cli/`)

**Commands:**
- `clu init` - Interactive configuration setup
- `clu watch` - Monitor PyPI and npm feeds continuously
- `clu scan <package>` - Analyze single package
  - `--pkg-version <VERSION>` - Specify package version
  - `--format <auto|color|text|json>` - Output format

**Key Functions:**
- `handle_init()` - Configuration wizard
- `handle_watch()` - Multi-ecosystem feed monitoring
- `handle_scan()` - Single package analysis with full pipeline
- `persist_and_notify()` - Shared helper: DB insert, sidecar POST, notifications

### 6. Risk Scoring System

**Aggregation Logic:**
```rust
let mut risk_score: u8 = 0;

// From Stage 1: Heuristics
for match in heuristic_matches {
    risk_score += match.risk_score / 2  // Scaled down
}

// From Stage 2: Typosquat
for match in typosquat_matches {
    risk_score += match.risk_score / 2  // Scaled down
}

risk_score = min(risk_score, 100)  // Cap at 100
```

**Recommendation Tiers:**
- **0-4:** IGNORE (green) - No action needed
- **5-25:** INSPECT (yellow+) - Investigation warranted

## Data Flow

### Watch Mode Flow

```
1. Load config.toml
   ├─ Feed settings (URL, poll interval)
   ├─ Pipeline config (which stages enabled)
   └─ Analysis settings (thresholds)

2. Load heuristics.toml
   └─ Custom rule definitions

3. Start feed watcher loop
   └─ Poll PyPI RSS at interval
      └─ Filter for new packages (not seen before)
         └─ For each new package:
            a) Run enabled analysis stages
               ├─ Stage 1: Heuristics (if enabled)
               ├─ Stage 2: Typosquat (if enabled)
               ├─ Stage 3: YARA (if enabled)
               └─ Stage 4: LLM (if enabled)

            b) Aggregate risk scores

            c) Generate recommendation

            d) Format output
               └─ Display to user
               └─ Send to webhook (if configured)

4. Sleep for poll_interval
   └─ Loop back to step 3
```

### Scan Mode Flow

```
1. Load config.toml + heuristics.toml
2. Open database connection
3. Resolve package name from CLI args
4. Build PackageRef from ecosystem config
5. Run analyze_package() through enabled pipeline stages
6. Format output using selected formatter (--format)
7. Persist report to database
8. POST to sidecar if configured
9. Send notifications if severity threshold met
```

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Runtime** | Tokio (async) | Concurrent feed polling, API calls |
| **HTTP** | Reqwest | Async HTTP client for RSS/APIs |
| **Parsing** | RSS crate | XML parsing for PyPI feed |
| **Config** | TOML/Serde | Configuration serialization |
| **CLI** | Clap | Command-line argument parsing |
| **UI** | owo-colors | Terminal color output |
| **Dialog** | Dialoguer | Interactive setup prompts |
| **Distance** | Levenshtein | Typosquat similarity matching |
| **LLM** | Ollama-rs | Ollama HTTP API client |
| **Archive** | Tar/Flate2, Zip | Package decompression |
| **Utilities** | Walkdir, Regex | File traversal, pattern matching |
| **API** | Axum | Sidecar REST API + metrics |
| **Database** | SQLite (sqlx) | Persistence, WAL mode |
| **Metrics** | metrics + metrics-exporter-prometheus | Prometheus exposition |
| **Notifications** | Reqwest (fire-and-forget) | Slack/Discord/generic webhooks |

## Key Design Decisions

### 1. **Layered Analysis Pipeline**
- **Why:** Balances speed vs. thoroughness
- **Trade-off:** Quick feedback from heuristics, deeper analysis on demand
- **Benefit:** Can detect obvious threats without expensive computation

### 2. **Configurable Stages**
- **Why:** Different deployment scenarios need different analysis depths
- **Trade-off:** More configuration complexity vs. flexibility
- **Benefit:** Production can run fast (heuristics only), dev can run full analysis

### 3. **Boolean Stage Control (Not Thresholds)**
- **Why:** Simpler mental model, easier to configure
- **Trade-off:** Cannot do partial execution based on risk score
- **Benefit:** Clear semantics, reduced complexity

### 4. **Scaled Risk Scoring**
- **Why:** Prevents stage 1 findings from dominating final score
- **Decision:** Divide Heuristic & Typosquat scores by 2
- **Implication:** Stage 3/4 analyses will have higher weight when implemented

### 5. **External LLM via Ollama**
- **Why:** Privacy (runs locally), no API costs
- **Trade-off:** Requires local model download (~7GB for qwen2.5-coder)
- **Benefit:** No external dependencies, fully offline capable

### 6. **Async Everything**
- **Why:** Handle multiple packages concurrently
- **Trade-off:** Tokio complexity, harder debugging
- **Benefit:** Efficient resource usage, responsive UI

## Module Organization

```
src/
├── main.rs              # CLI entry point, handle_scan, handle_watch, persist_and_notify, get_formatter
├── lib.rs               # Library exports
├── init.rs              # Interactive config setup (dialoguer prompts)
├── glitch.rs            # Matrix-style banner animation
├── analysis/
│   ├── mod.rs          # Analysis orchestration & pipeline
│   ├── heuristics.rs   # Rule-based metadata analysis
│   ├── typosquat.rs    # Levenshtein distance matching
│   ├── guarddog.rs     # DEPRECATED: former GuardDog CLI scanner (replaced by yara.rs)
│   ├── yara.rs         # YARA scanning engine (yara-x crate, rule management)
│   ├── llm.rs          # LLM semantic analysis with injection detection
│   ├── package.rs      # Package download, in-memory extraction, sha256, source bundles
│   └── ollama_utils.rs # Ollama model checking and management
├── api/                # Sidecar REST API (clu-api binary)
│   ├── mod.rs          # Router, AppState (with PrometheusHandle), AppError, auth helper
│   ├── findings.rs     # Finding CRUD handlers + DTOs
│   ├── health.rs       # GET /healthz
│   ├── metrics.rs      # GET /metrics (Prometheus exposition)
│   └── osm.rs          # OpenSourceMalware report export
├── bin/
│   └── clu-api.rs      # Sidecar binary: load config, open DB (WAL), serve axum
├── cli/
│   ├── mod.rs          # CLI command routing
│   └── args.rs         # Argument parsing (clap derive)
├── feed/
│   ├── mod.rs          # RSS feed fetching & parsing
│   ├── ecosystem.rs    # Ecosystem enum, PackageRef, PyPIRegistry, NpmRegistry
│   ├── pypi.rs         # PyPI package data structures
│   └── npm.rs          # npm _changes feed client + metadata resolution
├── db/
│   ├── mod.rs          # Database struct, analysis_reports, package_status, WAL mode
│   └── findings.rs     # Finding, FindingStatus, FindingFilters, CRUD methods
├── output/
│   ├── mod.rs          # AnalysisReport (with ecosystem + sha256), Formatter trait
│   ├── webhook.rs      # Scanner → sidecar POST (fire-and-forget)
│   ├── notify.rs       # Slack/Discord/generic webhook notifications
│   ├── tui.rs          # Terminal UI (minimal)
│   └── formatters/
│       ├── mod.rs
│       ├── coloured_text.rs   # Terminal color output
│       ├── json.rs            # JSON serialization
│       └── text.rs            # Plain text formatter
└── config/
    └── mod.rs          # Config, PipelineConfig, CacheConfig, SidecarConfig, NotificationsConfig

config/
├── config.toml         # Runtime configuration
├── heuristics.toml     # Heuristic rule definitions
└── data/               # Runtime state (optional, for caching)
```

## Future Enhancements

1. **YARA Pattern Matching Enhancements**
   - Hot-reload and CRUD API for custom rules ✅ (done)
   - Could benefit from native Semgrep integration as an alternative
   - Risk score mapping based on YARA rule metadata

2. **npm Scope 3b+**
   - Feed + metadata (scope 3a) ✅ (done)
   - Package download and extraction for npm packages
   - YARA/LLM analysis for npm packages

3. **TUI Mode**
   - Minimal implementation exists in `src/output/tui.rs`
   - Not fully built out - mostly placeholder code

4. **Alert System Expansion**
   - Slack/Discord/generic webhooks ✅ (done)
   - Email notifications
   - Integration with threat feeds

5. **Performance Optimization**
   - Parallel stage execution
   - Caching of analysis results
   - Incremental rule updates

6. **Model Alternatives**
   - Support multiple LLM providers
   - Local model fine-tuning
   - Confidence thresholding

## Testing Strategy

| Component | Test Type | Status |
|-----------|-----------|--------|
| Heuristics | Unit tests | In `tests/injection_tests.rs` |
| LLM | Unit tests | In `tests/injection_tests.rs` (injection detection) |
| Typosquat | Unit tests | In `src/analysis/typosquat.rs` |
| npm Feed | Unit tests | In `src/feed/npm.rs` (deserialization, semver_cmp) |
| Text Formatter | Unit tests | In `src/output/formatters/text.rs` |
| JSON Formatter | Unit tests | In `src/output/formatters/json.rs` |
| Config Loading | Unit test | TODO |
| RSS Parsing | Integration test | TODO |
| End-to-end | Integration test | Manual verification via `clu scan` |

## Security Considerations

1. **Malicious Code Analysis**
   - Always run in container
   - Non-root user (cluuser UID 1000)
   - Resource limits (CPU, memory)

2. **LLM Prompt Injection**
   - Injection detection sentinel in `llm.rs`
   - Code sanitization before sending to model

3. **External API Calls**
   - Popular packages endpoint (read-only)
   - Ollama endpoint (local or trusted)

4. **Configuration Security**
   - Config files mounted read-only in Docker
   - No secrets in version control (use .env)

---

*Last Updated: 2026-06-16*
