# CLU Architecture

## Overview

**CLU** (Containerized malware scanner for python packages) is a multi-tier security analysis system that monitors the PyPI feed for potentially malicious Python packages. It employs a layered approach combining fast heuristic analysis, pattern matching, and semantic analysis to detect threats.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         PyPI RSS Feed                            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
                    ┌────────────────┐
                    │  Feed Watcher  │  (watch_feed)
                    │  RSS Consumer  │
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
    │Heur.   │          │Typo.   │          │Guard   │      │  LLM   │
    │(fast)  │          │(API)   │          │(slow)  │      │(slow)  │
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
                             ▼
                    ┌────────────────────┐
                    │  Output Formatters │
                    │ (JSON/Text/Colour) │
                    └────────┬───────────┘
                             │
                             ▼
                    ┌────────────────────┐
                    │  User Output or    │
                    │  Webhook Alert     │
                    └────────────────────┘
```

## Core Components

### 1. Feed System (`src/feed/`)

**Responsibility:** Fetch and parse PyPI package feeds

**Files:**
- `mod.rs` - Feed orchestration, RSS parsing
- `pypi.rs` - PyPI package data structures

**Key Functions:**
- `fetch_rss(url)` - Async HTTP fetch of RSS feed
- `serialize_packages(channel)` - Parse RSS XML into package structs
- `watch_feed()` - Main loop that polls feed at intervals

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

#### **Stage 3: GuardDog Analysis** (`guarddog.rs`)
- **Type:** Pattern-based code scanning
- **Speed:** Slow (~seconds, requires package download + Semgrep)
- **Default:** Disabled
- **Inputs:** Package source code
- **Outputs:** Pattern matches with severity levels

**Status:** Stub implementation (TODO: requires package download)

**Planned Behavior:**
- Downloads package from PyPI
- Extracts source files
- Runs Semgrep rules to detect malicious patterns
- Risk scoring:
  - Critical: 30 points per match
  - High: 20 points per match
  - Medium: 10 points per match
  - Low: 5 points per match

#### **Stage 4: LLM Analysis** (`llm.rs`)
- **Type:** Semantic code analysis via LLM
- **Speed:** Very slow (~seconds per package)
- **Default:** Disabled
- **Inputs:** Extracted Python source code
- **Outputs:** LLM verdict + confidence score

**Status:** Stub implementation (TODO: requires package download)

**Planned Behavior:**
- Downloads package from PyPI
- Extracts Python source code
- Sends code to Ollama (qwen2.5-coder model)
- LLM analyzes for malicious behavior
- Extracts risk score (0-100) from response
- Includes injection detection sentinel

### 3. Configuration System (`src/config/`)

**File:** `config.toml`

**Structure:**
```toml
[feed]
endpoint = "https://pypi.org/rss/packages.xml"
poll_interval = "30s"
popular_packages_endpoint = "https://hugovk.github.io/..."

[llm]
endpoint = "http://localhost:11434"  # Ollama
model = "qwen2.5-coder:7b"

[analysis]
typosquat_distance_threshold = 2
min_package_length = 4

[output]
log_level = "info"
enable_tui = false
# webhook = "https://hooks.slack.com/..."  # Optional

[pipeline]
heuristics = true    # Enable Stage 1
typosquat = true     # Enable Stage 2
guarddog = false     # Enable Stage 3
llm = false          # Enable Stage 4
```

**Pipeline Config:**
- Each stage can be enabled (true) or disabled (false)
- Controlled via `PipelineConfig` struct with boolean fields
- Defaults allow fast heuristics only

### 4. Output System (`src/output/`)

**Responsibility:** Format analysis results for different audiences

**Formatters:**
- `ColouredTextFormatter` - Colorized terminal output (fully implemented)
- `JsonFormatter` - JSON serialization (fully implemented)
- `TextFormatter` - Plain text (stub)

**Data Structure:**
```rust
pub struct AnalysisReport {
    pub package_name: String,
    pub package_version: Option<String>,
    pub timestamp: String,
    pub heuristic_matches: Vec<HeuristicMatch>,
    pub typosquat_matches: Vec<TyposquatMatch>,
    pub injection_detection: Option<InjectionDetection>,
    pub llm_analysis: Option<LLMAnalysis>,
    pub guarddog_result: Option<GuardDogResult>,
    pub overall_risk_score: u8,
    pub is_malicious: bool,
    pub recommendation: String,
}
```

### 5. CLI System (`src/main.rs` + `src/cli.rs`)

**Commands:**
- `clu init` - Interactive configuration setup
- `clu watch` - Monitor PyPI feed continuously
- `clu scan <package>` - Analyze single package (TODO)

**Key Functions:**
- `handle_init()` - Configuration wizard
- `handle_watch()` - Feed monitoring
- `handle_scan()` - Single package analysis (unimplemented)

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
- **0-30:** SAFE (green) - Monitor only
- **31-70:** REVIEW (yellow) - Investigate recommended
- **71-85:** BLOCK (red) - High likelihood of malicious code
- **86-100:** CRITICAL (purple) - Immediate action required

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
               ├─ Stage 3: GuardDog (if enabled)
               └─ Stage 4: LLM (if enabled)

            b) Aggregate risk scores

            c) Generate recommendation

            d) Format output
               └─ Display to user
               └─ Send to webhook (if configured)

4. Sleep for poll_interval
   └─ Loop back to step 3
```

### Scan Mode Flow (TODO)

```
1. Load config
2. Get package name from CLI
3. Download from PyPI (or use local)
4. Run full analysis pipeline
5. Display results
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
| **Archive** | Tar/Flate2 | Package decompression |
| **Utilities** | Walkdir, Regex | File traversal, pattern matching |

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
├── main.rs              # CLI entry point, watch/scan commands
├── lib.rs               # Library exports
├── init.rs              # Interactive config setup
├── glitch.rs            # Matrix-style banner animation
├── analysis/
│   ├── mod.rs          # Analysis orchestration
│   ├── heuristics.rs   # Rule-based metadata analysis
│   ├── typosquat.rs    # Levenshtein distance matching
│   ├── guarddog.rs     # Pattern-based scanning (stub)
│   └── llm.rs          # LLM semantic analysis (stub)
├── feed/
│   ├── mod.rs          # RSS feed fetching
│   └── pypi.rs         # PyPI package data structures
├── output/
│   ├── mod.rs          # Output trait & report structures
│   └── formatters/
│       ├── coloured_text.rs   # Terminal color output
│       ├── json.rs            # JSON serialization
│       └── text.rs            # Plain text (stub)
├── config/
│   └── mod.rs          # Configuration loading & structures
└── cli.rs              # CLI helpers (empty)

config/
├── config.toml         # Runtime configuration
├── heuristics.toml     # Rule definitions
└── data/               # Runtime state (logs, cache, etc.)
```

## Future Enhancements

1. **Package Download & Extraction**
   - Required for GuardDog and LLM analysis
   - Secure sandbox for untrusted code

2. **Database Persistence**
   - Store analysis history
   - Track package evolution over time

3. **Web Dashboard**
   - Real-time monitoring UI
   - Historical trends

4. **Alert System Expansion**
   - Email notifications
   - Custom webhooks
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
| Typosquat | Unit tests | TODO |
| RSS Parsing | Integration test | TODO |
| Config Loading | Unit test | TODO |
| End-to-end | Integration test | TODO |

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

*Last Updated: 2026-01-06*
