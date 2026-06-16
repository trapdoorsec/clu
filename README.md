# CLU - Containerized Malware Scanner for Python and npm Packages

Malicious PyPI and npm package hunter. Monitors the PyPI and npm feeds for new packages, runs heuristic analysis and LLM-based code review, then validates with YARA pattern-matching rules.

**⚠️ SECURITY NOTE**: This tool analyzes potentially malicious code. Always run inside a container as a non-root user.

## How it works

```
PyPI feed
    ↓
Stage 1: Heuristics (fast metadata analysis)
    ↓
Stage 2: Typosquat (package name similarity)
    ↓
[Optionally, if enabled:]
    ├→ Stage 3: YARA (pattern-based code scanning)
    └→ Stage 4: LLM Analysis (semantic AI-based review with injection detection)
    ↓
Results → Database + Sidecar API + Webhook + Log Aggregator
```

**Stage 1 & 2**: Always enabled by default (fast, ~ms to 100ms)
- Heuristics: Regex/keyword matching on package metadata
- Typosquat: Levenshtein distance against popular packages

**Stage 3 & 4**: Optional (slower, ~seconds each)
- YARA: Pattern-based code scanning via native Rust `yara-x` crate (no external CLI needed)
- LLM: Semantic analysis with prompt injection detection (requires Ollama)

> **Note:** GuardDog (the external Python CLI) is **deprecated**. CLU now uses native YARA rules for pattern-based scanning. If you previously enabled `guarddog = true`, the database migrates automatically on startup. See the migration note below.

**Results**: Persisted to SQLite database, queriable via sidecar API, and forwarded to webhook/logging services

## Quick Start with Docker (Recommended)

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 4GB+ available memory
- Webhook URL for receiving results (Slack, custom endpoint, etc.)

### Setup

```bash
# 1. Clone repository
git clone https://github.com/akses/clu.git
cd clu

# 2. Build Docker image
make docker-build

# 3. Create initial config (generates config.toml interactively)
make docker-init

# During setup, you'll be prompted for:
# - PyPI feed endpoint
# - Ollama endpoint (if using LLM analysis)
# - Webhook URL for alerts (optional — results are also persisted to SQLite)
# - Which analysis stages to enable

# 4. Start the service
make docker-up

# 5. View real-time analysis logs
make docker-logs

# 6. Check that Ollama model loaded (if LLM enabled)
make docker-logs-ollama | grep "model loaded"
```

**⚠️ Important**: Configure webhook in `config.toml` or results will be lost!

```toml
[output]
webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### Docker Usage

**Using Make (recommended):**

```bash
# Build Docker image
make docker-build

# Interactive config setup (first time only)
make docker-init

# Start containers
make docker-up

# Watch logs from all containers
make docker-logs

# Watch CLU logs only
make docker-logs-clu

# Watch Ollama logs only
make docker-logs-ollama

# Stop containers
make docker-down
```

**Using Docker Compose directly:**

```bash
# Build Docker image
docker-compose build --no-cache

# Start watching PyPI feed
docker-compose up -d

# View live analysis output
docker-compose logs -f clu

# View sidecar API logs
docker-compose logs -f clu-api

# View Ollama logs (model loading, inference)
docker-compose logs -f ollama

# Scan specific package
docker-compose exec clu clu scan requests

# Check container is running
docker-compose ps

# Stop service
docker-compose down

# Stop and remove everything (including Ollama models)
docker-compose down -v
```

**Analysis results are persisted** to SQLite and served via the sidecar API:
1. **Database** (SQLite with WAL — both scanner and API share one file)
2. **Sidecar API** (`clu-api`) for findings triage, search, and OSM export
3. **Webhook** (real-time alerts to Slack, Teams, custom endpoint)
4. **Docker logs** (available via `docker logs` + log drivers)
5. **Log aggregators** (ELK Stack, Splunk, CloudWatch — see STORAGE.md)

### Cleanup & Disk Space Management

Docker images and containers can consume significant disk space. Use these commands to clean up:

**Safe cleanup (recommended):**
```bash
# Remove CLU and Ollama images + prune unused layers
make docker-clean
```

This:
- Stops and removes all containers
- Deletes volumes (but keeps downloaded Ollama models in Docker volumes)
- Removes CLU and Ollama images
- Prunes dangling images

**Aggressive cleanup (removes everything):**
```bash
# Complete Docker cleanup - only use if you want to free maximum space
make docker-clean-aggressive
```

This:
- Removes ALL unused Docker images, containers, networks, and volumes
- Requires rebuilding everything from scratch
- Frees the most disk space

**Manual cleanup:**
```bash
# Stop all containers
docker-compose down -v

# Remove specific images
docker image rm clu-scanner ollama/ollama

# Prune unused images
docker image prune -f

# Full system cleanup (aggressive)
docker system prune -af --volumes
```

## Security: Running as Non-Root User

The Docker containers are configured to run as non-root user `cluuser` (UID 1000) by default.

### Verification

```bash
# Confirm non-root execution
docker-compose exec clu whoami
# Output: cluuser

# Check container user
docker inspect clu-scanner | grep -i '"user"'
# Output: "User": "1000:1000"
```

### Storage & Data Handling

**Config files mount permissions:**

```bash
# After init completes, verify config files
docker-compose exec clu ls -la /home/cluuser/config/
# -rw-r--r-- config.toml        (RW - generated by init, can be updated)
# -r--r--r-- heuristics.toml    (RO - rules are immutable)
```

**Why different permissions:**
- `config.toml` is **writable** because `clu init` generates it
- `heuristics.toml` is **read-only** because rules should not be modified by the container

**To lock config.toml after init** (production):
```bash
# Edit docker-compose.yml and change:
# ./config.toml:/home/cluuser/config/config.toml:rw
# to:
# ./config.toml:/home/cluuser/config/config.toml:ro
```

**Analysis results are persisted** (no data loss):
- Results stored in SQLite database (shared between scanner and API)
- Available via sidecar API for triage, search, and export
- Also sent to webhook for real-time alerts
- Logs written to stdout/stderr for Docker log drivers
- Ollama models persist in named volume (shared between CLU & Ollama)

### Scanner → API → Triage

The `clu` scanner watches PyPI, analyzes packages, and stores results in SQLite. The `clu-api` sidecar serves a REST API for triage:

```
clu scanner ──POST /findings──▶ clu-api ──▶ SQLite (WAL)
     │                              │
     │                              ├─ GET  /findings          (list/query)
     │                              ├─ GET  /findings/{id}      (detail)
     │                              ├─ PATCH /findings/{id}      (triage)
     │                              └─ GET  /findings/{id}/report (OSM export)
     │
     └── also writes directly to SQLite (same DB file, WAL mode)
```

- Both binaries share one SQLite database via WAL mode (concurrent reads/writes)
- The scanner POSTs each finding to the sidecar when `[sidecar] endpoint` is configured
- POST is fire-and-forget (non-blocking, logged on failure)
- All mutating endpoints (`POST`, `PATCH`) require `Authorization: Bearer <token>`
- Read endpoints (`GET /findings`, `GET /findings/{id}`, `GET /findings/{id}/report`) also require authentication
- `GET /healthz` is unauthenticated for liveness probes

### Resource Limits

Containers have memory and CPU limits to prevent resource exhaustion:

```yaml
limits:
  cpus: '2'
  memory: 4G
reservations:
  cpus: '1'
  memory: 2G
```

Edit `docker-compose.yml` to adjust for your system.

## Manual Installation (Advanced)

### Requirements

- Rust 1.75+
- Ollama with qwen2.5-coder or similar

### Build

```bash
cargo build --release
# Scanner binary
./target/release/clu --help
# Sidecar API binary
./target/release/clu-api
```

### Run

```bash
# Interactive setup
clu init

# Watch feed
clu watch --poll-interval 30s

# Scan package
clu scan requests

# Start sidecar API
clu-api
```

## Configuration

The `clu init` command generates `config.toml` interactively. Here's the complete reference:

```toml
[feed]
endpoint = "https://pypi.org/rss/packages.xml"
poll_interval = "30s"
check_updates = false

# Popular packages for typosquat detection
popular_packages_endpoint = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

[llm]
# Ollama endpoint (required if llm stage enabled)
endpoint = "http://ollama:11434"  # In Docker: use service name
model = "qwen2.5-coder:7b"
request_timeout = 30

[analysis]
typosquat_distance_threshold = 2    # Levenshtein distance for similarity
min_package_length = 4              # Skip very short package names

[output]
log_level = "info"                  # debug, info, warn, error
enable_tui = true
# Webhook URL for the scanner to POST findings to the sidecar API
# (optional — if set, each report is forwarded to the sidecar)
webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

[pipeline]
heuristics = true       # Fast metadata rules
typosquat = true        # Similarity detection
guarddog = false         # DEPRECATED — use "yara" below; auto-migrated
yara = false              # Enable Stage 3 (YARA rules)
llm = false              # Requires Ollama running with model

[database]
enable = true
url = "sqlite://config/data/clu.db"

[extraction]
# In-memory extraction limits (safety bounds)
max_total_bytes = 67108864    # 64 MiB
max_file_bytes = 2097152      # 2 MiB
max_entries = 5000

[ecosystems]
pypi_enabled = true
npm_enabled = false           # Feed monitoring implemented; full download/analysis pending

[sidecar]
# Scanner → API POST configuration. When endpoint is set, the scanner
# POSTs each AnalysisReport to the sidecar after saving it locally.
# The clu-api binary serves the findings triage REST API.
# endpoint = "http://127.0.0.1:8080"
# token = "shared-secret-here"
# timeout_secs = 5
# listen_addr = "127.0.0.1:8080"
```

### Pipeline Configuration Guide

Each analysis stage can be enabled (`true`) or disabled (`false`):

| Stage | Speed | Enabled by Default | Requirements | Notes |
|-------|-------|---|---|---|
| **Heuristics** | ~ms | ✅ Yes | None | Fast metadata rules |
| **Typosquat** | ~100ms | ✅ Yes | Network (external API) | Levenshtein similarity |
| **YARA** | ~sub-second | ❌ No | YARA rules (built-in + custom) | Pattern-based scanning (replaces GuardDog) |
| **LLM** | ~2-5s | ❌ No | Ollama + model | Semantic analysis + injection detection |

**Example Configurations:**

```toml
# Minimum (fast, recommended for production)
[pipeline]
heuristics = true
typosquat = true
yara = false
llm = false

# Balanced (add YARA for medium-risk packages)
[pipeline]
heuristics = true
typosquat = true
yara = true
llm = false

# Maximum (all stages - slowest but most thorough)
[pipeline]
heuristics = true
typosquat = true
yara = true
llm = true
```

**To enable YARA (replaces GuardDog):**
```bash
# 1. YARA rules are included in config/yara_rules/builtin/
#    Custom rules can be added to config/yara_rules/custom/ or via the API

# 2. Enable in config.toml
[pipeline]
yara = true
```

> **Migration from GuardDog:** If you previously used `guarddog = true`, the database will automatically rename `guarddog_result` → `yara_result` and `guarddog` → `yara` status values on first boot. You will see a log message like:
> ```
> Running YARA migration: renaming guarddog_result → yara_result in stored reports
> ```
> No manual intervention is required.

**To enable LLM:**
```bash
# 1. Make sure Ollama is running
docker-compose logs ollama | grep "model loaded"

# 2. Enable in config.toml
[pipeline]
llm = true

# 3. Configure Ollama endpoint
[llm]
endpoint = "http://ollama:11434"
model = "qwen2.5-coder:7b"
```

Create `heuristics.toml`:

```toml
[[rules]]
name = "suspicious_author"
type = "metadata"
field = "author"
keywords = ["test", "admin", "root", "example"]
risk_score = 50
description = "Suspicious author name detected"

[[rules]]
name = "short_package_name"
type = "metadata"
field = "title"
check = "length < 3"
risk_score = 30
description = "Very short package name"
```

## Risk Levels

| Score | Level | Meaning | Action |
|-------|-------|---------|--------|
| 0-30 | **SAFE** (green) | Safe package | Monitor |
| 31-70 | **REVIEW** (yellow) | Review recommended | Investigate |
| 71-100 | **BLOCK** (red) | Likely malicious | Block/Immediate action |

## Example Output

```
────────────────────────────────────────────────────────────────────── ANALYSIS REPORT ───────────────────────────────────────────────────────────────

Package: suspicious-package
Timestamp: 2026-01-03T12:34:56Z

Analysis Methods:
  [x] Heuristics (2 rules matched)
  [x] Typosquat Detection (1 match)
  [x] LLM Analysis
  [·] YARA (skipped)

Risk Level: BLOCK (72)
Recommendation: BLOCK

Heuristic Matches:
  • suspicious_author (risk: 50)
    Suspicious author name detected
  • short_package_name (risk: 30)
    Very short package name

Typosquat Matches:
  • Similar to: requests (confidence: 88.5%)
    Evidence: Package 'requestss' is 1 character(s) away from 'requests'

LLM Analysis:
  Impact: HIGH (4)
  Likelihood: VERY_LIKELY (4)
  Severity: 16 (MALICIOUS)
  Reasoning: Contains credential harvesting code
  Confidence: 95.2%

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

## Troubleshooting

### Container won't start

```bash
# Check CLU logs
docker-compose logs clu | head -50

# Check Ollama logs
docker-compose logs ollama

# Rebuild image
docker-compose build --no-cache
```

### No results appearing

**Check webhook is configured:**
```bash
# View config
grep webhook ./config.toml
# Should show: webhook = "https://..."
```

**Test webhook connectivity:**
```bash
docker-compose exec clu curl -v https://your-webhook-url
```

**View container logs:**
```bash
docker-compose logs clu | grep -i "new package\|webhook\|analysis"
```

### Ollama model not loading

```bash
# Check Ollama service
docker-compose logs ollama

# Verify model is installed
docker-compose exec ollama ollama list

# Pull model manually
docker-compose exec ollama ollama pull qwen2.5-coder:7b

# Wait for it to complete, then restart CLU
docker-compose restart clu
```

### LLM analysis not running (stage 4)

```bash
# Check if LLM is enabled
grep "llm = " ./config.toml  # Should be 'true'

# Check Ollama is healthy
docker-compose ps | grep ollama  # Should show 'healthy'

# Check CLU can reach Ollama
docker-compose exec clu curl http://ollama:11434/api/tags
```

### YARA analysis not running (stage 3)

```bash
# Check if YARA is enabled
grep "yara = " ./config.toml  # Should be 'true'

# Verify YARA rules are present
ls -la config/yara_rules/builtin/
ls -la config/yara_rules/custom/

# Check logs for YARA rule loading
docker-compose logs clu | grep -i yara
```

> **Note:** GuardDog (the external CLI scanner) is deprecated. If `guarddog = true` is present in your config, CLU will treat it as `yara = true` and log a migration notice.

### Out of memory

```bash
# Check memory usage
docker stats

# Increase Docker memory limit in docker-compose.yml
deploy:
  resources:
    limits:
      memory: 8G  # Increase this
```

### Permission denied errors on config files

```bash
# Ensure config files are readable
chmod 644 ./config.toml ./heuristics.toml

# Verify they're mounted correctly
docker-compose exec clu ls -la /home/cluuser/config/
```

## Logging & External Integrations

CLU sends analysis results to external services in real-time:

### Real-Time Alerts via Webhook

```toml
[output]
# Sidecar webhook — scanner POSTs findings here when configured
webhook = "http://127.0.0.1:8080"
```

The scanner forwards findings to the sidecar API when `webhook` is configured.
For Slack/Discord/generic alerts, use the `[notifications]` section instead.

### Sidecar API (`clu-api`)

The sidecar is a separate binary that serves a REST API for querying findings and exporting reports.

**Starting the sidecar:**

```bash
# Standalone
clu-api

# With Docker
docker-compose up -d clu-api
```

**Endpoints** (authentication required unless bound to loopback without a token — see below):

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/findings` | Register finding (idempotent on ecosystem+name+version+sha256) |
| `GET` | `/findings` | List/query findings (filter by ecosystem, status, severity, min_score, since) |
| `GET` | `/findings/{id}` | Single finding detail |
| `PATCH` | `/findings/{id}` | Update triage status, classification, analyst notes |
| `GET` | `/findings/{id}/report` | OpenSourceMalware-shaped JSON export (includes linked scan evidence) |
| `GET` | `/metrics` | Prometheus metrics exposition |
| `GET` | `/healthz` | Liveness probe (unauthenticated) |

**Authentication behavior:**

The sidecar API uses fail-closed authentication:

| Token configured? | Bind address | Behavior |
|---|---|---|
| Yes | Any | Require `Authorization: Bearer <token>` (constant-time comparison) |
| No | Loopback (`127.x.x.x`, `::1`, `localhost`) | Allow without token |
| No | Non-loopback (`0.0.0.0`, public IP) | **Refuse to start** (exit 1) |

When the `[sidecar] token` is not configured and `listen_addr` is not a loopback address, `clu-api` will exit immediately on startup with an error message. This prevents accidentally exposing the API on a public interface without authentication.

To configure authentication:

```toml
[sidecar]
token = "your-shared-secret-here"   # Required for non-loopback deployments
listen_addr = "127.0.0.1:8080"       # Default: loopback only
```

**Example requests:**

```bash
# List all confirmed-malicious findings
curl -H "Authorization: Bearer my-secret" \
  "http://127.0.0.1:8080/findings?status=confirmed_malicious"

# Triage a finding
curl -X PATCH -H "Authorization: Bearer my-secret" \
  -H "Content-Type: application/json" \
  -d '{"status":"confirmed_malicious","classification":"trojan","analyst_notes":"credential harvester"}' \
  "http://127.0.0.1:8080/findings/42"

# Export OSM report
curl -H "Authorization: Bearer my-secret" \
  "http://127.0.0.1:8080/findings/42/report"
```

**Finding statuses:** `new` → `triaging` → `confirmed_malicious` / `benign` / `duplicate` → `reported`

### Log Aggregation (ELK, Splunk, CloudWatch)

Results are also written to stdout/stderr and can be forwarded via Docker log drivers:

```yaml
# In docker-compose.yml
services:
  clu:
    logging:
      driver: "splunk"  # or awslogs, json-file, etc.
      options:
        splunk-token: "${SPLUNK_HEC_TOKEN}"
        splunk-url: "https://splunk.company.com:8088"
```

See **STORAGE.md** for detailed integration examples:
- ELK Stack with Filebeat
- Splunk HEC integration
- AWS CloudWatch
- Fluent Bit multi-destination setup

## Development

**Use the Makefile for development tasks:**

```bash
# View all available targets
make help

# Run full test suite and build checks
make all

# Build optimized release binary
make release

# Run unit tests
cargo test --lib

# Run tests with output
make test-verbose

# Run specific test suite
make test-injection

# Check code with clippy
make check

# Format code
make fmt-fix
```

**Or use cargo directly:**

```bash
# Build debug binary
cargo build

# Build release binary
cargo build --release

# Run all tests
cargo test --lib

# Run tests with output
cargo test --lib -- --nocapture

# Check code
cargo clippy

# Check formatting
cargo fmt --check

# Auto-format code
cargo fmt

# Clean build artifacts
cargo clean
```

## License

MIT

---

*Last Updated: 2026-06-16*
