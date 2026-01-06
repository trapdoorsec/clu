# CLU - Containerized Malware Scanner for Python Packages

Malicious PyPI package hunter. Monitors the PyPI feed for new packages, runs heuristic analysis and LLM-based code review, then validates with GuardDog.

**⚠️ SECURITY NOTE**: This tool analyzes potentially malicious code. Always run inside a container as a non-root user.

## How it works

```
PyPI feed -> Heuristics (typosquat, metadata) -> LLM analysis -> GuardDog -> Alerts
```

**Tier 1**: Fast Rust-based checks (Levenshtein distance, regex patterns, metadata red flags)
**Tier 2**: Local LLM review for flagged packages (Qwen2.5-Coder via Ollama)
**Tier 3**: GuardDog confirmation (Semgrep rules)

## Quick Start with Docker (Recommended)

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 4GB+ available memory

### Setup

```bash
# 1. Clone repository
git clone https://github.com/akses/clu.git
cd clu

# 2. Create initial config (generates config.toml interactively)
docker-compose run --rm clu clu init

# 3. Start the service
docker-compose up -d

# 4. View logs
docker-compose logs -f clu
```

### Docker Usage

```bash
# Watch PyPI feed continuously
docker-compose up -d

# View real-time logs
docker-compose logs -f clu

# Scan a specific package
docker-compose exec clu clu scan requests

# Stop service
docker-compose down

# Remove all data (including models)
docker-compose down -v
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

### File Permissions

Config files are mounted read-only:

```bash
# config.toml is read-only
docker-compose exec clu ls -la /home/cluuser/config/
# -r--r--r-- config.toml  (read-only)
# drwxr-xr-x data/        (writable for logs/cache)
```

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
- GuardDog (`pip install guarddog`)
- Python 3.9+

### Build

```bash
cargo build --release
./target/release/clu --help
```

### Run

```bash
# Interactive setup
clu init

# Watch feed
clu watch --poll-interval 30s

# Scan package
clu scan requests
```

## Configuration

Create `config.toml`:

```toml
[feed]
endpoint = "https://pypi.org/rss/packages.xml"
poll_interval = "30s"
check_updates = false

# Popular packages list (for typosquat detection)
popular_packages_endpoint = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"

[llm]
endpoint = "http://localhost:11434"  # or http://ollama:11434 in Docker
model = "qwen2.5-coder:7b"

[analysis]
typosquat_distance_threshold = 2
min_package_length = 4

[output]
log_level = "info"
enable_tui = false
# webhook = "https://hooks.slack.com/..."  # Optional

[pipeline]
# Analysis pipeline configuration
# Each stage can be: "always" (always run), "conditional" (run if risk > threshold), "disabled" (never run)

# Heuristics: Fast metadata analysis (regex patterns, suspicious fields, etc.)
# Recommended: "always"
heuristics = "always"

# Typosquat: Levenshtein distance-based package name similarity detection
# Recommended: "always"
typosquat = "always"

# GuardDog: Pattern-based code analysis (Semgrep rules for malicious patterns)
# Recommended: "conditional"
guarddog = "conditional"

# LLM: Semantic code analysis using LLM for suspicious behavior detection
# Recommended: "conditional"
llm = "conditional"

# Risk score threshold (0-100) for triggering conditional stages
# Packages scoring above this will run conditional analysis stages
trigger_threshold = 30
```

### Pipeline Configuration Guide

The `[pipeline]` section lets you customize which analysis stages run and when:

| Stage | Description | Recommended | Resource Impact |
|-------|-------------|-------------|-----------------|
| **heuristics** | Fast regex/metadata checks | always | Very low |
| **typosquat** | Levenshtein distance matching against popular packages | always | Low |
| **guarddog** | Pattern-based code scanning (Semgrep) | conditional | Medium |
| **llm** | Semantic AI-based code review | conditional | High |

**Trigger Modes:**

- `"always"` - Run this stage on every package
- `"conditional"` - Only run if risk score from previous stages exceeds `trigger_threshold`
- `"disabled"` - Skip this stage entirely

**Example Configurations:**

```toml
# Aggressive: Run all stages (slowest, most thorough)
[pipeline]
heuristics = "always"
typosquat = "always"
guarddog = "always"
llm = "always"
trigger_threshold = 0

# Balanced: Run deep analysis only on flagged packages (recommended)
[pipeline]
heuristics = "always"
typosquat = "always"
guarddog = "conditional"
llm = "conditional"
trigger_threshold = 30

# Fast: Only heuristics and typosquat
[pipeline]
heuristics = "always"
typosquat = "always"
guarddog = "disabled"
llm = "disabled"
trigger_threshold = 100
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
| 0-30 | **LOW** (green) | Safe package | Monitor |
| 31-60 | **MED** (yellow) | Review recommended | Investigate |
| 61-85 | **HIGH** (red) | Likely malicious | Block/Warn |
| 86-100 | **CRIT** (purple) | Critical threat | Immediate action |

## Example Output

```
────────────────────────────────────────────────────────────────────── ANALYSIS REPORT ───────────────────────────────────────────────────────────────

Package: suspicious-package
Timestamp: 2026-01-03T12:34:56Z

Analysis Methods:
  [x] Heuristics (2 rules matched)
  [x] Typosquat Detection (1 match)
  [x] LLM Analysis
  [·] GuardDog (skipped)

Risk Level: HIGH (72)
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
  Verdict: MALICIOUS
  Reasoning: Contains credential harvesting code
  Confidence: 95.2%

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose logs clu

# Rebuild image
docker-compose build --no-cache
```

### Ollama models not loading

```bash
# Check Ollama service
docker-compose logs ollama

# Manually pull model
docker-compose exec ollama ollama pull qwen2.5-coder:7b
```

### Permission denied errors

```bash
# Ensure files are readable by UID 1000
sudo chown -R 1000:1000 ./config.toml ./heuristics.toml
sudo chmod 644 ./config.toml ./heuristics.toml
```

### Out of memory

Increase Docker memory allocation or reduce `memory` limits in `docker-compose.yml`

## Development

```bash
# Build locally
cargo build --release

# Run tests
cargo test

# Check code
cargo clippy

# Format code
cargo fmt
```

## License

MIT
