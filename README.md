# clu

Malicious PyPI package hunter. Monitors the PyPI feed for new packages, runs heuristic analysis and LLM-based code review, then validates with GuardDog.

## How it works

```
PyPI feed -> Heuristics (typosquat, metadata) -> LLM analysis -> GuardDog -> Alerts
```

Tier 1: Fast Rust-based checks (Levenshtein distance, regex patterns, metadata red flags)
Tier 2: Local LLM review for flagged packages (Qwen2.5-Coder via Ollama)
Tier 3: GuardDog confirmation (Semgrep rules)

## Requirements

- Rust 1.75+
- Ollama with qwen2.5-coder:32b (or similar code model)
- GuardDog (`pip install guarddog`)
- Python 3.9+ (for GuardDog)

## Usage

```sh
# Watch PyPI feed in real-time
clu watch

# Scan a specific package
clu scan <package-name>

# Scan with version
clu scan requests==2.31.0
```

## Configuration

```toml
# config.toml
[feed]
poll_interval = "5m"

[llm]
endpoint = "http://localhost:11434"
model = "qwen2.5-coder:32b"

[output]
webhook = ""  # Optional Discord/Slack webhook
```

## Building

```sh
cargo build --release
```

## License

MIT
