# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`clu` is a malicious PyPI package hunter that monitors the PyPI feed for new packages and uses a three-tier analysis pipeline:

1. **Tier 1 (Fast Rust checks)**: Heuristics-based analysis including typosquat detection (Levenshtein distance), regex patterns, and metadata red flags
2. **Tier 2 (LLM analysis)**: Local LLM review for flagged packages using Qwen2.5-Coder via Ollama
3. **Tier 3 (GuardDog)**: Confirmation using GuardDog's Semgrep rules

Flow: `PyPI feed -> Heuristics -> LLM analysis -> GuardDog -> Alerts`

## Architecture

The codebase is organized into five main modules:

- **cli/**: Command-line interface and argument parsing for `watch` and `scan` commands
- **feed/**: PyPI feed monitoring and package fetching logic
- **analysis/**: Three-tier analysis pipeline
  - `heuristics.rs`: Tier 1 - Fast Rust-based checks (typosquat, metadata)
  - `llm.rs`: Tier 2 - LLM integration with Ollama
  - Integration with GuardDog for Tier 3 validation
- **output/**: Alert delivery via TUI, webhooks (Discord/Slack), and formatters
- **config/**: Configuration management for feed polling, LLM endpoint, and output options

## Common Commands

```sh
# Build the project
cargo build --release

# Run in development
cargo run -- watch
cargo run -- scan <package-name>

# Run tests
cargo test

# Run a specific test
cargo test <test_name>
```

## External Dependencies

- **Ollama** running locally at `http://localhost:11434` with `qwen2.5-coder:32b` model
- **GuardDog** installed via `pip install guarddog` (requires Python 3.9+)

## Configuration

Configuration is read from `config.toml`:
- `feed.poll_interval`: PyPI feed polling frequency
- `llm.endpoint`: Ollama API endpoint
- `llm.model`: LLM model to use
- `output.webhook`: Optional webhook URL for alerts
