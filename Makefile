.PHONY: help build release test check fmt clean docker-build docker-up docker-down docker-init docker-logs docker-logs-clu docker-logs-ollama docker-clean docker-clean-aggressive

help:
	@echo "CLU Makefile targets:"
	@echo ""
	@echo "Development:"
	@echo "  make build          - Build debug binary"
	@echo "  make release        - Build optimized release binary"
	@echo "  make test           - Run all unit tests"
	@echo "  make test-verbose   - Run tests with output"
	@echo "  make test-injection - Run injection detection tests only"
	@echo "  make check          - Run cargo clippy linter"
	@echo "  make fmt            - Check code formatting"
	@echo "  make fmt-fix        - Auto-format code"
	@echo "  make all            - Build release, test, and check"
	@echo "  make clean          - Remove build artifacts"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build              - Build Docker image"
	@echo "  make docker-init               - Interactive config setup"
	@echo "  make docker-up                 - Start Docker containers"
	@echo "  make docker-down               - Stop Docker containers"
	@echo "  make docker-logs               - Watch logs from all containers"
	@echo "  make docker-logs-clu           - Watch CLU logs only"
	@echo "  make docker-logs-ollama        - Watch Ollama logs only"
	@echo "  make docker-clean              - Remove images and prune (safe)"
	@echo "  make docker-clean-aggressive   - Aggressive cleanup (removes all unused Docker)"

build:
	cargo build

release:
	cargo build --release

test:
	cargo test --lib

test-verbose:
	cargo test --lib -- --nocapture --test-threads=1

test-injection:
	cargo test --test injection_tests -- --nocapture --test-threads=1

check:
	cargo clippy

fmt:
	cargo fmt --check

fmt-fix:
	cargo fmt

clean:
	cargo clean

docker-build:
	docker-compose build --no-cache

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-init:
	docker-compose run --rm clu clu init

docker-logs:
	docker-compose logs -f

docker-logs-clu:
	docker-compose logs -f clu

docker-logs-ollama:
	docker-compose logs -f ollama

docker-clean:
	docker-compose down -v
	docker image rm clu-scanner ollama/ollama 2>/dev/null || true
	docker image prune -f

docker-clean-aggressive:
	docker-compose down -v
	docker image rm clu-scanner ollama/ollama 2>/dev/null || true
	docker system prune -af --volumes

# Run all checks (build, test, lint)
all: release test check
	@echo "✅ All checks passed!"
