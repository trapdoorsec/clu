#!/bin/bash

set -e

echo "════════════════════════════════════════════════════════════════"
echo "  CLU - Containerized Malware Scanner Setup"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Check prerequisites
echo "[*] Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "[!] Docker not found. Please install Docker:"
    echo "    https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "[!] Docker Compose not found. Please install Docker Compose:"
    echo "    https://docs.docker.com/compose/install/"
    exit 1
fi

# Check Docker daemon
if ! docker ps &> /dev/null; then
    echo "[!] Docker daemon not running. Please start Docker:"
    echo "    sudo systemctl start docker"
    exit 1
fi

echo "[✓] Docker installed: $(docker --version)"
echo "[✓] Docker Compose installed: $(docker-compose --version)"
echo ""

# Create directories if they don't exist
echo "[*] Creating configuration directories..."
mkdir -p ./data/logs ./data/cache
chmod 755 ./data ./data/logs ./data/cache
echo "[✓] Directories created"
echo ""

# Check if config files exist
if [ ! -f config.toml ]; then
    echo "[*] config.toml not found. Would you like to create it now? (y/n)"
    read -r response
    if [[ "$response" == "y" ]]; then
        echo "[*] Starting interactive setup..."
        docker-compose run --rm clu clu init
    else
        echo "[!] config.toml is required. Please create one before running."
        exit 1
    fi
else
    echo "[✓] config.toml found"
fi

if [ ! -f heuristics.toml ]; then
    echo "[*] heuristics.toml not found. Creating default..."
    cat > heuristics.toml << 'EOF'
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
EOF
    echo "[✓] Default heuristics.toml created"
else
    echo "[✓] heuristics.toml found"
fi
echo ""

# Set proper permissions
echo "[*] Setting file permissions..."
chmod 644 config.toml heuristics.toml 2>/dev/null || true
echo "[✓] Permissions set"
echo ""

# Build images
echo "[*] Building Docker images (this may take a few minutes)..."
docker-compose build

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Setup Complete! ✓"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo ""
echo "  1. Start the scanner:"
echo "     docker-compose up -d"
echo ""
echo "  2. View logs:"
echo "     docker-compose logs -f clu"
echo ""
echo "  3. Stop the scanner:"
echo "     docker-compose down"
echo ""
echo "For more information, see README.md"
echo ""
