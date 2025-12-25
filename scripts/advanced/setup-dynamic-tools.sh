#!/usr/bin/env bash
set -euo pipefail

# Install dynamic analysis tools for bug bounty threat hunting
#
# Tools installed:
#   - nuclei: Template-based vulnerability scanner
#   - httpx: HTTP probing and tech fingerprinting
#   - subfinder: Passive subdomain enumeration
#   - ffuf: Web/API fuzzing
#   - interactsh-client: OOB callback monitoring
#
# Prerequisites: Go 1.21+ installed

echo "========================================"
echo "Dynamic Analysis Tools Setup"
echo "========================================"
echo ""

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "Error: Go is required but not installed."
    echo "Install Go 1.21+ from https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | grep -oP 'go\d+\.\d+' | head -1)
echo "Go version: $GO_VERSION"
echo ""

install_tool() {
    local name="$1"
    local package="$2"

    if command -v "$name" &> /dev/null; then
        echo "[$name] Already installed: $(command -v "$name")"
    else
        echo "[$name] Installing..."
        go install -v "$package"
        echo "[$name] Installed"
    fi
}

echo "Installing tools..."
echo ""

# Nuclei - Template-based vulnerability scanner
install_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

# httpx - HTTP probing and fingerprinting
install_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"

# subfinder - Subdomain enumeration
install_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

# ffuf - Web fuzzer
install_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"

# interactsh-client - OOB interaction client
install_tool "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

echo ""
echo "========================================"
echo "Updating Nuclei Templates"
echo "========================================"
nuclei -update-templates 2>&1 | tail -5

echo ""
echo "========================================"
echo "Verification"
echo "========================================"

verify_tool() {
    local name="$1"
    if command -v "$name" &> /dev/null; then
        local version
        version=$("$name" -version 2>&1 | head -1 || echo "installed")
        echo "  $name: $version"
    else
        echo "  $name: NOT FOUND"
    fi
}

verify_tool "nuclei"
verify_tool "httpx"
verify_tool "subfinder"
verify_tool "ffuf"
verify_tool "interactsh-client"

echo ""
echo "========================================"
echo "Next Steps"
echo "========================================"
echo ""
echo "1. Configure subfinder API keys for better results:"
echo "   Edit ~/.config/subfinder/provider-config.yaml"
echo "   Add keys for: Shodan, VirusTotal, SecurityTrails, etc."
echo ""
echo "2. (Optional) Set up self-hosted interactsh server:"
echo "   ./scripts/setup-interactsh-server.sh <your-domain>"
echo ""
echo "3. Run your first dynamic scan:"
echo "   ./scripts/scan-dynamic.sh <org> -d <domain>"
echo ""
