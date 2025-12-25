#!/usr/bin/env bash
set -euo pipefail

# Setup self-hosted interactsh server on a VPS
#
# This script is meant to be run ON the VPS, not locally.
#
# Prerequisites:
#   - VPS with public IP (any $5/mo VPS works)
#   - Domain with wildcard A record pointing to VPS IP
#   - Ports open: 53 (DNS), 80 (HTTP), 443 (HTTPS), 25 (SMTP optional)
#
# DNS Setup Example:
#   If your domain is oob.example.com and VPS IP is 1.2.3.4:
#   - A record: oob.example.com -> 1.2.3.4
#   - A record: *.oob.example.com -> 1.2.3.4
#   - NS record: oob.example.com -> oob.example.com (self-referential)
#
# Usage: ./setup-interactsh-server.sh <domain>
# Example: ./setup-interactsh-server.sh oob.example.com

if [[ $# -lt 1 ]]; then
    cat << 'EOF'
Usage: ./setup-interactsh-server.sh <domain>

Setup self-hosted interactsh server for OOB vulnerability detection.

Arguments:
  domain    Your interactsh domain (e.g., oob.example.com)

Prerequisites:
  1. VPS with public IP address
  2. Go 1.21+ installed on VPS
  3. DNS configured:
     - A record: <domain> -> <VPS_IP>
     - A record: *.<domain> -> <VPS_IP>
     - NS record: <domain> -> <domain>

Example:
  ./setup-interactsh-server.sh oob.mydomain.io

After setup:
  - Start server: sudo systemctl start interactsh
  - Check status: sudo systemctl status interactsh
  - View logs: sudo journalctl -u interactsh -f

Use with local client:
  interactsh-client -server https://<domain>
EOF
    exit 1
fi

DOMAIN="$1"

echo "========================================"
echo "Interactsh Server Setup"
echo "========================================"
echo "Domain: $DOMAIN"
echo ""

# Check if running as root or with sudo capability
if [[ $EUID -ne 0 ]]; then
    echo "Note: This script will use sudo for systemd configuration"
fi

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "Error: Go is required but not installed."
    echo ""
    echo "Install Go on Ubuntu/Debian:"
    echo "  sudo apt update && sudo apt install -y golang-go"
    echo ""
    echo "Or use snap:"
    echo "  sudo snap install go --classic"
    exit 1
fi

echo "Installing interactsh-server..."
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

# Get Go bin path
GOPATH="${GOPATH:-$HOME/go}"
INTERACTSH_BIN="$GOPATH/bin/interactsh-server"

if [[ ! -f "$INTERACTSH_BIN" ]]; then
    echo "Error: interactsh-server not found at $INTERACTSH_BIN"
    exit 1
fi

echo "interactsh-server installed at: $INTERACTSH_BIN"
echo ""

# Create systemd service
echo "Creating systemd service..."

SYSTEMD_SERVICE="[Unit]
Description=Interactsh OOB Interaction Server
Documentation=https://github.com/projectdiscovery/interactsh
After=network.target

[Service]
Type=simple
User=$USER
ExecStart=$INTERACTSH_BIN -domain $DOMAIN -hostmaster admin@$DOMAIN
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target"

echo "$SYSTEMD_SERVICE" | sudo tee /etc/systemd/system/interactsh.service > /dev/null

echo "Reloading systemd..."
sudo systemctl daemon-reload

echo ""
echo "========================================"
echo "Setup Complete"
echo "========================================"
echo ""
echo "Systemd service created: /etc/systemd/system/interactsh.service"
echo ""
echo "Commands:"
echo "  Start server:   sudo systemctl start interactsh"
echo "  Stop server:    sudo systemctl stop interactsh"
echo "  Enable on boot: sudo systemctl enable interactsh"
echo "  Check status:   sudo systemctl status interactsh"
echo "  View logs:      sudo journalctl -u interactsh -f"
echo ""
echo "Test the server:"
echo "  curl http://$DOMAIN"
echo ""
echo "Use with local client:"
echo "  interactsh-client -server https://$DOMAIN"
echo ""
echo "Use with nuclei:"
echo "  nuclei -l targets.txt -iserver https://$DOMAIN"
echo ""
echo "DNS Verification:"
echo "  Ensure these records exist:"
echo "  - A record: $DOMAIN -> <VPS_IP>"
echo "  - A record: *.$DOMAIN -> <VPS_IP>"
echo "  - NS record: $DOMAIN -> $DOMAIN"
echo ""
