#!/usr/bin/env bash
set -euo pipefail

# HTTP probing to find live web servers from subdomain list
#
# Takes subdomains.txt and probes each for HTTP/HTTPS servers.
# Captures status codes, titles, technologies, and other metadata.
#
# Usage: ./scripts/recon-httpx.sh <org-name>
# Example: ./scripts/recon-httpx.sh acme-corp
#
# Input: scans/<org>/dynamic-results/recon/subdomains.txt
# Output: scans/<org>/dynamic-results/recon/live-hosts.json

if [[ $# -ne 1 ]]; then
    cat << 'EOF'
Usage: ./scripts/recon-httpx.sh <org-name>

Probe subdomains for live HTTP/HTTPS servers.

Arguments:
  org-name    Organization name (must have subdomains.txt from recon)

Prerequisites:
  Run recon-subdomains.sh first to generate subdomains.txt

Output:
  scans/<org>/dynamic-results/recon/live-hosts.json

The JSON output includes:
  - url: Full URL
  - status_code: HTTP status
  - title: Page title
  - tech: Detected technologies
  - content_length: Response size
  - webserver: Server header
EOF
    exit 1
fi

ORG="$1"
RESULTS_DIR="$(pwd)/scans/$ORG/dynamic-results/recon"
SUBDOMAINS_FILE="$RESULTS_DIR/subdomains.txt"
OUTPUT_FILE="$RESULTS_DIR/live-hosts.json"
URLS_FILE="$RESULTS_DIR/live-urls.txt"

if [[ ! -f "$SUBDOMAINS_FILE" ]]; then
    echo "Error: Subdomains file not found: $SUBDOMAINS_FILE"
    echo "Run ./scripts/recon-subdomains.sh $ORG <domain> first"
    exit 1
fi

if ! command -v httpx &> /dev/null; then
    echo "Error: httpx is required but not installed."
    echo "Run: ./scripts/setup-dynamic-tools.sh"
    exit 1
fi

SUBDOMAIN_COUNT=$(wc -l < "$SUBDOMAINS_FILE" | xargs)

echo "========================================"
echo "HTTP Probing: $ORG"
echo "========================================"
echo "Input: $SUBDOMAINS_FILE ($SUBDOMAIN_COUNT subdomains)"
echo "Output: $OUTPUT_FILE"
echo ""
echo "Probing for live HTTP servers..."
echo ""

# httpx options:
# -td: Technology detection
# -sc: Status code
# -title: Page title
# -cl: Content length
# -wc: Word count
# -server: Server header
# -fr: Follow redirects
# -j: JSON output
# -rl: Rate limit (requests/sec)
# -t: Threads

httpx -l "$SUBDOMAINS_FILE" \
    -td \
    -sc \
    -title \
    -cl \
    -server \
    -fr \
    -j \
    -rl 50 \
    -t 25 \
    -silent \
    -o "$OUTPUT_FILE" \
    2>&1 | grep -E "^\[" || true

# Also create a simple URL list for easy target import
if [[ -f "$OUTPUT_FILE" && -s "$OUTPUT_FILE" ]]; then
    jq -r '.url' "$OUTPUT_FILE" 2>/dev/null > "$URLS_FILE" || true
fi

echo ""
echo "========================================"
echo "Summary"
echo "========================================"

if [[ -f "$OUTPUT_FILE" && -s "$OUTPUT_FILE" ]]; then
    LIVE_COUNT=$(wc -l < "$OUTPUT_FILE" | xargs)
    echo "Live hosts found: $LIVE_COUNT"
    echo ""

    # Status code breakdown
    echo "Status codes:"
    jq -r '.status_code' "$OUTPUT_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
    echo ""

    # Technology breakdown
    echo "Technologies detected:"
    jq -r '.tech[]?' "$OUTPUT_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /' || echo "  (none detected)"
    echo ""

    echo "Results saved:"
    echo "  JSON: $OUTPUT_FILE"
    echo "  URLs: $URLS_FILE"
else
    echo "No live hosts found"
fi

echo ""
echo "Next steps:"
echo "  1. Build target list: ./scripts/recon-targets.sh $ORG from-recon"
echo "  2. Run vulnerability scan: ./scripts/scan-nuclei.sh $ORG"
echo ""
