#!/usr/bin/env bash
set -euo pipefail

# Subdomain enumeration using subfinder
#
# Uses passive sources to enumerate subdomains without touching the target.
# Configure API keys in ~/.config/subfinder/provider-config.yaml for better results.
#
# Usage: ./scripts/recon-subdomains.sh <org-name> <domain1> [domain2] ...
# Example: ./scripts/recon-subdomains.sh acme-corp acme.com acme.io
#
# Output: findings/<org>/dynamic-results/recon/subdomains.txt

if [[ $# -lt 2 ]]; then
    cat << 'EOF'
Usage: ./scripts/recon-subdomains.sh <org-name> <domain1> [domain2] ...

Enumerate subdomains using passive sources (subfinder).

Arguments:
  org-name    Organization name for results directory
  domain      One or more domains to enumerate

Examples:
  ./scripts/recon-subdomains.sh acme-corp acme.com
  ./scripts/recon-subdomains.sh acme-corp acme.com acme.io api.acme.com

Output:
  findings/<org>/dynamic-results/recon/subdomains.txt

Tips:
  Configure API keys for better results:
  ~/.config/subfinder/provider-config.yaml
EOF
    exit 1
fi

ORG="$1"
shift
DOMAINS=("$@")

RESULTS_DIR="$(pwd)/findings/$ORG/dynamic-results/recon"
mkdir -p "$RESULTS_DIR"

if ! command -v subfinder &> /dev/null; then
    echo "Error: subfinder is required but not installed."
    echo "Run: ./scripts/setup-dynamic-tools.sh"
    exit 1
fi

OUTPUT_FILE="$RESULTS_DIR/subdomains.txt"
TEMP_FILE=$(mktemp)

echo "========================================"
echo "Subdomain Enumeration: $ORG"
echo "========================================"
echo "Domains: ${DOMAINS[*]}"
echo "Output: $OUTPUT_FILE"
echo ""

total_found=0

for domain in "${DOMAINS[@]}"; do
    echo "[$domain] Enumerating subdomains..."

    # Run subfinder with silent mode, append to temp file
    subfinder -d "$domain" -silent >> "$TEMP_FILE" 2>/dev/null || true

    # Count subdomains for this domain
    count=$(grep -c "\.$domain$\|^$domain$" "$TEMP_FILE" 2>/dev/null || echo "0")
    echo "[$domain] Found $count subdomains"
    total_found=$((total_found + count))
done

# Deduplicate and sort
sort -u "$TEMP_FILE" > "$OUTPUT_FILE"
rm -f "$TEMP_FILE"

UNIQUE_COUNT=$(wc -l < "$OUTPUT_FILE" | xargs)

echo ""
echo "========================================"
echo "Summary"
echo "========================================"
echo "Total found: $total_found"
echo "Unique subdomains: $UNIQUE_COUNT"
echo "Saved to: $OUTPUT_FILE"
echo ""

if [[ "$UNIQUE_COUNT" -gt 0 ]]; then
    echo "Sample subdomains:"
    head -10 "$OUTPUT_FILE" | sed 's/^/  /'
    if [[ "$UNIQUE_COUNT" -gt 10 ]]; then
        echo "  ... and $((UNIQUE_COUNT - 10)) more"
    fi
    echo ""
fi

echo "Next steps:"
echo "  1. Probe for live hosts: ./scripts/recon-httpx.sh $ORG"
echo "  2. Or add to targets: ./scripts/recon-targets.sh $ORG from-recon"
echo ""
