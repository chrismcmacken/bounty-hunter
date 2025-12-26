#!/bin/bash
# Extract ffuf fuzzing results from JSON files
#
# Usage: ./scripts/extract-ffuf-findings.sh <org-name> [format]
#
# Output formats:
#   summary  - One line per result with status and URL (default)
#   full     - Full JSON output
#   count    - Just counts per scan

set -e

ORG="${1:-}"
FORMAT="${2:-summary}"

if [ -z "$ORG" ]; then
    cat << 'EOF'
Usage: ./scripts/extract-ffuf-findings.sh <org-name> [format]

Extract and display ffuf fuzzing results.

Arguments:
  org-name    Organization name
  format      Output format (default: summary)

Formats:
  summary   Status code, URL, and size for each result (default)
  full      Full JSON output
  count     Result counts only

Examples:
  ./scripts/extract-ffuf-findings.sh acme-corp
  ./scripts/extract-ffuf-findings.sh acme-corp count
EOF
    exit 1
fi

RESULTS_DIR="scans/$ORG/dynamic-results/ffuf"

if [ ! -d "$RESULTS_DIR" ]; then
    echo "Error: Results directory not found: $RESULTS_DIR"
    echo "Run ./scripts/scan-ffuf.sh $ORG <url> first"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed"
    exit 1
fi

total=0

for file in "$RESULTS_DIR"/*.json; do
    [ -f "$file" ] || continue

    scan_name=$(basename "$file" .json)
    result_count=$(jq '.results | length' "$file" 2>/dev/null || echo "0")

    if [ "$result_count" = "0" ]; then
        continue
    fi

    total=$((total + result_count))

    case "$FORMAT" in
        count)
            # Get breakdown by status code
            status_breakdown=$(jq -r '[.results[].status] | group_by(.) | map("\(.[0]): \(length)") | join(", ")' "$file" 2>/dev/null || echo "")
            echo "$scan_name: $result_count results ($status_breakdown)"
            ;;

        full)
            echo "=== $scan_name ($result_count results) ==="
            jq '.' "$file"
            echo ""
            ;;

        summary|*)
            echo "=== $scan_name ($result_count results) ==="

            # Get the original URL from commandline if available
            original_url=$(jq -r '.commandline // ""' "$file" 2>/dev/null | grep -oE 'https?://[^ ]+' | head -1 || echo "")
            if [ -n "$original_url" ]; then
                echo "Target: $original_url"
                echo ""
            fi

            jq -r '.results[] | "[\(.status)] \(.url)
  Size: \(.length) bytes | Words: \(.words) | Lines: \(.lines)"' "$file" 2>/dev/null

            echo ""
            ;;
    esac
done

if [ "$total" -gt 0 ]; then
    echo "========================================"
    echo "Total results: $total"
    echo "========================================"
else
    echo "No ffuf results found in $RESULTS_DIR/"
fi
