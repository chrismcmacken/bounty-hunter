#!/bin/bash
# Extract nuclei findings from JSON result files
#
# Usage: ./scripts/extract-nuclei-findings.sh <org-name> [format] [scan-name]
#
# Output formats:
#   summary  - One line per finding with key details (default)
#   full     - Full JSON for each finding
#   count    - Just counts per scan
#   critical - Only critical/high severity findings

set -e

ORG="${1:-}"
FORMAT="${2:-summary}"
SCAN="${3:-}"

if [ -z "$ORG" ]; then
    cat << 'EOF'
Usage: ./scripts/extract-nuclei-findings.sh <org-name> [format] [scan-name]

Extract and display nuclei vulnerability scan results.

Arguments:
  org-name    Organization name
  format      Output format (default: summary)
  scan-name   Specific scan file to extract (optional)

Formats:
  summary   One line per finding with severity, name, URL (default)
  full      Full JSON output
  count     Finding counts only
  critical  Only high and critical severity findings

Examples:
  ./scripts/extract-nuclei-findings.sh acme-corp
  ./scripts/extract-nuclei-findings.sh acme-corp critical
  ./scripts/extract-nuclei-findings.sh acme-corp summary scan-20241218-143000
EOF
    exit 1
fi

RESULTS_DIR="scans/$ORG/dynamic-results/nuclei"

if [ ! -d "$RESULTS_DIR" ]; then
    echo "Error: Results directory not found: $RESULTS_DIR"
    echo "Run ./scripts/scan-nuclei.sh $ORG first"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed"
    exit 1
fi

extract_findings() {
    local file="$1"
    local scan_name
    scan_name=$(basename "$file" .json)

    # Skip empty files
    if [ ! -s "$file" ]; then
        return
    fi

    local count
    count=$(wc -l < "$file" | tr -d ' ')
    if [ "$count" = "0" ]; then
        return
    fi

    case "$FORMAT" in
        count)
            local critical high medium
            critical=$(grep -c '"severity":"critical"' "$file" 2>/dev/null || echo "0")
            high=$(grep -c '"severity":"high"' "$file" 2>/dev/null || echo "0")
            medium=$(grep -c '"severity":"medium"' "$file" 2>/dev/null || echo "0")
            echo "$scan_name: $count total ($critical critical, $high high, $medium medium)"
            ;;

        critical)
            local crit_findings
            crit_findings=$(grep -E '"severity":"(critical|high)"' "$file" 2>/dev/null || true)
            if [ -n "$crit_findings" ]; then
                local crit_count
                crit_count=$(echo "$crit_findings" | wc -l | tr -d ' ')
                echo "=== $scan_name ($crit_count critical/high) ==="
                echo "$crit_findings" | while IFS= read -r line; do
                    echo "$line" | jq -r '"[\(.info.severity | ascii_upcase)] \(.info.name)
  URL: \(.host)\(.["matched-at"] // "")
  Template: \(."template-id")
  Tags: \(.info.tags | join(", "))
"' 2>/dev/null || echo "$line"
                done
            fi
            ;;

        full)
            echo "=== $scan_name ($count findings) ==="
            cat "$file"
            echo ""
            ;;

        summary|*)
            echo "=== $scan_name ($count findings) ==="
            while IFS= read -r line; do
                echo "$line" | jq -r '"[\(.info.severity)] \(.info.name)
  URL: \(.host)
  Template: \(."template-id")
"' 2>/dev/null || echo "$line"
            done < "$file"
            ;;
    esac
}

# Process specific scan or all scans
if [ -n "$SCAN" ]; then
    FILE="$RESULTS_DIR/$SCAN.json"
    if [ ! -f "$FILE" ]; then
        echo "Error: Scan results not found: $FILE"
        exit 1
    fi
    extract_findings "$FILE"
else
    total=0
    critical_total=0
    high_total=0

    for file in "$RESULTS_DIR"/*.json; do
        [ -f "$file" ] || continue

        if [ -s "$file" ]; then
            count=$(wc -l < "$file" | tr -d ' ')
            if [ "$count" != "0" ]; then
                total=$((total + count))
                crit=$(grep -c '"severity":"critical"' "$file" 2>/dev/null || echo "0")
                high=$(grep -c '"severity":"high"' "$file" 2>/dev/null || echo "0")
                critical_total=$((critical_total + crit))
                high_total=$((high_total + high))
                extract_findings "$file"
            fi
        fi
    done

    if [ "$total" -gt 0 ]; then
        echo ""
        echo "========================================"
        echo "Summary"
        echo "========================================"
        echo "Total findings: $total"
        echo "Critical: $critical_total"
        echo "High: $high_total"

        if [ "$critical_total" -gt 0 ] || [ "$high_total" -gt 0 ]; then
            echo ""
            echo "*** Review critical/high findings immediately ***"
            echo "./scripts/extract-nuclei-findings.sh $ORG critical"
        fi
    else
        echo "No findings in $RESULTS_DIR/"
    fi
fi
