#!/usr/bin/env bash
set -euo pipefail

# Nuclei vulnerability scanner with template categories
#
# Scans targets for known vulnerabilities, misconfigurations, and exposures
# using Nuclei's template library.
#
# Usage: ./scripts/scan-nuclei.sh <org-name> [options]
# Output: findings/<org>/dynamic-results/nuclei/<scan-name>.json

show_help() {
    cat << 'EOF'
Usage: ./scripts/scan-nuclei.sh <org-name> [options]

Scan targets for vulnerabilities using Nuclei templates.

Options:
  -t, --templates <category>  Template category (default: all-safe)
                              Categories:
                                cves         - Known CVEs with PoC
                                misconfig    - Misconfigurations
                                exposures    - Sensitive file exposure
                                panels       - Exposed admin panels
                                takeovers    - Subdomain takeovers
                                default-logins - Default credentials
                                all-safe     - All except DoS/fuzzing (default)
  -s, --severity <level>      Minimum severity (default: medium)
                              Levels: info, low, medium, high, critical
  -rl, --rate-limit <n>       Requests per second (default: 25)
  --interactsh <url>          Interactsh server for OOB detection
  -o, --output <name>         Output file name (default: scan-<timestamp>)
  --tags <tags>               Custom nuclei tags (comma-separated)
  -h, --help                  Show this help

Examples:
  # Default safe scan
  ./scripts/scan-nuclei.sh acme-corp

  # CVE-only scan with high severity filter
  ./scripts/scan-nuclei.sh acme-corp -t cves -s high

  # Scan with OOB detection
  ./scripts/scan-nuclei.sh acme-corp --interactsh https://oob.example.com

  # Custom tags
  ./scripts/scan-nuclei.sh acme-corp --tags "rce,sqli,ssrf"

Prerequisites:
  - Targets file: findings/<org>/dynamic-results/targets.txt
  - Run ./scripts/recon-targets.sh to set up targets
EOF
    exit 0
}

if [[ $# -lt 1 ]]; then
    show_help
fi

ORG="$1"
shift

# Defaults
TEMPLATES="all-safe"
SEVERITY="medium"
RATE_LIMIT="25"
INTERACTSH_URL=""
OUTPUT_NAME="scan-$(date +%Y%m%d-%H%M%S)"
CUSTOM_TAGS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--templates) TEMPLATES="$2"; shift 2 ;;
        -s|--severity) SEVERITY="$2"; shift 2 ;;
        -rl|--rate-limit) RATE_LIMIT="$2"; shift 2 ;;
        --interactsh) INTERACTSH_URL="$2"; shift 2 ;;
        -o|--output) OUTPUT_NAME="$2"; shift 2 ;;
        --tags) CUSTOM_TAGS="$2"; shift 2 ;;
        -h|--help) show_help ;;
        *) echo "Unknown option: $1"; show_help ;;
    esac
done

RESULTS_DIR="$(pwd)/findings/$ORG/dynamic-results/nuclei"
TARGETS_FILE="$(pwd)/findings/$ORG/dynamic-results/targets.txt"
OUTPUT_FILE="$RESULTS_DIR/$OUTPUT_NAME.json"
LOG_FILE="$RESULTS_DIR/$OUTPUT_NAME.log"

mkdir -p "$RESULTS_DIR"

if [[ ! -f "$TARGETS_FILE" ]] || [[ ! -s "$TARGETS_FILE" ]]; then
    echo "Error: No targets file found or file is empty: $TARGETS_FILE"
    echo ""
    echo "Set up targets first:"
    echo "  ./scripts/recon-targets.sh $ORG add-urls <file>"
    echo "  ./scripts/recon-targets.sh $ORG from-recon"
    exit 1
fi

if ! command -v nuclei &> /dev/null; then
    echo "Error: nuclei is required but not installed."
    echo "Run: ./scripts/setup-dynamic-tools.sh"
    exit 1
fi

TARGET_COUNT=$(wc -l < "$TARGETS_FILE" | xargs)

echo "========================================"
echo "Nuclei Vulnerability Scan: $ORG"
echo "========================================"
echo "Targets: $TARGET_COUNT"
echo "Templates: $TEMPLATES"
echo "Severity: $SEVERITY+"
echo "Rate limit: $RATE_LIMIT req/sec"
[[ -n "$INTERACTSH_URL" ]] && echo "Interactsh: $INTERACTSH_URL"
echo "Output: $OUTPUT_FILE"
echo "========================================"
echo ""

# Build nuclei arguments
NUCLEI_ARGS=(
    -l "$TARGETS_FILE"
    -rate-limit "$RATE_LIMIT"
    -jsonl
    -o "$OUTPUT_FILE"
    -nc  # No color for cleaner logs
)

# Add severity filter
case "$SEVERITY" in
    info)     NUCLEI_ARGS+=(-severity "info,low,medium,high,critical") ;;
    low)      NUCLEI_ARGS+=(-severity "low,medium,high,critical") ;;
    medium)   NUCLEI_ARGS+=(-severity "medium,high,critical") ;;
    high)     NUCLEI_ARGS+=(-severity "high,critical") ;;
    critical) NUCLEI_ARGS+=(-severity "critical") ;;
esac

# Add template selection
if [[ -n "$CUSTOM_TAGS" ]]; then
    NUCLEI_ARGS+=(-tags "$CUSTOM_TAGS")
elif [[ "$TEMPLATES" == "all-safe" ]]; then
    # Exclude dangerous templates
    NUCLEI_ARGS+=(-etags "dos,fuzz,intrusive")
else
    # Map category names to nuclei tags
    case "$TEMPLATES" in
        cves)           NUCLEI_ARGS+=(-tags "cve") ;;
        misconfig)      NUCLEI_ARGS+=(-tags "misconfig") ;;
        exposures)      NUCLEI_ARGS+=(-tags "exposure") ;;
        panels)         NUCLEI_ARGS+=(-tags "panel") ;;
        takeovers)      NUCLEI_ARGS+=(-tags "takeover") ;;
        default-logins) NUCLEI_ARGS+=(-tags "default-login") ;;
        *)              NUCLEI_ARGS+=(-tags "$TEMPLATES") ;;
    esac
fi

# Add interactsh if configured
if [[ -n "$INTERACTSH_URL" ]]; then
    NUCLEI_ARGS+=(-iserver "$INTERACTSH_URL")
fi

echo "Starting scan..."
echo ""

# Run nuclei and tee to log file
nuclei "${NUCLEI_ARGS[@]}" 2>&1 | tee "$LOG_FILE"

echo ""
echo "========================================"
echo "Scan Complete"
echo "========================================"

# Process results
if [[ -f "$OUTPUT_FILE" ]] && [[ -s "$OUTPUT_FILE" ]]; then
    FINDING_COUNT=$(wc -l < "$OUTPUT_FILE" | xargs)
    echo "Findings: $FINDING_COUNT"
    echo ""

    echo "Severity breakdown:"
    jq -r '.info.severity' "$OUTPUT_FILE" 2>/dev/null | sort | uniq -c | sort -rn | sed 's/^/  /'
    echo ""

    echo "Top templates:"
    jq -r '"\(.["template-id"]) (\(.info.severity))"' "$OUTPUT_FILE" 2>/dev/null | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
    echo ""

    # Check for critical/high findings
    CRITICAL_COUNT=$(grep -c '"severity":"critical"' "$OUTPUT_FILE" 2>/dev/null || echo "0")
    HIGH_COUNT=$(grep -c '"severity":"high"' "$OUTPUT_FILE" 2>/dev/null || echo "0")

    if [[ "$CRITICAL_COUNT" -gt 0 ]] || [[ "$HIGH_COUNT" -gt 0 ]]; then
        echo "*** HIGH-PRIORITY FINDINGS ***"
        echo "Critical: $CRITICAL_COUNT"
        echo "High: $HIGH_COUNT"
        echo ""
    fi
else
    echo "No findings"
fi

echo "Results: $OUTPUT_FILE"
echo "Log: $LOG_FILE"
echo ""
echo "Review findings:"
echo "  ./scripts/extract-nuclei-findings.sh $ORG"
echo "  /review-dynamic $ORG"
echo ""
