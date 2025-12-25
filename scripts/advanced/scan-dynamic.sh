#!/usr/bin/env bash
set -euo pipefail

# Dynamic Analysis Scanner - Main Orchestration Script
#
# Runs the full dynamic scanning workflow:
# 1. Subdomain enumeration (if domains provided)
# 2. HTTP probing
# 3. Target list building
# 4. Nuclei vulnerability scanning
#
# Usage: ./scripts/scan-dynamic.sh <org-name> [options]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_help() {
    cat << 'EOF'
Usage: ./scripts/scan-dynamic.sh <org-name> [options]

Run dynamic security scans against live web targets.

Options:
  -d, --domain <domain>   Domain(s) for recon (can specify multiple times)
  --recon-only            Only run recon (subdomains + httpx), no scanning
  --skip-recon            Skip recon, use existing targets.txt
  --nuclei-only           Only run nuclei (skip recon and ffuf)
  -t, --templates <cat>   Nuclei template category (default: all-safe)
                          Categories: cves, misconfig, exposures, panels,
                                     takeovers, default-logins, all-safe
  -s, --severity <level>  Nuclei minimum severity (default: medium)
  --interactsh <url>      Interactsh server for OOB detection
  --rate-limit <n>        Requests per second (default: 25)
  -h, --help              Show this help

Workflow Examples:

  # Full workflow: recon + scan
  ./scripts/scan-dynamic.sh acme-corp -d acme.com -d acme.io

  # Recon only (to review targets before scanning)
  ./scripts/scan-dynamic.sh acme-corp -d acme.com --recon-only

  # Scan existing targets (skip recon)
  ./scripts/scan-dynamic.sh acme-corp --skip-recon

  # CVE-only scan with OOB detection
  ./scripts/scan-dynamic.sh acme-corp --skip-recon -t cves --interactsh https://oob.example.com

  # Quick scan with higher severity threshold
  ./scripts/scan-dynamic.sh acme-corp --skip-recon -s high -t cves

Manual Target Setup:
  # Add URLs from a file
  ./scripts/recon-targets.sh acme-corp add-urls urls.txt

  # Then scan
  ./scripts/scan-dynamic.sh acme-corp --skip-recon

Output:
  findings/<org>/dynamic-results/
    ├── recon/              # Subdomain and live host data
    ├── targets.txt         # Master target list
    └── nuclei/             # Vulnerability scan results
EOF
    exit 0
}

if [[ $# -lt 1 ]]; then
    show_help
fi

ORG="$1"
shift

# Defaults
DOMAINS=()
RECON_ONLY=""
SKIP_RECON=""
NUCLEI_ONLY=""
TEMPLATES="all-safe"
SEVERITY="medium"
INTERACTSH_URL=""
RATE_LIMIT="25"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain) DOMAINS+=("$2"); shift 2 ;;
        --recon-only) RECON_ONLY="1"; shift ;;
        --skip-recon) SKIP_RECON="1"; shift ;;
        --nuclei-only) NUCLEI_ONLY="1"; SKIP_RECON="1"; shift ;;
        -t|--templates) TEMPLATES="$2"; shift 2 ;;
        -s|--severity) SEVERITY="$2"; shift 2 ;;
        --interactsh) INTERACTSH_URL="$2"; shift 2 ;;
        --rate-limit) RATE_LIMIT="$2"; shift 2 ;;
        -h|--help) show_help ;;
        *) echo "Unknown option: $1"; show_help ;;
    esac
done

RESULTS_DIR="$(pwd)/findings/$ORG/dynamic-results"
TARGETS_FILE="$RESULTS_DIR/targets.txt"

mkdir -p "$RESULTS_DIR"

echo "========================================"
echo "Dynamic Analysis: $ORG"
echo "========================================"
echo "Results: $RESULTS_DIR/"
echo ""

# Track what phases we'll run
RUN_RECON=""
RUN_SCAN=""

if [[ -z "$SKIP_RECON" ]]; then
    if [[ ${#DOMAINS[@]} -gt 0 ]]; then
        RUN_RECON="1"
    else
        echo "Note: No domains specified, skipping recon phase"
        echo "      Use -d <domain> to enable subdomain enumeration"
        echo ""
    fi
fi

if [[ -z "$RECON_ONLY" ]]; then
    RUN_SCAN="1"
fi

# ==========================================
# Phase 1: Subdomain Enumeration
# ==========================================

if [[ -n "$RUN_RECON" ]]; then
    echo "========================================"
    echo "Phase 1: Subdomain Enumeration"
    echo "========================================"
    echo ""

    "$SCRIPT_DIR/recon-subdomains.sh" "$ORG" "${DOMAINS[@]}"

    echo ""
fi

# ==========================================
# Phase 2: HTTP Probing
# ==========================================

if [[ -n "$RUN_RECON" ]]; then
    SUBDOMAINS_FILE="$RESULTS_DIR/recon/subdomains.txt"

    if [[ -f "$SUBDOMAINS_FILE" ]] && [[ -s "$SUBDOMAINS_FILE" ]]; then
        echo "========================================"
        echo "Phase 2: HTTP Probing"
        echo "========================================"
        echo ""

        "$SCRIPT_DIR/recon-httpx.sh" "$ORG"

        echo ""
    else
        echo "Skipping HTTP probing: no subdomains found"
        echo ""
    fi
fi

# ==========================================
# Phase 3: Build Target List
# ==========================================

if [[ -n "$RUN_RECON" ]]; then
    LIVE_URLS="$RESULTS_DIR/recon/live-urls.txt"

    if [[ -f "$LIVE_URLS" ]] && [[ -s "$LIVE_URLS" ]]; then
        echo "========================================"
        echo "Phase 3: Building Target List"
        echo "========================================"
        echo ""

        "$SCRIPT_DIR/recon-targets.sh" "$ORG" from-recon

        echo ""
    fi
fi

# Check if we have targets for scanning
if [[ -n "$RUN_SCAN" ]]; then
    if [[ ! -f "$TARGETS_FILE" ]] || [[ ! -s "$TARGETS_FILE" ]]; then
        echo "Error: No targets available for scanning"
        echo ""
        echo "Set up targets first:"
        echo "  ./scripts/scan-dynamic.sh $ORG -d <domain>  # Recon workflow"
        echo "  ./scripts/recon-targets.sh $ORG add-urls <file>  # Manual import"
        exit 1
    fi
fi

# Stop here if recon-only
if [[ -n "$RECON_ONLY" ]]; then
    TARGET_COUNT=$(wc -l < "$TARGETS_FILE" 2>/dev/null | xargs || echo "0")

    echo "========================================"
    echo "Recon Complete"
    echo "========================================"
    echo "Targets ready: $TARGET_COUNT"
    echo ""
    echo "Review targets:"
    echo "  ./scripts/recon-targets.sh $ORG list"
    echo ""
    echo "Run vulnerability scan:"
    echo "  ./scripts/scan-dynamic.sh $ORG --skip-recon"
    echo ""
    exit 0
fi

# ==========================================
# Phase 4: Nuclei Vulnerability Scan
# ==========================================

echo "========================================"
echo "Phase 4: Vulnerability Scanning"
echo "========================================"
echo ""

NUCLEI_ARGS=("$ORG" -t "$TEMPLATES" -s "$SEVERITY" --rate-limit "$RATE_LIMIT")
[[ -n "$INTERACTSH_URL" ]] && NUCLEI_ARGS+=(--interactsh "$INTERACTSH_URL")

"$SCRIPT_DIR/scan-nuclei.sh" "${NUCLEI_ARGS[@]}"

echo ""

# ==========================================
# Summary
# ==========================================

echo "========================================"
echo "Dynamic Analysis Complete: $ORG"
echo "========================================"
echo ""
echo "Results directory: $RESULTS_DIR/"
echo ""

# List what we have
if [[ -d "$RESULTS_DIR/recon" ]]; then
    echo "Recon:"
    [[ -f "$RESULTS_DIR/recon/subdomains.txt" ]] && echo "  Subdomains: $(wc -l < "$RESULTS_DIR/recon/subdomains.txt" | xargs)"
    [[ -f "$RESULTS_DIR/recon/live-hosts.json" ]] && echo "  Live hosts: $(wc -l < "$RESULTS_DIR/recon/live-hosts.json" | xargs)"
fi

if [[ -f "$TARGETS_FILE" ]]; then
    echo "Targets: $(wc -l < "$TARGETS_FILE" | xargs)"
fi

if [[ -d "$RESULTS_DIR/nuclei" ]]; then
    NUCLEI_FINDINGS=0
    for f in "$RESULTS_DIR/nuclei"/*.json; do
        [[ -f "$f" ]] || continue
        count=$(wc -l < "$f" | xargs)
        NUCLEI_FINDINGS=$((NUCLEI_FINDINGS + count))
    done
    echo "Nuclei findings: $NUCLEI_FINDINGS"
fi

echo ""
echo "Review findings:"
echo "  ./scripts/extract-nuclei-findings.sh $ORG"
echo "  /review-dynamic $ORG"
echo ""
