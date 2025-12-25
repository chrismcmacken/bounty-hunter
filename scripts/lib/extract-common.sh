#!/usr/bin/env bash
# Common functions for extract-*.sh scripts
# Source this file, don't execute it directly
#
# Usage in extract scripts:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$SCRIPT_DIR/lib/extract-common.sh"
#
#   RESULTS_TYPE="semgrep-results"  # or trufflehog-results, artifact-results, kics-results
#   CATALOG_FILE="semgrep.json.gz"  # filename in catalog scans (gzipped)
#   SCANNER_CMD="scan-semgrep.sh"   # for error messages
#   DEFAULT_FORMAT="summary"
#   AVAILABLE_FORMATS="summary, full, count, jsonl, rules"
#
#   extract_init "$@"
#   # Now ORG, FORMAT, REPO, PATTERN, RESULTS_DIR, CATALOG_MODE are set

set -euo pipefail

# DuckDB read_json options for large files (100MB limit)
DUCKDB_JSON_OPTS="maximum_object_size=104857600"

# Catalog root directory
CATALOG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Colors for output (if terminal supports it)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    NC='\033[0m' # No Color
else
    RED=''
    YELLOW=''
    NC=''
fi

# Print error message to stderr
err() {
    echo -e "${RED}Error:${NC} $*" >&2
}

# Print warning message to stderr
warn() {
    echo -e "${YELLOW}Warning:${NC} $*" >&2
}

# Check if DuckDB is installed
check_duckdb() {
    if ! command -v duckdb &> /dev/null; then
        err "DuckDB is required but not installed."
        echo "Install: brew install duckdb" >&2
        exit 1
    fi
}

# Show usage for extract scripts
# Args: $1 = script name (basename)
extract_usage() {
    local script_name="$1"
    cat << EOF
Usage: $script_name <org-name> [format] [repo-name]
       $script_name <org-name> --catalog [format] [scan-timestamp]

Sources:
  (default)           Read from findings/<org>/$RESULTS_TYPE/ (per-repo files)
  --catalog           Read from catalog scans (merged gzipped files)
  --scan <timestamp>  Read specific catalog scan (e.g., 2025-12-24-1427)

Formats:
EOF
    # AVAILABLE_FORMATS should be set by the calling script
    echo "$AVAILABLE_FORMATS" | tr ',' '\n' | while read -r fmt; do
        fmt=$(echo "$fmt" | xargs)  # trim whitespace
        [[ -n "$fmt" ]] && echo "  $fmt"
    done
    echo ""
    echo "Examples:"
    echo "  $script_name myorg                    # From findings/"
    echo "  $script_name myorg --catalog          # From latest catalog scan"
    echo "  $script_name myorg --scan 2025-12-24  # From specific scan"
}

# Get latest scan timestamp for an org
# Args: $1 = org name
get_latest_scan() {
    local org="$1"
    local scans_dir="$CATALOG_ROOT/catalog/tracked/$org/scans"

    if [[ ! -d "$scans_dir" ]]; then
        return 1
    fi

    # Get most recent scan directory
    ls -1 "$scans_dir" 2>/dev/null | sort -r | head -1
}

# Initialize extraction: parse args, validate, set up patterns
# Sets: ORG, FORMAT, REPO, RESULTS_DIR, PATTERN, CATALOG_MODE, SCAN_TIMESTAMP
# Requires: RESULTS_TYPE, CATALOG_FILE, SCANNER_CMD, DEFAULT_FORMAT to be set
extract_init() {
    local args=("$@")
    local positional=()
    CATALOG_MODE=""
    SCAN_TIMESTAMP=""

    # Parse flags
    local i=0
    while [[ $i -lt ${#args[@]} ]]; do
        case "${args[$i]}" in
            -h|--help)
                extract_usage "$(basename "$0")"
                exit 0
                ;;
            --catalog)
                CATALOG_MODE="1"
                ((i++))
                ;;
            --scan)
                CATALOG_MODE="1"
                ((i++))
                if [[ $i -lt ${#args[@]} ]]; then
                    SCAN_TIMESTAMP="${args[$i]}"
                    ((i++))
                else
                    err "--scan requires a timestamp argument"
                    exit 1
                fi
                ;;
            *)
                positional+=("${args[$i]}")
                ((i++))
                ;;
        esac
    done

    # Extract positional arguments
    ORG="${positional[0]:-}"
    FORMAT="${positional[1]:-$DEFAULT_FORMAT}"
    REPO="${positional[2]:-}"

    # Require org name
    if [[ -z "$ORG" ]]; then
        extract_usage "$(basename "$0")"
        exit 1
    fi

    # Check DuckDB
    check_duckdb

    if [[ -n "$CATALOG_MODE" ]]; then
        # CATALOG MODE: Read from catalog scans (merged gzipped files)

        # Get scan timestamp (latest if not specified)
        if [[ -z "$SCAN_TIMESTAMP" ]]; then
            SCAN_TIMESTAMP=$(get_latest_scan "$ORG")
            if [[ -z "$SCAN_TIMESTAMP" ]]; then
                err "No catalog scans found for '$ORG'"
                echo "Run: ./scripts/catalog-scan.sh $ORG" >&2
                exit 1
            fi
        fi

        RESULTS_DIR="$CATALOG_ROOT/catalog/tracked/$ORG/scans/$SCAN_TIMESTAMP"

        if [[ ! -d "$RESULTS_DIR" ]]; then
            err "Scan not found: $RESULTS_DIR"
            echo "Available scans:" >&2
            ls -1 "$CATALOG_ROOT/catalog/tracked/$ORG/scans" 2>/dev/null | head -5 >&2
            exit 1
        fi

        # Check for catalog file (gzipped)
        PATTERN="$RESULTS_DIR/${CATALOG_FILE:-$RESULTS_TYPE.json.gz}"
        if [[ ! -f "$PATTERN" ]]; then
            # Try without .gz extension
            PATTERN="${PATTERN%.gz}"
            if [[ ! -f "$PATTERN" ]]; then
                echo "No findings in scan $SCAN_TIMESTAMP"
                exit 0
            fi
        fi

        echo "Reading from catalog scan: $SCAN_TIMESTAMP" >&2
        echo "" >&2

        # REPO is used as format in catalog mode (second positional)
        # Catalog files are merged, so no per-repo filtering
        if [[ -n "$REPO" ]]; then
            warn "Catalog mode uses merged files; repo filter '$REPO' ignored"
        fi
        REPO=""

    else
        # FINDINGS MODE: Read from findings/ directory (per-repo files)
        RESULTS_DIR="findings/$ORG/$RESULTS_TYPE"

        # Check results directory exists
        if [[ ! -d "$RESULTS_DIR" ]]; then
            err "Results directory not found: $RESULTS_DIR"
            echo "Run $SCANNER_CMD first, or use --catalog to read from catalog scans." >&2
            exit 1
        fi

        # Build file pattern - prefer .json.gz, fall back to .json for backwards compatibility
        if [[ -n "$REPO" ]]; then
            if [[ -f "$RESULTS_DIR/$REPO.json.gz" ]]; then
                PATTERN="$RESULTS_DIR/$REPO.json.gz"
            elif [[ -f "$RESULTS_DIR/$REPO.json" ]]; then
                PATTERN="$RESULTS_DIR/$REPO.json"
            else
                err "Results file not found: $RESULTS_DIR/$REPO.json.gz (or .json)"
                exit 1
            fi
        else
            # Check for gzipped files first, then uncompressed
            shopt -s nullglob
            local gz_files=("$RESULTS_DIR"/*.json.gz)
            local json_files=("$RESULTS_DIR"/*.json)
            shopt -u nullglob

            if [[ ${#gz_files[@]} -gt 0 ]]; then
                PATTERN="$RESULTS_DIR/*.json.gz"
            elif [[ ${#json_files[@]} -gt 0 ]]; then
                PATTERN="$RESULTS_DIR/*.json"
            else
                echo "No result files found in $RESULTS_DIR"
                exit 0
            fi
        fi
    fi

    # Export for use in calling script
    export ORG FORMAT REPO RESULTS_DIR PATTERN CATALOG_MODE SCAN_TIMESTAMP
}

# Check if any non-empty files exist (for NDJSON like trufflehog)
# Returns 0 if found, 1 if not
has_nonempty_files() {
    local dir="$1"
    shopt -s nullglob
    for f in "$dir"/*.json; do
        if [[ -s "$f" ]]; then
            shopt -u nullglob
            return 0
        fi
    done
    shopt -u nullglob
    return 1
}

# Run DuckDB query with standard JSON options
# Args: query string
# Uses PATTERN from extract_init
duckdb_json() {
    duckdb -c "$1" 2>/dev/null
}

# Run DuckDB query and output as JSON
duckdb_json_output() {
    duckdb -json -c "$1" 2>/dev/null | jq '.'
}

# Run DuckDB query and output as JSONL (one object per line)
duckdb_jsonl_output() {
    duckdb -json -c "$1" 2>/dev/null | jq -c '.[]'
}

# Get a single value from DuckDB (no header, CSV format)
# Strips quotes from string results
duckdb_scalar() {
    local result
    result=$(duckdb -noheader -csv -c "$1" 2>/dev/null || echo "")
    # Strip surrounding quotes if present
    result="${result#\"}"
    result="${result%\"}"
    echo "$result"
}

# Build read_json call with standard options for regular JSON
# Args: $1 = pattern (defaults to $PATTERN)
read_json_opts() {
    local pattern="${1:-$PATTERN}"
    echo "read_json('$pattern', ignore_errors=true, $DUCKDB_JSON_OPTS)"
}

# Build read_json call for newline-delimited JSON (trufflehog)
read_ndjson_opts() {
    local pattern="${1:-$PATTERN}"
    echo "read_json('$pattern', format='newline_delimited', ignore_errors=true)"
}

# Print total count footer
# Args: $1 = label, $2 = count
print_total() {
    echo ""
    echo "Total: $2 $1"
}

# Handle unknown format error
unknown_format() {
    local format="$1"
    err "Unknown format: $format"
    echo "Available formats: $AVAILABLE_FORMATS" >&2
    exit 1
}
