#!/usr/bin/env bash
# Extract trufflehog findings from NDJSON result files using DuckDB
# Usage: ./scripts/extract-trufflehog-findings.sh <org-name> [format] [repo-name]
#
# Examples:
#   ./scripts/extract-trufflehog-findings.sh myorg              # All repos, summary format
#   ./scripts/extract-trufflehog-findings.sh myorg verified     # All repos, verified only
#   ./scripts/extract-trufflehog-findings.sh myorg summary repo # Specific repo

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/extract-common.sh
source "$SCRIPT_DIR/lib/extract-common.sh"

# Script-specific configuration (used by extract-common.sh)
# shellcheck disable=SC2034
RESULTS_TYPE="trufflehog-results"
# shellcheck disable=SC2034
CATALOG_FILE="trufflehog.json.gz"
# shellcheck disable=SC2034
SCANNER_CMD="scan-secrets.sh"
# shellcheck disable=SC2034
DEFAULT_FORMAT="summary"
# shellcheck disable=SC2034
AVAILABLE_FORMATS="summary   - One line per finding with key details (default)
  full      - Full JSON for each finding
  count     - Just counts per repo
  verified  - Only verified (confirmed active) secrets
  detectors - Group by detector type"

# Catalog root directory
CATALOG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Get latest scan timestamp for an org
get_latest_scan() {
    local org="$1"
    local scans_dir="$CATALOG_ROOT/catalog/tracked/$org/scans"
    if [[ ! -d "$scans_dir" ]]; then
        return 1
    fi
    ls -1 "$scans_dir" 2>/dev/null | sort -r | head -1
}

# Custom init for trufflehog (handles empty files and NDJSON format)
# Note: Regular repo scans produce NDJSON (one JSON per line)
# Archive scans (*-archives.json) produce standard JSON arrays - excluded here
trufflehog_init() {
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

    ORG="${positional[0]:-}"
    FORMAT="${positional[1]:-$DEFAULT_FORMAT}"
    REPO="${positional[2]:-}"

    if [[ -z "$ORG" ]]; then
        extract_usage "$(basename "$0")"
        exit 1
    fi

    check_duckdb

    if [[ -n "$CATALOG_MODE" ]]; then
        # CATALOG MODE: Read from catalog scans (merged gzipped NDJSON)
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
            exit 1
        fi

        PATTERN="$RESULTS_DIR/$CATALOG_FILE"
        if [[ ! -f "$PATTERN" ]]; then
            echo "No findings in scan $SCAN_TIMESTAMP"
            exit 0
        fi

        echo "Reading from catalog scan: $SCAN_TIMESTAMP" >&2
        echo "" >&2

        if [[ -n "$REPO" ]]; then
            warn "Catalog mode uses merged files; repo filter '$REPO' ignored"
        fi
        REPO=""
    else
        # FINDINGS MODE: Read from findings/ directory (per-repo NDJSON files)
        RESULTS_DIR="findings/$ORG/$RESULTS_TYPE"

        if [[ ! -d "$RESULTS_DIR" ]]; then
            err "Results directory not found: $RESULTS_DIR"
            echo "Run $SCANNER_CMD first, or use --catalog to read from catalog scans." >&2
            exit 1
        fi

        # Build file pattern and check for non-empty files
        # Note: We use a file list to exclude *-archives.json (different format)
        # Support both .json.gz (new) and .json (legacy) formats
        if [[ -n "$REPO" ]]; then
            if [[ -f "$RESULTS_DIR/$REPO.json.gz" ]]; then
                PATTERN="$RESULTS_DIR/$REPO.json.gz"
                # Check if gzipped file has content
                if [[ $(gzip -dc "$PATTERN" 2>/dev/null | wc -l) -eq 0 ]]; then
                    echo "No findings in $REPO"
                    exit 0
                fi
            elif [[ -f "$RESULTS_DIR/$REPO.json" ]]; then
                PATTERN="$RESULTS_DIR/$REPO.json"
                if [[ ! -s "$PATTERN" ]]; then
                    echo "No findings in $REPO"
                    exit 0
                fi
            else
                err "Results file not found: $RESULTS_DIR/$REPO.json.gz (or .json)"
                exit 1
            fi
        else
            # Build list of NDJSON files, excluding archive results
            # Check for gzipped files first, then uncompressed
            shopt -s nullglob
            local ndjson_files=()

            # Try gzipped files first
            for f in "$RESULTS_DIR"/*.json.gz; do
                # Skip archive results (different format)
                if [[ ! "$f" =~ -archives\.json\.gz$ ]]; then
                    # Check if file has content
                    if [[ $(gzip -dc "$f" 2>/dev/null | wc -l) -gt 0 ]]; then
                        ndjson_files+=("$f")
                    fi
                fi
            done

            # Fall back to uncompressed if no gzipped files
            if [[ ${#ndjson_files[@]} -eq 0 ]]; then
                for f in "$RESULTS_DIR"/*.json; do
                    # Skip empty files and archive results (different format)
                    if [[ -s "$f" && ! "$f" =~ -archives\.json$ ]]; then
                        ndjson_files+=("$f")
                    fi
                done
            fi
            shopt -u nullglob

            if [[ ${#ndjson_files[@]} -eq 0 ]]; then
                echo "No findings in $RESULTS_DIR"
                exit 0
            fi

            # DuckDB supports list syntax for multiple files
            PATTERN=$(printf "'%s'," "${ndjson_files[@]}")
            PATTERN="[${PATTERN%,}]"
        fi
    fi

    export ORG FORMAT REPO RESULTS_DIR PATTERN CATALOG_MODE SCAN_TIMESTAMP
}

trufflehog_init "$@"

# Build the read_json call for NDJSON
# Handle both single file (quoted path) and multiple files (list syntax)
if [[ "$PATTERN" =~ ^\[ ]]; then
    # List syntax: ['/path/to/file1.json','/path/to/file2.json']
    READ_JSON="read_json($PATTERN, format='newline_delimited', ignore_errors=true)"
else
    # Single file path
    READ_JSON="read_json('$PATTERN', format='newline_delimited', ignore_errors=true)"
fi

# Field accessors for Git-based scans (most common)
# Note: Filesystem scans use different paths but are rare
FILE_PATH="SourceMetadata.Data.Git.file"
LINE_NUM="SourceMetadata.Data.Git.line"
COMMIT="SourceMetadata.Data.Git.commit"

case "$FORMAT" in
    count)
        duckdb -c "
            SELECT
                regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                count(*) as findings,
                sum(CASE WHEN Verified THEN 1 ELSE 0 END) as verified
            FROM $READ_JSON
            GROUP BY repo
            HAVING findings > 0
            ORDER BY verified DESC, findings DESC
        " 2>/dev/null || echo "No findings found."

        if [[ -z "$REPO" ]]; then
            totals=$(duckdb_scalar "
                SELECT
                    count(*) || ',' || sum(CASE WHEN Verified THEN 1 ELSE 0 END)
                FROM $READ_JSON
            ")
            total=$(echo "$totals" | cut -d',' -f1)
            verified=$(echo "$totals" | cut -d',' -f2)
            echo ""
            echo "Total: ${total:-0} findings (${verified:-0} verified)"
            if [[ "${verified:-0}" -gt 0 ]]; then
                echo ""
                echo -e "${RED}WARNING: $verified verified secrets require immediate rotation!${NC}"
            fi
        fi
        ;;

    summary)
        duckdb -c "
            SELECT
                regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                CASE WHEN Verified THEN '[VERIFIED]' ELSE '[unverified]' END as status,
                DetectorName as detector,
                $FILE_PATH as file,
                $LINE_NUM as line,
                substring($COMMIT, 1, 12) as commit
            FROM $READ_JSON
            ORDER BY
                Verified DESC,
                repo,
                DetectorName,
                $FILE_PATH
        " 2>/dev/null || echo "No findings found."

        if [[ -z "$REPO" ]]; then
            totals=$(duckdb_scalar "
                SELECT
                    count(*) || ',' || sum(CASE WHEN Verified THEN 1 ELSE 0 END)
                FROM $READ_JSON
            ")
            total=$(echo "$totals" | cut -d',' -f1)
            verified=$(echo "$totals" | cut -d',' -f2)
            echo ""
            echo "Total: ${total:-0} findings (${verified:-0} verified)"
        fi
        ;;

    verified)
        result=$(duckdb -c "
            SELECT
                regexp_extract(filename, '([^/]+)\\.json(\\.gz)?\$', 1) as repo,
                DetectorName as detector,
                $FILE_PATH as file,
                $LINE_NUM as line,
                substring(Raw, 1, 20) || '...' as secret_preview
            FROM $READ_JSON
            WHERE Verified = true
            ORDER BY repo, DetectorName, $FILE_PATH
        " 2>/dev/null)

        if [[ -z "$result" || "$result" == *"0 rows"* ]]; then
            echo "No verified secrets found."
        else
            echo -e "${RED}VERIFIED SECRETS (confirmed active):${NC}"
            echo ""
            echo "$result"
            count=$(duckdb_scalar "
                SELECT count(*)
                FROM $READ_JSON
                WHERE Verified = true
            ")
            echo ""
            echo -e "${RED}WARNING: ${count:-0} verified secrets require immediate rotation!${NC}"
        fi
        ;;

    full)
        duckdb -json -c "
            SELECT *
            FROM $READ_JSON
            ORDER BY Verified DESC, DetectorName
        " 2>/dev/null | jq '.'
        ;;

    detectors)
        echo "Findings by detector type:"
        echo ""
        duckdb -c "
            SELECT
                DetectorName as detector,
                count(*) as count,
                sum(CASE WHEN Verified THEN 1 ELSE 0 END) as verified
            FROM $READ_JSON
            GROUP BY DetectorName
            ORDER BY verified DESC, count DESC
        " 2>/dev/null || echo "No findings found."
        ;;

    *)
        unknown_format "$FORMAT"
        ;;
esac
