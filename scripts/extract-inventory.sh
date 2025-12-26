#!/usr/bin/env bash
set -euo pipefail

# Inventory Extraction - Query language and dependency data with DuckDB
#
# Data sources:
#   - Languages: catalog/languages.json (global)
#   - SBOMs: scans/<org>/inventory/*-sbom.json.gz (per-repo, gzipped)
#
# Dependencies: duckdb, jq

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME <org-name|--all> [FORMAT] [OPTIONS]

Extract inventory data using DuckDB queries.

Arguments:
  org-name              Organization to query (or --all for all orgs)
  FORMAT                Output format (default: summary)

Formats:
  summary       Overview of languages and packages
  languages     Language breakdown with LOC counts
  packages      All packages/dependencies
  cve-ready     Package list for CVE lookup (name, version, purl)
  types         Package types distribution (npm, pip, go-module, etc.)
  count         Quick counts only

Options:
  --all                 Query all organizations
  --repo <name>         Filter to specific repository
  --json                Output as JSON
  -h, --help            Show this help message

Examples:
  $SCRIPT_NAME hemi                    # Summary for hemi
  $SCRIPT_NAME hemi languages          # Language breakdown
  $SCRIPT_NAME hemi packages           # All packages
  $SCRIPT_NAME --all languages         # Languages across all orgs
  $SCRIPT_NAME hemi packages --repo api-server  # Packages in one repo
EOF
    exit 0
}

# Parse arguments
ORG=""
FORMAT="summary"
REPO=""
ALL_ORGS=false
JSON_OUTPUT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        --all)
            ALL_ORGS=true
            shift
            ;;
        --repo)
            REPO="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            usage
            ;;
        *)
            if [[ -z "$ORG" && "$ALL_ORGS" == false ]]; then
                ORG="$1"
            elif [[ "$FORMAT" == "summary" ]]; then
                FORMAT="$1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$ORG" && "$ALL_ORGS" == false ]]; then
    echo "Error: Organization name or --all required" >&2
    usage
fi

# Check dependencies
if ! command -v duckdb &>/dev/null; then
    echo "Error: duckdb is required but not installed." >&2
    echo "Install: brew install duckdb" >&2
    exit 1
fi

LANGUAGES_FILE="$ROOT_DIR/catalog/languages.json"

# Build SBOM file pattern (prefer .json.gz, fall back to .json for backwards compatibility)
build_sbom_pattern() {
    local base_path="$1"
    local pattern="$2"

    # Check if gzipped files exist
    shopt -s nullglob
    local gz_files=("$base_path"/$pattern.gz)
    local json_files=("$base_path"/$pattern)
    shopt -u nullglob

    if [[ ${#gz_files[@]} -gt 0 ]]; then
        echo "$base_path/${pattern}.gz"
    elif [[ ${#json_files[@]} -gt 0 ]]; then
        echo "$base_path/$pattern"
    else
        # Default to gz pattern
        echo "$base_path/${pattern}.gz"
    fi
}

if [[ "$ALL_ORGS" == true ]]; then
    # For all orgs, build a pattern that covers both formats
    SBOM_PATTERN="$ROOT_DIR/scans/*/inventory/*-sbom.json*"
elif [[ -n "$REPO" ]]; then
    if [[ -f "$ROOT_DIR/scans/$ORG/inventory/${REPO}-sbom.json.gz" ]]; then
        SBOM_PATTERN="$ROOT_DIR/scans/$ORG/inventory/${REPO}-sbom.json.gz"
    else
        SBOM_PATTERN="$ROOT_DIR/scans/$ORG/inventory/${REPO}-sbom.json"
    fi
else
    SBOM_PATTERN=$(build_sbom_pattern "$ROOT_DIR/scans/$ORG/inventory" "*-sbom.json")
fi

# Check if data exists
check_languages_data() {
    if [[ ! -f "$LANGUAGES_FILE" ]]; then
        echo "No language data found. Run: ./scripts/scan-inventory.sh <org>" >&2
        return 1
    fi
    return 0
}

check_sbom_data() {
    shopt -s nullglob
    # Check for both .json and .json.gz files
    local gz_files=("${SBOM_PATTERN%.json*}-sbom.json.gz" 2>/dev/null || true)
    local json_files=("${SBOM_PATTERN%.json*}-sbom.json" 2>/dev/null || true)
    local pattern_files=($SBOM_PATTERN)
    shopt -u nullglob

    if [[ ${#pattern_files[@]} -eq 0 ]]; then
        echo "No SBOM data found. Run: ./scripts/scan-inventory.sh <org>" >&2
        return 1
    fi
    return 0
}

# Query functions
query_summary() {
    echo "=== Inventory Summary ==="
    echo ""

    if check_languages_data 2>/dev/null; then
        echo "Languages:"
        if [[ "$ALL_ORGS" == true ]]; then
            duckdb -c "
                WITH lang_data AS (
                    SELECT
                        key as org,
                        json_extract(value, '$.totals') as totals
                    FROM (
                        SELECT unnest(json_keys(orgs)) as key,
                               json_extract(orgs, '$.' || unnest(json_keys(orgs))) as value
                        FROM read_json('$LANGUAGES_FILE')
                    )
                )
                SELECT
                    '  ' || COUNT(DISTINCT org) || ' orgs scanned' as summary
                FROM lang_data;
            " 2>/dev/null || echo "  (no data)"
        else
            duckdb -c "
                SELECT
                    '  ' || json_array_length(json_keys(json_extract(orgs, '$.$ORG.repos'))) || ' repos, ' ||
                    json_array_length(json_keys(json_extract(orgs, '$.$ORG.totals'))) || ' languages'
                FROM read_json('$LANGUAGES_FILE')
                WHERE json_extract(orgs, '$.$ORG') IS NOT NULL;
            " 2>/dev/null || echo "  (no data for $ORG)"
        fi
        echo ""
    fi

    if check_sbom_data 2>/dev/null; then
        echo "Packages:"
        duckdb -c "
            SELECT
                '  ' || COUNT(*) || ' packages across ' ||
                COUNT(DISTINCT regexp_extract(filename, '/([^/]+)-sbom\.json', 1)) || ' repos'
            FROM read_json('$SBOM_PATTERN', ignore_errors=true, union_by_name=true),
            UNNEST(artifacts) as pkg;
        " 2>/dev/null || echo "  (no data)"
    fi
}

query_languages() {
    check_languages_data || return 1

    if [[ "$JSON_OUTPUT" == true ]]; then
        if [[ "$ALL_ORGS" == true ]]; then
            jq '.orgs | to_entries | map({org: .key, totals: .value.totals})' "$LANGUAGES_FILE"
        else
            jq --arg org "$ORG" '.orgs[$org].totals' "$LANGUAGES_FILE"
        fi
        return
    fi

    echo "Language Distribution"
    echo ""

    if [[ "$ALL_ORGS" == true ]]; then
        # Query all orgs
        duckdb -c "
            WITH all_langs AS (
                SELECT
                    org_key as org,
                    lang_key as language,
                    CAST(json_extract(lang_val, '$.Code') AS INTEGER) as code_loc,
                    CAST(json_extract(lang_val, '$.Files') AS INTEGER) as files
                FROM (
                    SELECT
                        unnest(json_keys(orgs)) as org_key,
                        json_extract(orgs, '$.' || unnest(json_keys(orgs)) || '.totals') as totals
                    FROM read_json('$LANGUAGES_FILE')
                ),
                LATERAL (
                    SELECT
                        unnest(json_keys(totals)) as lang_key,
                        json_extract(totals, '$.' || unnest(json_keys(totals))) as lang_val
                )
            )
            SELECT
                language as Language,
                SUM(files) as Files,
                SUM(code_loc) as \"Code LOC\",
                COUNT(DISTINCT org) as Orgs
            FROM all_langs
            GROUP BY language
            ORDER BY SUM(code_loc) DESC
            LIMIT 20;
        " 2>/dev/null || echo "No language data found"
    else
        # Query single org
        duckdb -c "
            WITH org_langs AS (
                SELECT
                    lang_key as language,
                    CAST(json_extract(lang_val, '$.Code') AS INTEGER) as code_loc,
                    CAST(json_extract(lang_val, '$.Files') AS INTEGER) as files,
                    CAST(json_extract(lang_val, '$.Repos') AS INTEGER) as repos
                FROM (
                    SELECT json_extract(orgs, '$.$ORG.totals') as totals
                    FROM read_json('$LANGUAGES_FILE')
                ),
                LATERAL (
                    SELECT
                        unnest(json_keys(totals)) as lang_key,
                        json_extract(totals, '$.' || unnest(json_keys(totals))) as lang_val
                )
            )
            SELECT
                language as Language,
                files as Files,
                code_loc as \"Code LOC\",
                repos as Repos
            FROM org_langs
            ORDER BY code_loc DESC
            LIMIT 20;
        " 2>/dev/null || echo "No language data found for $ORG"
    fi
}

query_packages() {
    check_sbom_data || return 1

    if [[ "$JSON_OUTPUT" == true ]]; then
        duckdb -json -c "
            SELECT
                pkg.name,
                pkg.version,
                pkg.type,
                pkg.purl,
                regexp_extract(filename, '/([^/]+)-sbom\.json', 1) as repo
            FROM read_json('$SBOM_PATTERN', ignore_errors=true, union_by_name=true),
            UNNEST(artifacts) as pkg
            ORDER BY pkg.type, pkg.name, pkg.version;
        " 2>/dev/null | jq '.'
        return
    fi

    echo "Packages"
    echo ""
    duckdb -c "
        SELECT
            pkg.name as Name,
            pkg.version as Version,
            pkg.type as Type,
            regexp_extract(filename, '/([^/]+)-sbom\.json', 1) as Repo
        FROM read_json('$SBOM_PATTERN', ignore_errors=true, union_by_name=true),
        UNNEST(artifacts) as pkg
        ORDER BY pkg.type, pkg.name
        LIMIT 100;
    " 2>/dev/null || echo "No package data found"

    echo ""
    echo "(showing first 100, use --json for full list)"
}

query_cve_ready() {
    check_sbom_data || return 1

    if [[ "$JSON_OUTPUT" == true ]]; then
        duckdb -json -c "
            SELECT DISTINCT
                pkg.name,
                pkg.version,
                pkg.type,
                pkg.purl
            FROM read_json('$SBOM_PATTERN', ignore_errors=true, union_by_name=true),
            UNNEST(artifacts) as pkg
            WHERE pkg.purl IS NOT NULL
            ORDER BY pkg.type, pkg.name, pkg.version;
        " 2>/dev/null | jq '.'
        return
    fi

    echo "CVE-Ready Package List"
    echo ""
    echo "# Format: purl (for CVE database lookup)"
    echo ""
    duckdb -noheader -c "
        SELECT DISTINCT pkg.purl
        FROM read_json('$SBOM_PATTERN', ignore_errors=true, union_by_name=true),
        UNNEST(artifacts) as pkg
        WHERE pkg.purl IS NOT NULL
        ORDER BY pkg.purl;
    " 2>/dev/null || echo "No package data found"
}

query_types() {
    check_sbom_data || return 1

    if [[ "$JSON_OUTPUT" == true ]]; then
        duckdb -json -c "
            SELECT
                pkg.type as type,
                COUNT(*) as count
            FROM read_json('$SBOM_PATTERN', ignore_errors=true, union_by_name=true),
            UNNEST(artifacts) as pkg
            GROUP BY pkg.type
            ORDER BY count DESC;
        " 2>/dev/null | jq '.'
        return
    fi

    echo "Package Types Distribution"
    echo ""
    duckdb -c "
        SELECT
            pkg.type as Type,
            COUNT(*) as Count,
            COUNT(DISTINCT regexp_extract(filename, '/([^/]+)-sbom\.json', 1)) as Repos
        FROM read_json('$SBOM_PATTERN', ignore_errors=true, union_by_name=true),
        UNNEST(artifacts) as pkg
        GROUP BY pkg.type
        ORDER BY Count DESC;
    " 2>/dev/null || echo "No package data found"
}

query_count() {
    echo "=== Counts ==="

    if check_languages_data 2>/dev/null; then
        if [[ "$ALL_ORGS" == true ]]; then
            org_count=$(jq '.orgs | keys | length' "$LANGUAGES_FILE")
            echo "Organizations: $org_count"
        else
            repo_count=$(jq --arg org "$ORG" '.orgs[$org].repos | keys | length // 0' "$LANGUAGES_FILE")
            lang_count=$(jq --arg org "$ORG" '.orgs[$org].totals | keys | length // 0' "$LANGUAGES_FILE")
            echo "Repos (languages): $repo_count"
            echo "Languages: $lang_count"
        fi
    fi

    if check_sbom_data 2>/dev/null; then
        pkg_count=$(duckdb -noheader -c "
            SELECT COUNT(*)
            FROM read_json('$SBOM_PATTERN', ignore_errors=true, union_by_name=true),
            UNNEST(artifacts);
        " 2>/dev/null || echo "0")
        echo "Packages: $pkg_count"
    fi
}

# Execute query based on format
case "$FORMAT" in
    summary)
        query_summary
        ;;
    languages)
        query_languages
        ;;
    packages)
        query_packages
        ;;
    cve-ready|cve)
        query_cve_ready
        ;;
    types)
        query_types
        ;;
    count)
        query_count
        ;;
    *)
        echo "Error: Unknown format: $FORMAT" >&2
        echo "Valid formats: summary, languages, packages, cve-ready, types, count" >&2
        exit 1
        ;;
esac
