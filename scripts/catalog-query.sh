#!/usr/bin/env bash
# Query bug bounty platform scope data
#
# Usage:
#   ./scripts/catalog-query.sh <search-term>           # Search all platforms
#   ./scripts/catalog-query.sh github --type github    # Find GitHub repos only
#   ./scripts/catalog-query.sh stripe --platform h1    # Search HackerOne only
#
# Examples:
#   ./scripts/catalog-query.sh immutable               # Find programs with "immutable"
#   ./scripts/catalog-query.sh --type github           # All GitHub repos in scope
#   ./scripts/catalog-query.sh --type github --orgs    # Extract GitHub org names
#   ./scripts/catalog-query.sh "*.example.com"         # Wildcard domains

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CATALOG_ROOT="${CATALOG_ROOT:-$SCRIPT_DIR/..}"
PLATFORMS_DIR="$CATALOG_ROOT/catalog/platforms"

# Require DuckDB
if ! command -v duckdb &> /dev/null; then
    echo "Error: DuckDB required. Install: brew install duckdb" >&2
    exit 1
fi

usage() {
    cat << 'EOF'
Usage: catalog-query.sh [options] [search-term]

Search bug bounty platform scope data.

Options:
    --platform <p>    Platform to search: h1, hackerone, bc, bugcrowd, all (default: all)
    --type <t>        Filter by target type: github, domain, wildcard, ip, all (default: all)
    --paid            Only show paid bug bounty programs (excludes VDPs)
    --vdp             Only show VDP programs (free, no bounty)
    --format <f>      Output format: table, programs, targets, orgs, json (default: table)
    --limit <n>       Limit results (default: unlimited, use -1 or 0 for unlimited)
    -h, --help        Show this help

Target Types:
    github      GitHub repositories (github.com/...)
    domain      Specific domains (example.com)
    wildcard    Wildcard domains (*.example.com)
    ip          IP addresses or CIDR ranges
    all         All target types

Output Formats:
    table       Program and target in columns (default)
    programs    Unique program names only
    targets     Target URLs/domains only
    orgs        GitHub organizations only (requires --type github)
    json        Full JSON output

Examples:
    catalog-query.sh stripe                      # Search for "stripe"
    catalog-query.sh --type github               # All GitHub repos
    catalog-query.sh --type github --format orgs # GitHub org names for cloning
    catalog-query.sh --platform h1 aws           # Search HackerOne for "aws"
    catalog-query.sh "*.corp.com"                # Find wildcard scopes
    catalog-query.sh --paid                      # Only paid bug bounty programs
    catalog-query.sh --type github --paid        # GitHub repos from paid programs only
EOF
    exit 0
}

# Defaults
SEARCH_TERM=""
PLATFORM="all"
TARGET_TYPE="all"
FORMAT="table"
LIMIT=0
PAID_FILTER=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --type)
            TARGET_TYPE="$2"
            shift 2
            ;;
        --format)
            FORMAT="$2"
            shift 2
            ;;
        --limit)
            LIMIT="$2"
            shift 2
            ;;
        --paid)
            PAID_FILTER="paid"
            shift
            ;;
        --vdp)
            PAID_FILTER="vdp"
            shift
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage
            ;;
        *)
            SEARCH_TERM="$1"
            shift
            ;;
    esac
done

# Normalize platform names
case "$PLATFORM" in
    h1|hackerone|HackerOne)
        PLATFORM="hackerone"
        ;;
    bc|bugcrowd|Bugcrowd)
        PLATFORM="bugcrowd"
        ;;
    ywh|yeswehack|YesWeHack)
        PLATFORM="yeswehack"
        ;;
    it|intigriti|Intigriti)
        PLATFORM="intigriti"
        ;;
    all|"")
        PLATFORM="all"
        ;;
esac

# Build file pattern
if [[ "$PLATFORM" == "all" ]]; then
    FILE_PATTERN="$PLATFORMS_DIR/*.json"
else
    FILE_PATTERN="$PLATFORMS_DIR/$PLATFORM.json"
    if [[ ! -f "$FILE_PATTERN" ]]; then
        echo "Error: Platform data not found: $FILE_PATTERN" >&2
        echo "Run: ./scripts/catalog-refresh.sh $PLATFORM" >&2
        exit 1
    fi
fi

# Check if any platform files exist
shopt -s nullglob
platform_files=("$PLATFORMS_DIR"/*.json)
shopt -u nullglob
if [[ ${#platform_files[@]} -eq 0 ]]; then
    echo "Error: No platform data found in $PLATFORMS_DIR" >&2
    echo "Run: ./scripts/catalog-refresh.sh" >&2
    exit 1
fi

# Build type filter
TYPE_FILTER=""
case "$TARGET_TYPE" in
    github)
        TYPE_FILTER="AND lower(unnest.target) LIKE '%github.com%'"
        ;;
    domain)
        TYPE_FILTER="AND unnest.target NOT LIKE '*%' AND unnest.target NOT LIKE '%github.com%' AND unnest.target LIKE '%.%'"
        ;;
    wildcard)
        TYPE_FILTER="AND unnest.target LIKE '*%'"
        ;;
    ip)
        TYPE_FILTER="AND regexp_matches(unnest.target, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]')"
        ;;
    all|"")
        TYPE_FILTER=""
        ;;
    *)
        echo "Unknown type: $TARGET_TYPE" >&2
        exit 1
        ;;
esac

# Build search filter
SEARCH_FILTER=""
if [[ -n "$SEARCH_TERM" ]]; then
    # Escape single quotes by doubling them for SQL, using sed for reliability
    ESCAPED_TERM=$(printf '%s' "$SEARCH_TERM" | sed "s/'/''/g")
    # Convert to lowercase for case-insensitive search
    LOWER_TERM=$(echo "$ESCAPED_TERM" | tr '[:upper:]' '[:lower:]')
    SEARCH_FILTER="AND (lower(unnest.target) LIKE '%${LOWER_TERM}%' OR lower(unnest.url) LIKE '%${LOWER_TERM}%')"
fi

# Build paid status filter
PAID_STATUS_FILTER=""
case "$PAID_FILTER" in
    paid)
        PAID_STATUS_FILTER="AND unnest.paid = true"
        ;;
    vdp)
        PAID_STATUS_FILTER="AND unnest.paid = false"
        ;;
esac

# Build limit clause
LIMIT_CLAUSE=""
if [[ "$LIMIT" -gt 0 ]]; then
    LIMIT_CLAUSE="LIMIT $LIMIT"
fi

# DuckDB settings to show all rows (-1 = unlimited)
DUCKDB_OPTS=(-cmd ".maxrows -1")

# Execute query based on format
case "$FORMAT" in
    table)
        duckdb "${DUCKDB_OPTS[@]}" -c "
            SELECT
                platform,
                COALESCE(
                    NULLIF(regexp_extract(unnest.url, 'hackerone.com/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/engagements/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'yeswehack.com/programs/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'app.intigriti.com/researcher/programs/[^/]+/([^/]+)', 1), ''),
                    'unknown'
                ) as program,
                CASE
                    WHEN unnest.paid = true THEN 'paid'
                    WHEN unnest.paid = false THEN 'vdp'
                    ELSE '?'
                END as type,
                unnest.target as target
            FROM read_json('$FILE_PATTERN'),
            UNNEST(scopes)
            WHERE unnest.target <> ''
            $TYPE_FILTER
            $SEARCH_FILTER
            $PAID_STATUS_FILTER
            ORDER BY platform, program, target
            $LIMIT_CLAUSE
        "
        ;;

    programs)
        duckdb "${DUCKDB_OPTS[@]}" -c "
            SELECT DISTINCT
                platform,
                COALESCE(
                    NULLIF(regexp_extract(unnest.url, 'hackerone.com/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/engagements/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'yeswehack.com/programs/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'app.intigriti.com/researcher/programs/[^/]+/([^/]+)', 1), ''),
                    'unknown'
                ) as program,
                CASE
                    WHEN bool_or(unnest.paid = true) THEN 'paid'
                    WHEN bool_or(unnest.paid = false) THEN 'vdp'
                    ELSE '?'
                END as type,
                count(*) as matching_scopes
            FROM read_json('$FILE_PATTERN'),
            UNNEST(scopes)
            WHERE unnest.target <> ''
            $TYPE_FILTER
            $SEARCH_FILTER
            $PAID_STATUS_FILTER
            GROUP BY platform, program
            ORDER BY matching_scopes DESC
            $LIMIT_CLAUSE
        "
        ;;

    targets)
        duckdb "${DUCKDB_OPTS[@]}" -noheader -c "
            SELECT DISTINCT unnest.target
            FROM read_json('$FILE_PATTERN'),
            UNNEST(scopes)
            WHERE unnest.target <> ''
            $TYPE_FILTER
            $SEARCH_FILTER
            $PAID_STATUS_FILTER
            ORDER BY unnest.target
            $LIMIT_CLAUSE
        "
        ;;

    orgs)
        if [[ "$TARGET_TYPE" != "github" ]]; then
            echo "Note: --format orgs implies --type github" >&2
            TYPE_FILTER="AND lower(unnest.target) LIKE '%github.com%'"
        fi
        duckdb "${DUCKDB_OPTS[@]}" -noheader -c "
            SELECT DISTINCT regexp_extract(unnest.target, 'github\\.com/([A-Za-z0-9_-]+)', 1) as org
            FROM read_json('$FILE_PATTERN'),
            UNNEST(scopes)
            WHERE unnest.target <> ''
            $TYPE_FILTER
            $SEARCH_FILTER
            $PAID_STATUS_FILTER
            AND regexp_extract(unnest.target, 'github\\.com/([A-Za-z0-9_-]+)', 1) <> ''
            AND length(regexp_extract(unnest.target, 'github\\.com/([A-Za-z0-9_-]+)', 1)) > 1
            ORDER BY org
            $LIMIT_CLAUSE
        "
        ;;

    json)
        duckdb "${DUCKDB_OPTS[@]}" -json -c "
            SELECT
                platform,
                COALESCE(
                    NULLIF(regexp_extract(unnest.url, 'hackerone.com/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/engagements/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'yeswehack.com/programs/([^/]+)', 1), ''),
                    NULLIF(regexp_extract(unnest.url, 'app.intigriti.com/researcher/programs/[^/]+/([^/]+)', 1), ''),
                    'unknown'
                ) as program,
                unnest.target as target,
                unnest.url as program_url,
                unnest.paid as paid
            FROM read_json('$FILE_PATTERN'),
            UNNEST(scopes)
            WHERE unnest.target <> ''
            $TYPE_FILTER
            $SEARCH_FILTER
            $PAID_STATUS_FILTER
            ORDER BY platform, program, target
            $LIMIT_CLAUSE
        "
        ;;

    *)
        echo "Unknown format: $FORMAT" >&2
        exit 1
        ;;
esac
