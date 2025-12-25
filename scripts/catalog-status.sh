#!/usr/bin/env bash
# Display status dashboard for all tracked organizations
#
# Usage: ./scripts/catalog-status.sh [options]
#
# Examples:
#   ./scripts/catalog-status.sh
#   ./scripts/catalog-status.sh --stale-days 14
#   ./scripts/catalog-status.sh --org acme-corp

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

usage() {
    cat << EOF
Usage: $0 [options]

Display status dashboard for tracked organizations.

Options:
    --stale-days N   Days before a scan is considered stale (default: 7)
    --org <name>     Show detailed status for a specific org
    --archived       Show only archived organizations
    --active         Show only active organizations (default: show all)
    -h, --help       Show this help message

Examples:
    $0                      # Show all tracked orgs
    $0 --stale-days 14      # Consider scans stale after 14 days
    $0 --org acme-corp      # Detailed view of one org
    $0 --archived           # List only archived orgs
EOF
    exit 1
}

STALE_DAYS=7
SPECIFIC_ORG=""
FILTER_STATUS=""  # "", "archived", or "active"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --stale-days)
            STALE_DAYS="$2"
            shift 2
            ;;
        --org)
            SPECIFIC_ORG="$2"
            shift 2
            ;;
        --archived)
            FILTER_STATUS="archived"
            shift
            ;;
        --active)
            FILTER_STATUS="active"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Check for DuckDB
if ! command -v duckdb &> /dev/null; then
    echo "Error: DuckDB is required but not installed."
    echo "Install: brew install duckdb"
    exit 1
fi

# Check catalog exists
if ! ensure_index_exists; then
    echo "No catalog found. Run catalog-track.sh first."
    exit 1
fi

INDEX_FILE="$CATALOG_INDEX"

# Check if any orgs are tracked
ORG_COUNT=$(jq '.tracked_orgs | length' "$INDEX_FILE")
if [[ "$ORG_COUNT" -eq 0 ]]; then
    echo "No organizations tracked yet."
    echo ""
    echo "To track an organization:"
    echo "  ./scripts/catalog-track.sh <org-name> <platform>"
    exit 0
fi

# Detailed view for specific org
if [[ -n "$SPECIFIC_ORG" ]]; then
    if ! is_org_tracked "$SPECIFIC_ORG"; then
        echo "Error: '$SPECIFIC_ORG' is not tracked"
        exit 1
    fi

    ORG_DIR="$CATALOG_ROOT/catalog/tracked/$SPECIFIC_ORG"
    META_FILE="$ORG_DIR/meta.json"
    SCANS_DIR="$ORG_DIR/scans"

    echo "========================================"
    echo "Organization: $SPECIFIC_ORG"
    echo "========================================"
    echo ""

    # Basic info from index
    echo "Tracking Info:"
    jq -r --arg name "$SPECIFIC_ORG" '
        .tracked_orgs[] | select(.name == $name) |
        "  Platform:    \(.platform)\n  Status:      \(.status // "active")\n  Program URL: \(.program_url // "(not set)")\n  Added:       \(.added_date)\n  Last Scan:   \(.last_scan // "never")\n  Scan Count:  \(.scan_count)"
    ' "$INDEX_FILE"
    echo ""

    # Repos info
    REPOS_DIR="$CATALOG_ROOT/repos/$SPECIFIC_ORG"
    if [[ -d "$REPOS_DIR" ]]; then
        repo_count=$(find "$REPOS_DIR" -maxdepth 1 -mindepth 1 -type d ! -name ".*" | wc -l | xargs)
        echo "Repositories: $repo_count (in $REPOS_DIR)"
    else
        echo "Repositories: Not cloned yet"
        echo "  Clone with: ./scripts/clone-org-repos.sh $SPECIFIC_ORG"
    fi
    echo ""

    # List scans
    if [[ -d "$SCANS_DIR" ]]; then
        scan_count=$(ls -1 "$SCANS_DIR" 2>/dev/null | wc -l | xargs)
        echo "Scan History: $scan_count scans"
        if [[ "$scan_count" -gt 0 ]]; then
            echo ""
            ls -1 "$SCANS_DIR" | sort -r | head -10 | while read -r scan; do
                scan_dir="$SCANS_DIR/$scan"
                # Count findings in each scan
                semgrep_count=0
                trufflehog_count=0
                if [[ -f "$scan_dir/semgrep.json" ]]; then
                    semgrep_count=$(jq '.results | length' "$scan_dir/semgrep.json" 2>/dev/null || echo "0")
                fi
                if [[ -f "$scan_dir/trufflehog.json" ]]; then
                    trufflehog_count=$(wc -l < "$scan_dir/trufflehog.json" | xargs)
                fi
                echo "  $scan  (semgrep: $semgrep_count, secrets: $trufflehog_count)"
            done
            if [[ "$scan_count" -gt 10 ]]; then
                echo "  ... and $((scan_count - 10)) more"
            fi
        fi
    else
        echo "Scan History: No scans yet"
        echo "  Run: ./scripts/catalog-scan.sh $SPECIFIC_ORG"
    fi
    echo ""
    exit 0
fi

# Dashboard view for all orgs
echo "========================================"
echo "Catalog Status Dashboard"
echo "========================================"
echo "Stale threshold: $STALE_DAYS days"
if [[ -n "$FILTER_STATUS" ]]; then
    echo "Filter: $FILTER_STATUS only"
fi
echo ""

# Build status filter condition
STATUS_FILTER=""
if [[ "$FILTER_STATUS" == "archived" ]]; then
    STATUS_FILTER="WHERE org_status = 'archived'"
elif [[ "$FILTER_STATUS" == "active" ]]; then
    STATUS_FILTER="WHERE org_status = 'active'"
fi

# Use DuckDB for the main query
duckdb -c "
    WITH orgs AS (
        SELECT
            unnest.name as name,
            unnest.platform as platform,
            unnest.last_scan::VARCHAR as last_scan,
            unnest.scan_count as scan_count,
            unnest.status as org_status
        FROM read_json('$INDEX_FILE'),
        UNNEST(tracked_orgs)
    ),
    with_status AS (
        SELECT
            *,
            CASE
                WHEN last_scan IS NULL OR last_scan = 'null' THEN 'never'
                WHEN TRY_STRPTIME(last_scan, '%Y-%m-%d-%H%M') < CURRENT_DATE - INTERVAL '$STALE_DAYS days' THEN 'stale'
                ELSE 'current'
            END as scan_status,
            CASE
                WHEN last_scan IS NULL OR last_scan = 'null' THEN NULL
                ELSE DATEDIFF('day', TRY_STRPTIME(last_scan, '%Y-%m-%d-%H%M')::DATE, CURRENT_DATE)
            END as days_ago
        FROM orgs
        $STATUS_FILTER
    )
    SELECT
        name as \"ORG\",
        platform as \"PLATFORM\",
        CASE WHEN last_scan IS NULL OR last_scan = 'null' THEN '-' ELSE last_scan END as \"LAST SCAN\",
        scan_count as \"SCANS\",
        CASE
            WHEN org_status = 'archived' THEN '[ARCHIVED]'
            WHEN scan_status = 'current' THEN 'Current'
            WHEN scan_status = 'stale' THEN 'Stale (' || days_ago || 'd)'
            WHEN scan_status = 'never' THEN 'Never scanned'
        END as \"STATUS\"
    FROM with_status
    ORDER BY
        CASE org_status WHEN 'archived' THEN 2 ELSE 1 END,
        CASE scan_status WHEN 'stale' THEN 1 WHEN 'never' THEN 2 ELSE 3 END,
        name
" 2>/dev/null || {
    echo "Error querying catalog. Falling back to basic view..."
    echo ""
    jq -r '.tracked_orgs[] | "\(.name)\t\(.platform)\t\(.last_scan // "-")\t\(.scan_count)\t\(.status // "active")"' "$INDEX_FILE" | \
        column -t -s $'\t'
}

# Summary line
echo ""
summary=$(duckdb -noheader -csv -c "
    WITH orgs AS (
        SELECT
            unnest.last_scan::VARCHAR as last_scan,
            unnest.status as org_status
        FROM read_json('$INDEX_FILE'),
        UNNEST(tracked_orgs)
    )
    SELECT
        COUNT(*) as total,
        SUM(CASE WHEN org_status = 'archived' THEN 1 ELSE 0 END) as archived,
        SUM(CASE WHEN org_status != 'archived' AND last_scan IS NOT NULL AND last_scan != 'null' AND TRY_STRPTIME(last_scan, '%Y-%m-%d-%H%M') < CURRENT_DATE - INTERVAL '$STALE_DAYS days' THEN 1 ELSE 0 END) as stale,
        SUM(CASE WHEN org_status != 'archived' AND (last_scan IS NULL OR last_scan = 'null') THEN 1 ELSE 0 END) as never_scanned
    FROM orgs
" 2>/dev/null || echo "$ORG_COUNT,0,0,0")

total=$(echo "$summary" | cut -d',' -f1)
archived=$(echo "$summary" | cut -d',' -f2)
stale=$(echo "$summary" | cut -d',' -f3)
never=$(echo "$summary" | cut -d',' -f4)

if [[ "$archived" -gt 0 ]]; then
    echo "Tracked: $total orgs | Active: $((total - archived)) | Archived: $archived | Stale: $stale | Never scanned: $never"
else
    echo "Tracked: $total orgs | Stale: $stale | Never scanned: $never"
fi

# Recommendations
if [[ "$stale" -gt 0 || "$never" -gt 0 ]]; then
    echo ""
    echo "----------------------------------------"
    echo "Recommendations:"

    if [[ "$never" -gt 0 ]]; then
        echo ""
        echo "Organizations needing initial scan:"
        jq -r '.tracked_orgs[] | select(.last_scan == null) | "  ./scripts/catalog-scan.sh \(.name)"' "$INDEX_FILE"
    fi

    if [[ "$stale" -gt 0 ]]; then
        echo ""
        echo "Organizations needing rescan (stale > $STALE_DAYS days):"
        # Get stale orgs using jq (simpler than DuckDB for this)
        jq -r --argjson days "$STALE_DAYS" '
            .tracked_orgs[] |
            select(.last_scan != null) |
            select((.last_scan | split("-") | .[0:3] | join("-") | strptime("%Y-%m-%d") | mktime) < (now - ($days * 86400))) |
            "  ./scripts/catalog-scan.sh \(.name)"
        ' "$INDEX_FILE" 2>/dev/null || \
        jq -r '.tracked_orgs[] | select(.last_scan != null) | "  ./scripts/catalog-scan.sh \(.name)"' "$INDEX_FILE"
    fi
fi

echo ""
