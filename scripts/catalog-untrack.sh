#!/usr/bin/env bash
# Remove an organization from the catalog tracking system
#
# Usage: ./scripts/catalog-untrack.sh <org-name> [options]
#
# Examples:
#   ./scripts/catalog-untrack.sh acme-corp
#   ./scripts/catalog-untrack.sh acme-corp --delete-scans
#   ./scripts/catalog-untrack.sh acme-corp --delete-repos --force

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

usage() {
    cat << EOF
Usage: $0 <org-name> [options]

Remove an organization from the catalog tracking system.

Arguments:
    org-name    GitHub organization name to untrack

Options:
    --delete-scans   Also delete scan data from catalog/tracked/<org>/
    --delete-repos   Also delete cloned repos from repos/<org>/
    --delete-all     Delete both scans and repos
    --force, -f      Skip confirmation prompt
    -h, --help       Show this help message

Examples:
    $0 acme-corp                       # Untrack only (keep data)
    $0 acme-corp --delete-scans        # Untrack and delete scan data
    $0 acme-corp --delete-all --force  # Full cleanup without prompting
EOF
    exit 1
}

# Check for help flag first
for arg in "$@"; do
    if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
        usage
    fi
done

if [[ $# -lt 1 ]]; then
    usage
fi

ORG="$1"
shift

DELETE_SCANS="0"
DELETE_REPOS="0"
FORCE="0"

# Parse optional flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --delete-scans)
            DELETE_SCANS="1"
            shift
            ;;
        --delete-repos)
            DELETE_REPOS="1"
            shift
            ;;
        --delete-all)
            DELETE_SCANS="1"
            DELETE_REPOS="1"
            shift
            ;;
        -f|--force)
            FORCE="1"
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

# Validate org name
if ! validate_org_name "$ORG"; then
    exit 1
fi

# Ensure catalog infrastructure exists
if ! ensure_index_exists; then
    echo "Catalog index not found"
    exit 1
fi

# Check if tracked
if ! is_org_tracked "$ORG"; then
    echo "Error: '$ORG' is not tracked"
    echo ""
    echo "To see tracked orgs: ./scripts/catalog-status.sh"
    exit 1
fi

# Gather info before removal
ORG_DIR="$(get_org_catalog_dir "$ORG")"
REPOS_DIR="$(get_org_repos_dir "$ORG")"
PLATFORM=$(get_org_field "$ORG" "platform")
SCAN_COUNT=$(get_org_field "$ORG" "scan_count")

# Count what will be deleted
SCANS_SIZE=""
REPOS_SIZE=""

if [[ -d "$ORG_DIR" ]]; then
    SCANS_SIZE=$(du -sh "$ORG_DIR" 2>/dev/null | cut -f1 || echo "unknown")
fi

if [[ -d "$REPOS_DIR" ]]; then
    REPOS_SIZE=$(du -sh "$REPOS_DIR" 2>/dev/null | cut -f1 || echo "unknown")
fi

# Show what will happen
echo "========================================"
echo "Untrack: $ORG"
echo "========================================"
echo ""
echo "  Platform:    $PLATFORM"
echo "  Scans:       ${SCAN_COUNT:-0}"
echo ""
echo "Actions:"
echo "  • Remove from catalog index"

if [[ "$DELETE_SCANS" == "1" && -d "$ORG_DIR" ]]; then
    echo "  • Delete scan data: $ORG_DIR ($SCANS_SIZE)"
fi

if [[ "$DELETE_REPOS" == "1" && -d "$REPOS_DIR" ]]; then
    echo "  • Delete repos: $REPOS_DIR ($REPOS_SIZE)"
fi

if [[ "$DELETE_SCANS" != "1" && -d "$ORG_DIR" ]]; then
    echo "  • Keep scan data: $ORG_DIR ($SCANS_SIZE)"
fi

if [[ "$DELETE_REPOS" != "1" && -d "$REPOS_DIR" ]]; then
    echo "  • Keep repos: $REPOS_DIR ($REPOS_SIZE)"
fi

echo ""

# Confirmation
if [[ "$FORCE" != "1" ]]; then
    read -p "Proceed? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
fi

# Remove from index
echo "Removing from index..."
remove_from_index "$ORG"

# Delete scan data if requested
if [[ "$DELETE_SCANS" == "1" && -d "$ORG_DIR" ]]; then
    echo "Deleting scan data..."
    rm -rf "$ORG_DIR"
fi

# Delete repos if requested
if [[ "$DELETE_REPOS" == "1" && -d "$REPOS_DIR" ]]; then
    echo "Deleting repos..."
    rm -rf "$REPOS_DIR"
fi

echo ""
echo "========================================"
echo "Done"
echo "========================================"
echo ""
echo "  '$ORG' has been untracked."

if [[ "$DELETE_SCANS" != "1" && -d "$ORG_DIR" ]]; then
    echo ""
    echo "  Scan data preserved at:"
    echo "    $ORG_DIR"
    echo ""
    echo "  To delete later: rm -rf $ORG_DIR"
fi

if [[ "$DELETE_REPOS" != "1" && -d "$REPOS_DIR" ]]; then
    echo ""
    echo "  Repos preserved at:"
    echo "    $REPOS_DIR"
    echo ""
    echo "  To delete later: rm -rf $REPOS_DIR"
fi

echo ""
