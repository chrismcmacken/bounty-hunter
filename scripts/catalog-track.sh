#!/usr/bin/env bash
# Add an organization to the catalog tracking system
#
# Usage: ./scripts/catalog-track.sh <org-name> <platform> [options]
#
# Examples:
#   ./scripts/catalog-track.sh acme-corp hackerone
#   ./scripts/catalog-track.sh acme-corp bugcrowd --program-url https://bugcrowd.com/acme
#
# Platforms: hackerone, bugcrowd, yeswehack, intigriti, other

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

usage() {
    cat << EOF
Usage: $0 <program-name> <platform> [options]

Add a bug bounty program to the catalog for tracking.

Arguments:
    program-name  Program/target name (used as catalog key)
    platform      Bug bounty platform (hackerone, bugcrowd, yeswehack, intigriti, other)

Options:
    --github-org <org>   GitHub org name(s) - can be specified multiple times
                         or as comma-separated list (e.g., "org1,org2,org3")
    --program-url <url>  URL to the bug bounty program page
    -h, --help           Show this help message

Examples:
    $0 acme-corp hackerone
    $0 wise bugcrowd --github-org transferwise
    $0 blockopensource bugcrowd --github-org "block,square,cashapp"
    $0 multi-org other --github-org org1 --github-org org2
    $0 my-target other --program-url https://example.com/security
EOF
    exit 1
}

# Check for help flag first
for arg in "$@"; do
    if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
        usage
    fi
done

if [[ $# -lt 2 ]]; then
    usage
fi

ORG="$1"
PLATFORM="$2"
shift 2

PROGRAM_URL=""
GITHUB_ORGS=()

# Parse optional flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --program-url)
            PROGRAM_URL="$2"
            shift 2
            ;;
        --github-org)
            # Support comma-separated values
            IFS=',' read -ra ORGS <<< "$2"
            for org in "${ORGS[@]}"; do
                # Trim whitespace
                org=$(echo "$org" | xargs)
                [[ -n "$org" ]] && GITHUB_ORGS+=("$org")
            done
            shift 2
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

# Default github_orgs to program name if not specified
if [[ ${#GITHUB_ORGS[@]} -eq 0 ]]; then
    GITHUB_ORGS=("$ORG")
fi

# Validate org name
if ! validate_org_name "$ORG"; then
    exit 1
fi

# Validate platform
VALID_PLATFORMS="hackerone bugcrowd yeswehack intigriti other"
if [[ ! " $VALID_PLATFORMS " =~ " $PLATFORM " ]]; then
    echo "Error: Invalid platform '$PLATFORM'"
    echo "Valid platforms: $VALID_PLATFORMS"
    exit 1
fi

# Ensure catalog infrastructure exists
if ! ensure_index_exists; then
    echo "Run infrastructure setup first or create catalog/index.json"
    exit 1
fi

# Check if already tracked
if is_org_tracked "$ORG"; then
    echo "Error: '$ORG' is already tracked"
    echo ""
    echo "To see status: ./scripts/catalog-status.sh"
    echo "To untrack:    ./scripts/catalog-untrack.sh $ORG"
    exit 1
fi

# Try to get info from platform data if available
PLATFORM_FILE="$CATALOG_ROOT/catalog/platforms/$PLATFORM.json"
if [[ -f "$PLATFORM_FILE" && -z "$PROGRAM_URL" ]]; then
    PROGRAM_URL=$(jq -r --arg name "$ORG" \
        '.programs[]? | select(.name == $name or .handle == $name) | .program_url // .url // empty' \
        "$PLATFORM_FILE" 2>/dev/null | head -1) || true
fi

# Create directories
ORG_DIR="$CATALOG_ROOT/catalog/tracked/$ORG"
mkdir -p "$ORG_DIR/scans"

# Create meta.json with proper JSON formatting
# Use github_orgs array if multiple, github_org string if single (backward compat)
if [[ ${#GITHUB_ORGS[@]} -eq 1 ]]; then
    jq -n \
        --arg name "$ORG" \
        --arg platform "$PLATFORM" \
        --arg github_org "${GITHUB_ORGS[0]}" \
        --arg url "${PROGRAM_URL:-}" \
        --arg date "$(date +%Y-%m-%d)" \
        '{
            name: $name,
            platform: $platform,
            github_org: $github_org,
            program_url: $url,
            scope: {
                in_scope: [],
                out_of_scope: []
            },
            added_date: $date,
            status: "active",
            notes: ""
        }' > "$ORG_DIR/meta.json"
else
    # Build JSON array of orgs
    ORGS_JSON=$(printf '%s\n' "${GITHUB_ORGS[@]}" | jq -R . | jq -s .)
    jq -n \
        --arg name "$ORG" \
        --arg platform "$PLATFORM" \
        --argjson github_orgs "$ORGS_JSON" \
        --arg url "${PROGRAM_URL:-}" \
        --arg date "$(date +%Y-%m-%d)" \
        '{
            name: $name,
            platform: $platform,
            github_orgs: $github_orgs,
            program_url: $url,
            scope: {
                in_scope: [],
                out_of_scope: []
            },
            added_date: $date,
            status: "active",
            notes: ""
        }' > "$ORG_DIR/meta.json"
fi

# Add to index
add_to_index "$ORG" "$PLATFORM" "${PROGRAM_URL:-}"

echo "========================================"
echo "Tracked: $ORG"
echo "========================================"
echo ""
echo "  Platform:    $PLATFORM"
if [[ ${#GITHUB_ORGS[@]} -eq 1 && "${GITHUB_ORGS[0]}" != "$ORG" ]]; then
    echo "  GitHub Org:  ${GITHUB_ORGS[0]}"
elif [[ ${#GITHUB_ORGS[@]} -gt 1 ]]; then
    echo "  GitHub Orgs: ${GITHUB_ORGS[*]}"
fi
echo "  Program URL: ${PROGRAM_URL:-"(not set)"}"
echo "  Added:       $(date +%Y-%m-%d)"
echo "  Catalog:     catalog/tracked/$ORG/"
echo ""
echo "Next steps:"
echo "  1. Clone repos:  ./scripts/clone-org-repos.sh $ORG"
echo "  2. Run scan:     ./scripts/catalog-scan.sh $ORG"
echo ""
