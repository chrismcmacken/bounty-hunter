#!/usr/bin/env bash
set -euo pipefail

# Inventory Scanner - Language and dependency analysis
#
# Runs scc (language stats) and syft (SBOM) on repositories.
#
# Storage:
#   - Languages: catalog/languages.json (global, all orgs in one file)
#   - SBOMs: scans/<org>/inventory/<repo>-sbom.json (per-repo)
#
# Dependencies: scc, syft, jq

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME <org-name> [OPTIONS]

Scan repositories for language statistics (scc) and dependencies (syft).

Arguments:
  org-name              Organization name to scan

Options:
  --repos-dir <path>    Directory containing repos (default: repos/<org>)
  --output-dir <path>   Output directory for SBOMs (default: scans/<org>)
  --languages-only      Only run language analysis (scc)
  --sbom-only           Only run dependency analysis (syft)
  --no-languages        Skip language analysis
  --no-sbom             Skip dependency analysis
  -q, --quiet           Quiet mode: show progress and final summary only
  -h, --help            Show this help message

Output:
  catalog/languages.json                  Global language stats (updated)
  scans/<org>/inventory/<repo>-sbom.json  Per-repo SBOM files

Examples:
  $SCRIPT_NAME hemi                         # Full inventory scan
  $SCRIPT_NAME hemi --languages-only        # Languages only
  $SCRIPT_NAME hemi --repos-dir ./my-repos  # Custom repos location
EOF
    exit 0
}

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

check_dependencies() {
    local missing=()

    if [[ "$DO_LANGUAGES" == true ]] && ! command -v scc &>/dev/null; then
        missing+=("scc")
    fi

    if [[ "$DO_SBOM" == true ]] && ! command -v syft &>/dev/null; then
        missing+=("syft")
    fi

    if ! command -v jq &>/dev/null; then
        missing+=("jq")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  brew install ${missing[*]}"
        exit 1
    fi
}

# Parse arguments
ORG=""
REPOS_DIR=""
OUTPUT_DIR=""
DO_LANGUAGES=true
DO_SBOM=true
QUIET_MODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        --repos-dir)
            REPOS_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --languages-only)
            DO_SBOM=false
            shift
            ;;
        --sbom-only)
            DO_LANGUAGES=false
            shift
            ;;
        --no-languages)
            DO_LANGUAGES=false
            shift
            ;;
        --no-sbom)
            DO_SBOM=false
            shift
            ;;
        -q|--quiet)
            QUIET_MODE="1"
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            usage
            ;;
        *)
            if [[ -z "$ORG" ]]; then
                ORG="$1"
            else
                log_error "Unexpected argument: $1"
                usage
            fi
            shift
            ;;
    esac
done

export QUIET_MODE

if [[ -z "$ORG" ]]; then
    log_error "Organization name required"
    usage
fi

# Set defaults
REPOS_DIR="${REPOS_DIR:-$ROOT_DIR/repos/$ORG}"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/scans/$ORG}"
LANGUAGES_FILE="$ROOT_DIR/catalog/languages.json"
INVENTORY_DIR="$OUTPUT_DIR/inventory"

if [[ ! -d "$REPOS_DIR" ]]; then
    log_error "Repos directory not found: $REPOS_DIR"
    exit 1
fi

check_dependencies

# Source utility functions for archived repo detection
if [[ -f "$SCRIPT_DIR/lib/catalog-utils.sh" ]]; then
    source "$SCRIPT_DIR/lib/catalog-utils.sh"
    REPOS=$(get_active_repos "$REPOS_DIR")
else
    # Fallback: get all directories
    REPOS=$(find "$REPOS_DIR" -mindepth 1 -maxdepth 1 -type d | sort)
fi

REPO_COUNT=$(echo "$REPOS" | grep -c . || echo 0)

if [[ "$REPO_COUNT" -eq 0 ]]; then
    log_warn "No repositories found in $REPOS_DIR"
    exit 0
fi

if [[ -z "$QUIET_MODE" ]]; then
    log_info "Scanning $REPO_COUNT repositories for inventory"
    [[ "$DO_LANGUAGES" == true ]] && log_info "  Languages: scc → catalog/languages.json"
    [[ "$DO_SBOM" == true ]] && log_info "  SBOMs: syft → $INVENTORY_DIR/"
    echo ""
fi

# Create output directories
mkdir -p "$INVENTORY_DIR"
mkdir -p "$(dirname "$LANGUAGES_FILE")"

# Initialize languages.json if it doesn't exist
if [[ ! -f "$LANGUAGES_FILE" ]]; then
    echo '{"orgs":{}}' > "$LANGUAGES_FILE"
fi

# Temporary file for collecting language data
LANG_TEMP=$(mktemp)
trap 'rm -f "$LANG_TEMP"' EXIT

echo "{}" > "$LANG_TEMP"

# Convert repos to array for counting
REPOS_ARRAY=()
while IFS= read -r repo; do
    [[ -n "$repo" ]] && REPOS_ARRAY+=("$repo")
done <<< "$REPOS"

# Scan each repository
current=0
for repo_path in "${REPOS_ARRAY[@]}"; do
    repo_name=$(basename "$repo_path")
    current=$((current + 1))

    # Skip if not a directory
    [[ ! -d "$repo_path" ]] && continue

    if [[ -n "$QUIET_MODE" ]]; then
        log_progress "$current" "$REPO_COUNT" "$repo_name"
    else
        echo "[$repo_name] Scanning..."
    fi

    # Run scc for language analysis
    if [[ "$DO_LANGUAGES" == true ]]; then
        scc_output=$(scc -f json "$repo_path" 2>/dev/null || echo "[]")

        # Add to temp file (repo -> language array)
        if [[ "$scc_output" != "[]" && -n "$scc_output" ]]; then
            # scc outputs an array of language objects
            LANG_TEMP_NEW=$(mktemp)
            jq --arg repo "$repo_name" --argjson langs "$scc_output" \
                '.[$repo] = $langs' "$LANG_TEMP" > "$LANG_TEMP_NEW"
            mv "$LANG_TEMP_NEW" "$LANG_TEMP"

            if [[ -z "$QUIET_MODE" ]]; then
                lang_count=$(echo "$scc_output" | jq 'length')
                echo "  [$repo_name] Languages: $lang_count detected"
            fi
        else
            if [[ -z "$QUIET_MODE" ]]; then
                echo "  [$repo_name] Languages: none detected"
            fi
        fi
    fi

    # Run syft for SBOM (output gzipped to save space)
    if [[ "$DO_SBOM" == true ]]; then
        sbom_file="$INVENTORY_DIR/${repo_name}-sbom.json.gz"

        # Run syft and pipe through gzip
        if syft dir:"$repo_path" -o syft-json 2>/dev/null | gzip > "$sbom_file"; then
            if [[ -f "$sbom_file" && -s "$sbom_file" ]]; then
                if [[ -z "$QUIET_MODE" ]]; then
                    pkg_count=$(gzip -dc "$sbom_file" | jq '.artifacts | length' 2>/dev/null || echo "0")
                    echo "  [$repo_name] SBOM: $pkg_count packages"
                fi
            fi
        else
            if [[ -z "$QUIET_MODE" ]]; then
                echo "  [$repo_name] SBOM: scan failed"
            fi
            rm -f "$sbom_file"
        fi
    fi
done

# Clear progress line if in quiet mode
[[ -n "$QUIET_MODE" ]] && clear_progress

# Update global languages.json with org data
if [[ "$DO_LANGUAGES" == true ]]; then
    [[ -z "$QUIET_MODE" ]] && log_info "Updating catalog/languages.json..."

    # Calculate totals per language
    TOTALS=$(jq -s '
        .[0] | to_entries | map(.value) | flatten |
        group_by(.Name) |
        map({
            key: .[0].Name,
            value: {
                Files: (map(.Count) | add),
                Code: (map(.Code) | add),
                Lines: (map(.Lines) | add),
                Repos: length
            }
        }) |
        from_entries
    ' "$LANG_TEMP")

    # Create org entry
    ORG_DATA=$(jq -n \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson repos "$(cat "$LANG_TEMP")" \
        --argjson totals "$TOTALS" \
        '{
            last_scan: $timestamp,
            repos: $repos,
            totals: $totals
        }')

    # Update languages.json with this org's data
    UPDATED=$(jq --arg org "$ORG" --argjson data "$ORG_DATA" \
        '.orgs[$org] = $data' "$LANGUAGES_FILE")

    echo "$UPDATED" > "$LANGUAGES_FILE"
fi

# Calculate totals for summary
lang_count=0
if [[ "$DO_LANGUAGES" == true ]]; then
    lang_count=$(jq -r --arg org "$ORG" '.orgs[$org].totals | keys | length' "$LANGUAGES_FILE" 2>/dev/null || echo "0")
fi

sbom_count=0
total_pkgs=0
if [[ "$DO_SBOM" == true ]]; then
    sbom_count=$(find "$INVENTORY_DIR" -name "*-sbom.json.gz" -type f 2>/dev/null | wc -l | tr -d ' ')
    for f in "$INVENTORY_DIR"/*-sbom.json.gz; do
        [[ -f "$f" ]] || continue
        count=$(gzip -dc "$f" 2>/dev/null | jq '.artifacts | length' 2>/dev/null || echo "0")
        total_pkgs=$((total_pkgs + count))
    done
fi

if [[ -z "$QUIET_MODE" ]]; then
    echo ""
    log_info "=== Inventory Summary ==="

    if [[ "$DO_LANGUAGES" == true ]]; then
        echo ""
        echo "Language totals for $ORG:"
        jq -r --arg org "$ORG" '
            .orgs[$org].totals | to_entries |
            sort_by(-.value.Code) |
            .[:10] |
            ["Language", "Files", "Code LOC"],
            (.[] | [.key, .value.Files, .value.Code]) |
            @tsv
        ' "$LANGUAGES_FILE" 2>/dev/null | column -t || echo "  (no data)"
    fi

    if [[ "$DO_SBOM" == true ]]; then
        echo ""
        echo "SBOM files created:"
        echo "  $sbom_count files, $total_pkgs total packages"
        echo "  Location: $INVENTORY_DIR/"
    fi

    echo ""
    log_info "Query commands:"
    echo "  ./scripts/extract-inventory.sh $ORG languages    # Language breakdown"
    echo "  ./scripts/extract-inventory.sh $ORG packages     # All packages"
    echo "  ./scripts/extract-inventory.sh $ORG summary      # Overview"
fi

echo "Inventory: $lang_count languages, $total_pkgs packages"
