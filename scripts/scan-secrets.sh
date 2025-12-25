#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <org-name> [--repos-dir <path>] [--output-dir <path>] [-q|--quiet]"
    echo "Scan all repositories for secrets using trufflehog."
    echo ""
    echo "Options:"
    echo "  --repos-dir <path>    Directory containing repos to scan"
    echo "  --output-dir <path>   Output directory for results"
    echo "  -q, --quiet           Quiet mode: show progress and final summary only"
    exit 1
fi

ORG="$1"
shift

REPOS_DIR=""
OUTPUT_BASE=""
QUIET_MODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repos-dir)
            REPOS_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_BASE="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET_MODE="1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

export QUIET_MODE

REPOS_DIR="${REPOS_DIR:-$ORG}"
OUTPUT_BASE="${OUTPUT_BASE:-findings/$ORG}"

# Handle both relative and absolute paths
if [[ "$OUTPUT_BASE" = /* ]]; then
    OUTPUT_DIR="${OUTPUT_BASE}/trufflehog-results"
else
    OUTPUT_DIR="$(pwd)/${OUTPUT_BASE}/trufflehog-results"
fi

if [[ ! -d "$REPOS_DIR" ]]; then
    echo "Error: Directory '$REPOS_DIR' not found."
    exit 1
fi

if ! command -v trufflehog &> /dev/null; then
    echo "Error: trufflehog is required but not installed."
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create exclusion patterns file for trufflehog
EXCLUDE_FILE=$(mktemp)
cat > "$EXCLUDE_FILE" << 'EOF'
vendor/
node_modules/
3rdparty/
EOF
trap "rm -f $EXCLUDE_FILE" EXIT

# Source utility functions for archived repo info
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

# Scan ALL repos including archived (secrets are the one thing we always scan for)
REPOS=$(find "$REPOS_DIR" -maxdepth 1 -mindepth 1 -type d ! -name ".*" | sort)
REPO_COUNT=$(echo "$REPOS" | wc -l | xargs)
ARCHIVED_COUNT=$(count_archived_repos "$REPOS_DIR")

log_verbose "Scanning $REPO_COUNT repositories in $REPOS_DIR for secrets"
[[ "$ARCHIVED_COUNT" -gt 0 ]] && log_verbose "  (including $ARCHIVED_COUNT archived repos)"
log_verbose "Results will be saved to: $OUTPUT_DIR/<repo>.json"
log_verbose ""

# Convert repos to array for counting
REPOS_ARRAY=()
while IFS= read -r repo; do
    [[ -n "$repo" ]] && REPOS_ARRAY+=("$repo")
done <<< "$REPOS"

current=0
total_findings=0
verified_count=0

for repo in "${REPOS_ARRAY[@]}"; do
    name=$(basename "$repo")
    output_file="${OUTPUT_DIR}/${name}.json.gz"
    current=$((current + 1))

    if [[ -n "$QUIET_MODE" ]]; then
        log_progress "$current" "$REPO_COUNT" "$name"
    else
        echo "[$name] Scanning..."
    fi

    cd "$repo"
    # Pipe trufflehog output directly through gzip
    trufflehog git file://. --results=verified,unknown --exclude-paths="$EXCLUDE_FILE" --json 2>/dev/null | gzip > "$output_file" || true
    cd - > /dev/null

    # Count findings (decompress to count lines)
    finding_count=$(gzip -dc "$output_file" 2>/dev/null | wc -l | xargs)
    repo_verified=$(gzip -dc "$output_file" 2>/dev/null | grep -c '"Verified":true' || echo "0")
    total_findings=$((total_findings + finding_count))
    verified_count=$((verified_count + repo_verified))

    if [[ -z "$QUIET_MODE" ]]; then
        echo "[$name] Done - $finding_count findings"
        echo ""
    fi
done

# Clear progress line if in quiet mode
[[ -n "$QUIET_MODE" ]] && clear_progress

log_verbose "Completed scanning $REPO_COUNT repositories."
log_verbose "Results saved to: $OUTPUT_DIR/"

echo "Trufflehog: $total_findings findings ($verified_count verified)"

log_verbose ""
log_verbose "Extract findings:"
log_verbose "  ./scripts/extract-trufflehog-findings.sh $ORG              # Summary view"
log_verbose "  ./scripts/extract-trufflehog-findings.sh $ORG verified     # Verified secrets only"
log_verbose "  ./scripts/extract-trufflehog-findings.sh $ORG detectors    # By detector type"
log_verbose ""
log_verbose "Review with Claude:"
log_verbose "  /review-trufflehog $ORG"
