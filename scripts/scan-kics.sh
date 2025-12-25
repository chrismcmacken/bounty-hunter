#!/usr/bin/env bash
set -euo pipefail

# KICS (Keeping Infrastructure as Code Secure) Scanner
#
# Scans for misconfigurations in Infrastructure as Code files:
# - Terraform, CloudFormation, Kubernetes, Helm, Ansible, Docker
# - Outputs JSON for analysis with extract-kics-findings.sh
#
# NOTE: IaC findings are reconnaissance, not direct vulnerabilities.
# Use findings to discover resource names, then verify actual exposure.

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <org-name> [--repos-dir <path>] [--output-dir <path>] [-q|--quiet]"
    echo "Scan all repositories for IaC misconfigurations using KICS."
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

if [[ ! -d "$REPOS_DIR" ]]; then
    echo "Error: Directory '$REPOS_DIR' not found."
    exit 1
fi

if ! command -v kics &> /dev/null; then
    echo "Error: kics is required but not installed."
    echo ""
    echo "Install options:"
    echo "  brew install kics"
    echo "  docker pull checkmarx/kics:latest"
    echo "  https://github.com/Checkmarx/kics#installation"
    exit 1
fi

# Find KICS queries path (required for Homebrew installations)
KICS_QUERIES_PATH=""
if [[ -d "/opt/homebrew/opt/kics/share/kics/assets/queries" ]]; then
    KICS_QUERIES_PATH="/opt/homebrew/opt/kics/share/kics/assets/queries"
elif [[ -d "/usr/local/opt/kics/share/kics/assets/queries" ]]; then
    KICS_QUERIES_PATH="/usr/local/opt/kics/share/kics/assets/queries"
elif [[ -d "/usr/share/kics/assets/queries" ]]; then
    KICS_QUERIES_PATH="/usr/share/kics/assets/queries"
fi

if [[ -z "$KICS_QUERIES_PATH" ]]; then
    echo "Warning: Could not find KICS queries path. KICS may fail."
    echo "Try: brew reinstall kics"
fi

# Handle both relative and absolute paths
if [[ "$OUTPUT_BASE" = /* ]]; then
    RESULTS_DIR="${OUTPUT_BASE}/kics-results"
else
    RESULTS_DIR="$(pwd)/${OUTPUT_BASE}/kics-results"
fi
mkdir -p "$RESULTS_DIR"

# Source utility functions for archived repo detection
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

# Exclusion directory names - KICS needs paths relative to scan target
EXCLUDE_DIRS=(
    "test"
    "tests"
    "__tests__"
    "examples"
    "example"
    "vendor"
    "node_modules"
    "3rdparty"
    "testdata"
    "fixtures"
    "samples"
    "demo"
)

# Get only active (non-archived) repos - archived repos are secrets-only
REPOS=$(get_active_repos "$REPOS_DIR")
REPO_COUNT=$(echo "$REPOS" | grep -c . || echo 0)
ARCHIVED_COUNT=$(count_archived_repos "$REPOS_DIR")

log_verbose "Scanning $REPO_COUNT repositories in $REPOS_DIR with KICS"
[[ "$ARCHIVED_COUNT" -gt 0 ]] && log_verbose "  (skipping $ARCHIVED_COUNT archived repos - secrets-only)"
log_verbose "Targets: Terraform, CloudFormation, Kubernetes, Helm, Ansible, Docker"
if [[ -n "$KICS_QUERIES_PATH" ]]; then
    log_verbose "Queries: $KICS_QUERIES_PATH"
fi
log_verbose "Filters: Excluding tests/examples/vendor"
log_verbose "Results: $RESULTS_DIR/"
log_verbose ""

# Convert repos to array for counting
REPOS_ARRAY=()
while IFS= read -r repo; do
    [[ -n "$repo" ]] && REPOS_ARRAY+=("$repo")
done <<< "$REPOS"

current=0
for repo in "${REPOS_ARRAY[@]}"; do
    name=$(basename "$repo")
    output_file="$RESULTS_DIR/$name.json.gz"
    current=$((current + 1))

    if [[ -n "$QUIET_MODE" ]]; then
        log_progress "$current" "$REPO_COUNT" "$name"
    else
        echo "[$name] Scanning..."
    fi

    # Check if repo has any IaC files worth scanning
    # Use -print -quit to avoid SIGPIPE from head -1 with pipefail
    iac_files=$(find "$repo" -type f \( \
        -name "*.tf" -o -name "*.tfvars" \
        -o -name "*.yaml" -o -name "*.yml" \
        -o -name "Dockerfile" -o -name "docker-compose*.yml" \
        -o -name "*.json" -name "*cloudformation*" \
        -o -name "Chart.yaml" -o -name "values.yaml" \
    \) -print -quit 2>/dev/null || true)

    if [[ -z "$iac_files" ]]; then
        if [[ -z "$QUIET_MODE" ]]; then
            echo "[$name] No IaC files detected, skipping"
        fi
        # Create empty result file (gzipped)
        echo '{"queries": [], "total_counter": 0, "files_scanned": 0}' | gzip > "$output_file"
        continue
    fi

    # Run KICS
    # --no-progress: Cleaner output for scripting
    # --report-formats json: Machine-readable output
    # --output-path: Where to write results
    # -q: Path to queries (required for Homebrew)
    # -p: Path to scan
    KICS_QUERY_ARG=""
    if [[ -n "$KICS_QUERIES_PATH" ]]; then
        KICS_QUERY_ARG="-q $KICS_QUERIES_PATH"
    fi

    # Build exclude args for directories that exist in this repo
    # KICS needs paths relative to scan target (e.g., "vendor/*" not "**/vendor/**")
    EXCLUDE_ARGS=()
    repo_abs=$(cd "$repo" && pwd)
    for dir in "${EXCLUDE_DIRS[@]}"; do
        if [[ -d "$repo_abs/$dir" ]]; then
            EXCLUDE_ARGS+=("-e" "$repo_abs/$dir/*")
        fi
    done

    kics scan \
        --no-progress \
        --report-formats json \
        --output-path "$RESULTS_DIR" \
        --output-name "$name" \
        --exclude-severities info,low \
        $KICS_QUERY_ARG \
        "${EXCLUDE_ARGS[@]}" \
        -p "$repo" 2>&1 | grep -v "^Scanning\|^Files scanned\|^Parsed files" || true

    # KICS creates file with .json extension - gzip it
    if [[ -f "$RESULTS_DIR/${name}.json" ]]; then
        # Count findings before gzipping
        high=$(jq '.severity_counters.HIGH // 0' "$RESULTS_DIR/${name}.json" 2>/dev/null || echo "0")
        medium=$(jq '.severity_counters.MEDIUM // 0' "$RESULTS_DIR/${name}.json" 2>/dev/null || echo "0")
        low=$(jq '.severity_counters.LOW // 0' "$RESULTS_DIR/${name}.json" 2>/dev/null || echo "0")
        total=$(jq '.total_counter // 0' "$RESULTS_DIR/${name}.json" 2>/dev/null || echo "0")
        if [[ -z "$QUIET_MODE" ]]; then
            echo "[$name] Found $total findings (HIGH: $high, MEDIUM: $medium, LOW: $low)"
        fi
        # Gzip the file
        gzip -f "$RESULTS_DIR/${name}.json"
    else
        if [[ -z "$QUIET_MODE" ]]; then
            echo "[$name] No results file created"
        fi
        echo '{"queries": [], "total_counter": 0, "severity_counters": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}}' | gzip > "$output_file"
    fi
done

# Clear progress line if in quiet mode
[[ -n "$QUIET_MODE" ]] && clear_progress

log_verbose ""
log_verbose "=== Summary ==="

# Aggregate results
total_high=0
total_medium=0
total_low=0
repos_with_findings=0

for f in "$RESULTS_DIR"/*.json.gz; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f" .json.gz)

    high=$(gzip -dc "$f" | jq '.severity_counters.HIGH // 0' 2>/dev/null || echo "0")
    medium=$(gzip -dc "$f" | jq '.severity_counters.MEDIUM // 0' 2>/dev/null || echo "0")
    low=$(gzip -dc "$f" | jq '.severity_counters.LOW // 0' 2>/dev/null || echo "0")
    total=$(gzip -dc "$f" | jq '.total_counter // 0' 2>/dev/null || echo "0")

    if [[ "$total" -gt 0 ]]; then
        log_verbose "$name: $total findings (H:$high M:$medium L:$low)"
        repos_with_findings=$((repos_with_findings + 1))
    fi

    total_high=$((total_high + high))
    total_medium=$((total_medium + medium))
    total_low=$((total_low + low))
done

total_all=$((total_high + total_medium + total_low))

log_verbose ""
log_verbose "Total findings: $total_all"
log_verbose "  HIGH:   $total_high"
log_verbose "  MEDIUM: $total_medium"
log_verbose "  LOW:    $total_low"
log_verbose ""
log_verbose "Repos with findings: $repos_with_findings / $REPO_COUNT"

echo "KICS: $total_all findings (HIGH: $total_high, MEDIUM: $total_medium)"

if [[ "$total_all" -gt 0 ]] && [[ -z "$QUIET_MODE" ]]; then
    echo ""
    echo "Top finding categories:"
    for f in "$RESULTS_DIR"/*.json.gz; do
        [[ -f "$f" ]] || continue
        gzip -dc "$f" | jq -r '.queries[]? | "\(.severity) \(.query_name)"' 2>/dev/null
    done | sort | uniq -c | sort -rn | head -10 | while read count severity_name; do
        echo "  $count  $severity_name"
    done
fi

log_verbose ""
log_verbose "Results saved to: $RESULTS_DIR/"
log_verbose ""
log_verbose "Extract findings:"
log_verbose "  ./scripts/extract-kics-findings.sh $ORG                  # Summary view"
log_verbose "  ./scripts/extract-kics-findings.sh $ORG resources        # Resource identifiers"
log_verbose "  ./scripts/extract-kics-findings.sh $ORG queries          # By query type"
log_verbose ""
log_verbose "Review with Claude:"
log_verbose "  /review-kics $ORG"
