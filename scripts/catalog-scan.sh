#!/usr/bin/env bash
# Run security scans for an organization
#
# Usage: ./scripts/catalog-scan.sh <org-name> [options]
#
# By default, runs in catalog mode (tracked org with results stored in catalog).
# Use --no-catalog for one-off scans without catalog integration.
#
# Examples:
#   ./scripts/catalog-scan.sh acme-corp              # Catalog scan (tracked org)
#   ./scripts/catalog-scan.sh acme-corp --skip-kics  # Skip KICS scanner
#   ./scripts/catalog-scan.sh acme-corp --no-catalog --repos-dir ./acme  # One-off scan

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

usage() {
    cat << EOF
Usage: $0 <org-name> [options]

Run security scans for an organization's repositories.

Modes:
    (default)       Catalog mode - org must be tracked, results stored in catalog
    --no-catalog    One-off scan - no tracking required, results in scans/<org>/

Options:
    --repos-dir <path>   Directory containing repos (catalog: repos/<org>, standalone: ./<org>)
    --output-dir <path>  Directory for results (default: scans/<org>)
    --no-pull            Skip git pull on repositories (catalog mode only)
    --no-commit          Skip git commit prompt (catalog mode only)
    -q, --quiet          Quiet mode: show progress and final summary only
    -h, --help           Show this help message

Scan selection:
    --semgrep            Run semgrep only
    --secrets            Run trufflehog only
    --artifacts          Run artifacts only
    --kics               Run KICS only
    --inventory          Run inventory only (scc + syft)
    --skip-semgrep       Skip semgrep scan
    --skip-secrets       Skip trufflehog scan
    --skip-artifacts     Skip artifact scan
    --skip-kics          Skip KICS scan
    --skip-inventory     Skip inventory scan (scc + syft)

Examples:
    $0 acme-corp                              # Full catalog scan
    $0 acme-corp --no-pull                    # Scan without updating repos
    $0 acme-corp --skip-kics                  # Skip KICS scanner
    $0 acme-corp --semgrep --secrets          # Only semgrep and trufflehog
    $0 acme-corp --no-catalog --repos-dir ./my-repos  # One-off scan
    $0 acme-corp --quiet                      # Quiet output with progress only
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

# Parse options
NO_CATALOG=""
NO_PULL=""
NO_COMMIT=""
REPOS_DIR=""
OUTPUT_DIR=""
QUIET_MODE=""
RUN_SEMGREP=""
RUN_SECRETS=""
RUN_ARTIFACTS=""
RUN_KICS=""
RUN_INVENTORY=""
SKIP_SEMGREP=""
SKIP_SECRETS=""
SKIP_ARTIFACTS=""
SKIP_KICS=""
SKIP_INVENTORY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-catalog)
            NO_CATALOG="1"
            shift
            ;;
        --no-pull)
            NO_PULL="1"
            shift
            ;;
        --no-commit)
            NO_COMMIT="1"
            shift
            ;;
        --repos-dir)
            REPOS_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET_MODE="1"
            shift
            ;;
        --semgrep)
            RUN_SEMGREP="1"
            shift
            ;;
        --secrets)
            RUN_SECRETS="1"
            shift
            ;;
        --artifacts)
            RUN_ARTIFACTS="1"
            shift
            ;;
        --kics)
            RUN_KICS="1"
            shift
            ;;
        --inventory)
            RUN_INVENTORY="1"
            shift
            ;;
        --skip-semgrep)
            SKIP_SEMGREP="1"
            shift
            ;;
        --skip-secrets)
            SKIP_SECRETS="1"
            shift
            ;;
        --skip-artifacts)
            SKIP_ARTIFACTS="1"
            shift
            ;;
        --skip-kics)
            SKIP_KICS="1"
            shift
            ;;
        --skip-inventory)
            SKIP_INVENTORY="1"
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

export QUIET_MODE

# Determine which scans to run
if [[ -n "$RUN_SEMGREP" || -n "$RUN_SECRETS" || -n "$RUN_ARTIFACTS" || -n "$RUN_KICS" || -n "$RUN_INVENTORY" ]]; then
    # Specific scans requested - only run those
    DO_SEMGREP="${RUN_SEMGREP:-}"
    DO_SECRETS="${RUN_SECRETS:-}"
    DO_ARTIFACTS="${RUN_ARTIFACTS:-}"
    DO_KICS="${RUN_KICS:-}"
    DO_INVENTORY="${RUN_INVENTORY:-}"
else
    # Run all by default, respecting skip flags
    DO_SEMGREP="1"
    DO_SECRETS="1"
    DO_ARTIFACTS="1"
    DO_KICS="1"
    DO_INVENTORY="1"
    [[ -n "$SKIP_SEMGREP" ]] && DO_SEMGREP=""
    [[ -n "$SKIP_SECRETS" ]] && DO_SECRETS=""
    [[ -n "$SKIP_ARTIFACTS" ]] && DO_ARTIFACTS=""
    [[ -n "$SKIP_KICS" ]] && DO_KICS=""
    [[ -n "$SKIP_INVENTORY" ]] && DO_INVENTORY=""
fi

# =============================================================================
# Mode-specific setup
# =============================================================================

GITHUB_ORGS=()
TIMESTAMP=""
SCAN_DIR=""

if [[ -z "$NO_CATALOG" ]]; then
    # CATALOG MODE: Verify tracking and set up catalog paths
    if ! is_org_tracked "$ORG"; then
        echo "Error: '$ORG' is not tracked"
        echo ""
        echo "Options:"
        echo "  Track first:    ./scripts/catalog-track.sh $ORG <platform>"
        echo "  Or use:         $0 $ORG --no-catalog --repos-dir <path>"
        exit 1
    fi

    # Restore status to active if org was archived (scanning implies active use)
    if is_org_status_archived "$ORG"; then
        echo "Note: Restoring '$ORG' from archived to active status"
        set_org_status "$ORG" "active"
    fi

    # Get github_org(s) from meta.json for display
    while IFS= read -r org; do
        [[ -n "$org" ]] && GITHUB_ORGS+=("$org")
    done < <(get_github_orgs "$ORG")

    # Set default repos dir for catalog mode
    REPOS_DIR="${REPOS_DIR:-$CATALOG_ROOT/repos/$ORG}"
    OUTPUT_DIR="${OUTPUT_DIR:-$CATALOG_ROOT/scans/$ORG}"

    if [[ ! -d "$REPOS_DIR" ]]; then
        echo "Error: Repos not found at $REPOS_DIR"
        echo ""
        echo "Clone first: ./scripts/clone-org-repos.sh $ORG"
        exit 1
    fi

    TIMESTAMP=$(get_scan_timestamp)
    SCAN_DIR="$CATALOG_ROOT/catalog/tracked/$ORG/scans/$TIMESTAMP"
    mkdir -p "$SCAN_DIR"
else
    # STANDALONE MODE: Simple defaults
    REPOS_DIR="${REPOS_DIR:-$ORG}"
    OUTPUT_DIR="${OUTPUT_DIR:-scans/$ORG}"

    if [[ ! -d "$REPOS_DIR" ]]; then
        echo "Error: Repository directory '$REPOS_DIR' not found."
        echo "Clone repositories first: ./scripts/clone-org-repos.sh $ORG --standalone"
        exit 1
    fi
fi

# =============================================================================
# Common setup
# =============================================================================

# Create output directories
mkdir -p "$OUTPUT_DIR/"{semgrep-results,trufflehog-results,artifact-results,kics-results,inventory}

# Count repos
REPO_COUNT=$(find "$REPOS_DIR" -maxdepth 1 -mindepth 1 -type d ! -name ".*" | wc -l | xargs)
ARCHIVED_COUNT=$(count_archived_repos "$REPOS_DIR")
ACTIVE_COUNT=$((REPO_COUNT - ARCHIVED_COUNT))

if [[ "$REPO_COUNT" -eq 0 ]]; then
    echo "Error: No repositories found in $REPOS_DIR"
    exit 1
fi

# =============================================================================
# Print header
# =============================================================================

if [[ -z "$QUIET_MODE" ]]; then
    echo "========================================"
    if [[ -z "$NO_CATALOG" ]]; then
        echo "Catalog Scan: $ORG"
    else
        echo "Security Scan: $ORG"
    fi
    echo "========================================"
    [[ -n "$TIMESTAMP" ]] && echo "Timestamp:    $TIMESTAMP"
    if [[ ${#GITHUB_ORGS[@]} -eq 1 && "${GITHUB_ORGS[0]}" != "$ORG" ]]; then
        echo "GitHub Org:   ${GITHUB_ORGS[0]}"
    elif [[ ${#GITHUB_ORGS[@]} -gt 1 ]]; then
        echo "GitHub Orgs:  ${GITHUB_ORGS[*]}"
    fi
    if [[ "$ARCHIVED_COUNT" -gt 0 ]]; then
        echo "Repositories: $REPO_COUNT total ($ACTIVE_COUNT active, $ARCHIVED_COUNT archived)"
        echo "  Note: Archived repos scanned for secrets only"
    else
        echo "Repositories: $REPO_COUNT"
    fi
    echo "Repos dir:    $REPOS_DIR"
    [[ -n "$SCAN_DIR" ]] && echo "Catalog:      $SCAN_DIR"
    echo "Findings:     $OUTPUT_DIR"
    echo ""
    echo "Scans to run:"
    [[ -n "$DO_SEMGREP" ]] && echo "  - Semgrep (code vulnerabilities)"
    [[ -n "$DO_SECRETS" ]] && echo "  - Trufflehog (secrets)"
    [[ -n "$DO_ARTIFACTS" ]] && echo "  - Artifacts (archives, databases, backups)"
    [[ -n "$DO_KICS" ]] && echo "  - KICS (IaC misconfigurations)"
    [[ -n "$DO_INVENTORY" ]] && echo "  - Inventory (languages + dependencies)"
    echo "========================================"
    echo ""
else
    echo "Scanning $ORG ($REPO_COUNT repos)..."
fi

# =============================================================================
# Catalog mode: Update repos and record commit SHAs
# =============================================================================

if [[ -z "$NO_CATALOG" ]]; then
    [[ -z "$QUIET_MODE" ]] && echo "Recording repository states..."
    COMMITS_JSON="$SCAN_DIR/commits.json"

    # Start building commits JSON
    {
        echo "{"
        echo "  \"scan_time\": \"$(get_iso_timestamp)\","
        echo "  \"repos\": {"
    } > "$COMMITS_JSON"

    first=true
    for repo in "$REPOS_DIR"/*/; do
        [[ -d "$repo/.git" ]] || continue
        name=$(basename "$repo")

        # Update repo if not --no-pull
        if [[ -z "$NO_PULL" ]]; then
            [[ -z "$QUIET_MODE" ]] && echo "  [$name] Pulling latest..."
            if ! git -C "$repo" pull --ff-only 2>/dev/null; then
                [[ -z "$QUIET_MODE" ]] && echo "  [$name] Pull failed (may have local changes), using current state"
            fi
        else
            [[ -z "$QUIET_MODE" ]] && echo "  [$name] Skipping pull (--no-pull)"
        fi

        # Record SHA
        sha=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo "unknown")

        # Add to JSON
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$COMMITS_JSON"
        fi
        printf "    \"%s\": \"%s\"" "$name" "$sha" >> "$COMMITS_JSON"
    done

    # Close commits JSON
    {
        echo ""
        echo "  }"
        echo "}"
    } >> "$COMMITS_JSON"

    if [[ -z "$QUIET_MODE" ]]; then
        echo ""
        echo "Commit SHAs recorded to: commits.json"
        echo ""
    fi
fi

# =============================================================================
# Run scans
# =============================================================================

if [[ -z "$QUIET_MODE" ]]; then
    echo "========================================"
    echo "Running security scans..."
    echo "========================================"
    echo ""
fi

START_TIME=$(date +%s)
SCAN_RESULTS=()

run_scan() {
    local name="$1"
    local script="$2"
    local start end duration
    local quiet_arg=""

    [[ -n "$QUIET_MODE" ]] && quiet_arg="--quiet"

    if [[ -z "$QUIET_MODE" ]]; then
        echo ""
        echo "========================================"
        echo "Running: $name"
        echo "========================================"
        echo ""
    else
        echo "Running: $name..."
    fi

    start=$(date +%s)

    if "$SCRIPT_DIR/$script" "$ORG" --repos-dir "$REPOS_DIR" --output-dir "$OUTPUT_DIR" $quiet_arg; then
        end=$(date +%s)
        duration=$((end - start))
        SCAN_RESULTS+=("$name: completed in ${duration}s")
    else
        end=$(date +%s)
        duration=$((end - start))
        SCAN_RESULTS+=("$name: failed after ${duration}s")
    fi
}

[[ -n "$DO_SEMGREP" ]] && run_scan "Semgrep" "scan-semgrep.sh"
[[ -n "$DO_SECRETS" ]] && run_scan "Trufflehog" "scan-secrets.sh"
[[ -n "$DO_ARTIFACTS" ]] && run_scan "Artifacts" "scan-artifacts.sh"
[[ -n "$DO_KICS" ]] && run_scan "KICS" "scan-kics.sh"
[[ -n "$DO_INVENTORY" ]] && run_scan "Inventory" "scan-inventory.sh"

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

# =============================================================================
# Catalog mode: Merge and normalize results
# =============================================================================

if [[ -z "$NO_CATALOG" ]]; then
    if [[ -z "$QUIET_MODE" ]]; then
        echo ""
        echo "========================================"
        echo "Storing results in catalog..."
        echo "========================================"
        echo ""
    fi

    # Semgrep - merge all repo results into one normalized file (gzip compressed)
    if [[ -d "$OUTPUT_DIR/semgrep-results" ]]; then
        shopt -s nullglob
        semgrep_files=("$OUTPUT_DIR/semgrep-results"/*.json)
        shopt -u nullglob

        if [[ ${#semgrep_files[@]} -gt 0 ]]; then
            jq -s '{ results: map(.results // []) | flatten }' "${semgrep_files[@]}" 2>/dev/null | \
                jq --sort-keys '.results |= sort_by(.path, .start.line, .check_id)' | \
                gzip > "$SCAN_DIR/semgrep.json.gz" 2>/dev/null || echo '{"results":[]}' | gzip > "$SCAN_DIR/semgrep.json.gz"
            count=$(gzip -dc "$SCAN_DIR/semgrep.json.gz" | jq '.results | length' 2>/dev/null || echo "0")
            [[ -z "$QUIET_MODE" ]] && echo "  Semgrep:    $count findings"
        fi
    fi

    # Trufflehog - concatenate NDJSON files, sort, output as NDJSON (gzip compressed)
    if [[ -d "$OUTPUT_DIR/trufflehog-results" ]]; then
        shopt -s nullglob
        tf_files=("$OUTPUT_DIR/trufflehog-results"/*.json)
        shopt -u nullglob

        if [[ ${#tf_files[@]} -gt 0 ]]; then
            cat "${tf_files[@]}" 2>/dev/null | \
                jq -s 'sort_by(.SourceMetadata.Data.Git.file // .SourceMetadata.Data.Filesystem.file // "", .DetectorName)' 2>/dev/null | \
                jq -c '.[]' | gzip > "$SCAN_DIR/trufflehog.json.gz" 2>/dev/null || touch "$SCAN_DIR/trufflehog.json.gz"
            count=$(gzip -dc "$SCAN_DIR/trufflehog.json.gz" 2>/dev/null | wc -l | xargs)
            verified=$(gzip -dc "$SCAN_DIR/trufflehog.json.gz" 2>/dev/null | grep -c '"Verified":true' || echo "0")
            [[ -z "$QUIET_MODE" ]] && echo "  Trufflehog: $count findings ($verified verified)"
        fi
    fi

    # KICS - merge results (gzip compressed)
    if [[ -d "$OUTPUT_DIR/kics-results" ]]; then
        shopt -s nullglob
        kics_files=("$OUTPUT_DIR/kics-results"/*.json)
        shopt -u nullglob

        if [[ ${#kics_files[@]} -gt 0 ]]; then
            jq -s '{
                queries: map(.queries // []) | flatten | unique_by(.query_id),
                total_counter: map(.total_counter // 0) | add,
                severity_counters: {
                    HIGH: map(.severity_counters.HIGH // 0) | add,
                    MEDIUM: map(.severity_counters.MEDIUM // 0) | add,
                    LOW: map(.severity_counters.LOW // 0) | add
                }
            }' "${kics_files[@]}" 2>/dev/null | \
                jq --sort-keys '.' | gzip > "$SCAN_DIR/kics.json.gz" 2>/dev/null || echo '{"queries":[],"total_counter":0}' | gzip > "$SCAN_DIR/kics.json.gz"
            count=$(gzip -dc "$SCAN_DIR/kics.json.gz" | jq '.total_counter // 0' 2>/dev/null || echo "0")
            [[ -z "$QUIET_MODE" ]] && echo "  KICS:       $count findings"
        fi
    fi

    # Artifacts - merge results (gzip compressed)
    if [[ -d "$OUTPUT_DIR/artifact-results" ]]; then
        shopt -s nullglob
        artifact_files=("$OUTPUT_DIR/artifact-results"/*.json)
        shopt -u nullglob

        if [[ ${#artifact_files[@]} -gt 0 ]]; then
            jq -s '{
                repos: .,
                totals: {
                    archives: map(.archives | length) | add,
                    databases: map(.databases | length) | add,
                    sql_dumps: map(.sql_dumps | length) | add,
                    source_backups: map(.source_backups | length) | add
                }
            }' "${artifact_files[@]}" 2>/dev/null | \
                jq --sort-keys '.' | gzip > "$SCAN_DIR/artifacts.json.gz" 2>/dev/null || echo '{"repos":[],"totals":{}}' | gzip > "$SCAN_DIR/artifacts.json.gz"
            count=$(gzip -dc "$SCAN_DIR/artifacts.json.gz" | jq '.totals | add // 0' 2>/dev/null || echo "0")
            [[ -z "$QUIET_MODE" ]] && echo "  Artifacts:  $count items"
        fi
    fi

    # Update catalog index
    update_index_scan "$ORG" "$TIMESTAMP"
fi

# =============================================================================
# Print summary
# =============================================================================

echo ""
echo "========================================"
echo "Scan Complete: $ORG"
echo "========================================"
echo ""
echo "Duration: ${TOTAL_DURATION}s"
echo ""

if [[ -z "$QUIET_MODE" ]]; then
    echo "Scan Results:"
    for result in "${SCAN_RESULTS[@]}"; do
        echo "  $result"
    done
    echo ""
fi

# Count findings
echo "Finding Counts:"

if [[ -d "$OUTPUT_DIR/semgrep-results" ]]; then
    semgrep_count=0
    for f in "$OUTPUT_DIR/semgrep-results"/*.json; do
        [[ -f "$f" ]] || continue
        count=$(jq '.results | length' "$f" 2>/dev/null || echo "0")
        semgrep_count=$((semgrep_count + count))
    done
    echo "  Semgrep:    $semgrep_count"
fi

if [[ -d "$OUTPUT_DIR/trufflehog-results" ]]; then
    trufflehog_count=0
    for f in "$OUTPUT_DIR/trufflehog-results"/*.json; do
        [[ -f "$f" ]] || continue
        count=$(wc -l < "$f" | xargs)
        trufflehog_count=$((trufflehog_count + count))
    done
    echo "  Trufflehog: $trufflehog_count"
fi

if [[ -d "$OUTPUT_DIR/artifact-results" ]]; then
    artifact_count=$(find "$OUTPUT_DIR/artifact-results" -name "*.json" -type f | wc -l | xargs)
    echo "  Artifacts:  $artifact_count repos scanned"
fi

if [[ -d "$OUTPUT_DIR/kics-results" ]]; then
    kics_count=0
    for f in "$OUTPUT_DIR/kics-results"/*.json; do
        [[ -f "$f" ]] || continue
        count=$(jq '.total_counter // 0' "$f" 2>/dev/null || echo "0")
        kics_count=$((kics_count + count))
    done
    echo "  KICS:       $kics_count"
fi

if [[ -d "$OUTPUT_DIR/inventory" ]]; then
    sbom_count=$(find "$OUTPUT_DIR/inventory" -name "*-sbom.json" -type f 2>/dev/null | wc -l | xargs)
    if [[ "$sbom_count" -gt 0 ]]; then
        echo "  Inventory:  $sbom_count repos with SBOM"
    fi
fi

# =============================================================================
# Catalog mode: Show catalog info and git commit prompt
# =============================================================================

if [[ -z "$NO_CATALOG" ]]; then
    if [[ -z "$QUIET_MODE" ]]; then
        echo ""
        echo "Catalog results: $SCAN_DIR"
        ls -la "$SCAN_DIR"
        echo ""

        # Git commit prompt
        if [[ -z "$NO_COMMIT" ]]; then
            echo "----------------------------------------"
            read -p "Commit scan results to git? [y/N] " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                git add "$SCAN_DIR"
                git add "$CATALOG_ROOT/catalog/index.json"
                git commit -m "Scan $ORG - $TIMESTAMP

Catalog scan results for $ORG at $TIMESTAMP"
                echo ""
                echo "Committed to git."
            else
                echo ""
                echo "Not committed. To commit later:"
                echo "  git add $SCAN_DIR catalog/index.json"
                echo "  git commit -m 'Scan $ORG - $TIMESTAMP'"
            fi
        else
            echo "To commit results:"
            echo "  git add $SCAN_DIR catalog/index.json"
            echo "  git commit -m 'Scan $ORG - $TIMESTAMP'"
        fi

        echo ""
        echo "Next steps:"
        echo "  View status:  ./scripts/catalog-status.sh"
        echo "  Compare:      ./scripts/catalog-diff.sh $ORG"
        echo "  Extract:      ./scripts/extract-semgrep-findings.sh $ORG"
    fi
else
    if [[ -z "$QUIET_MODE" ]]; then
        echo ""
        echo "========================================"
        echo "Next Steps"
        echo "========================================"
        echo ""
        echo "Extract findings:"
        echo "  ./scripts/extract-semgrep-findings.sh $ORG"
        echo "  ./scripts/extract-trufflehog-findings.sh $ORG"
        echo "  ./scripts/extract-artifact-findings.sh $ORG"
        echo "  ./scripts/extract-kics-findings.sh $ORG"
        echo ""
        echo "Review with Claude:"
        echo "  /review-all $ORG"
    fi
fi
echo ""
