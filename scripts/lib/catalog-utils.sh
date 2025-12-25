#!/usr/bin/env bash
# Catalog System Utilities
# Shared functions for the bug bounty target catalog system
#
# Usage: source this file in other scripts
#   source "$SCRIPT_DIR/lib/catalog-utils.sh"

# Ensure we're not run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi

# Get the catalog root directory (assumes scripts are in scripts/)
CATALOG_ROOT="${CATALOG_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
CATALOG_INDEX="$CATALOG_ROOT/catalog/index.json"

# =============================================================================
# Timestamp Functions
# =============================================================================

# Get current timestamp in catalog format (YYYY-MM-DD-HHMM)
get_scan_timestamp() {
    date +"%Y-%m-%d-%H%M"
}

# Get ISO 8601 timestamp
get_iso_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# =============================================================================
# JSON Normalization Functions
# These ensure stable git diffs by sorting JSON consistently
# =============================================================================

# Normalize semgrep JSON for stable diffs
# Sort by: path, start.line, check_id
normalize_semgrep_json() {
    local input="$1"
    local output="${2:-$input}"

    if [[ ! -f "$input" ]]; then
        echo "Error: File not found: $input" >&2
        return 1
    fi

    jq --sort-keys '
        if .results then
            .results |= sort_by(.path, .start.line, .check_id)
        else
            .
        end
    ' "$input" > "${output}.tmp" && mv "${output}.tmp" "$output"
}

# Normalize trufflehog NDJSON for stable diffs
# Input is newline-delimited JSON, sort by: file, DetectorName
normalize_trufflehog_json() {
    local input="$1"
    local output="${2:-$input}"

    if [[ ! -f "$input" ]]; then
        echo "Error: File not found: $input" >&2
        return 1
    fi

    # Handle empty files
    if [[ ! -s "$input" ]]; then
        touch "$output"
        return 0
    fi

    # NDJSON: collect into array, sort, output back as NDJSON
    jq -s '
        sort_by(
            (.SourceMetadata.Data.Filesystem.file // .SourceMetadata.Data.Git.file // ""),
            .DetectorName
        )
    ' "$input" | jq -c '.[]' > "${output}.tmp" && mv "${output}.tmp" "$output"
}

# Normalize KICS JSON for stable diffs
# Sort by: query_name, then files by file_name and line
normalize_kics_json() {
    local input="$1"
    local output="${2:-$input}"

    if [[ ! -f "$input" ]]; then
        echo "Error: File not found: $input" >&2
        return 1
    fi

    jq --sort-keys '
        if .queries then
            .queries |= (sort_by(.query_name) | map(
                if .files then
                    .files |= sort_by(.file_name, .line)
                else
                    .
                end
            ))
        else
            .
        end
    ' "$input" > "${output}.tmp" && mv "${output}.tmp" "$output"
}

# Normalize artifacts JSON for stable diffs
# Sort each array by path
normalize_artifacts_json() {
    local input="$1"
    local output="${2:-$input}"

    if [[ ! -f "$input" ]]; then
        echo "Error: File not found: $input" >&2
        return 1
    fi

    jq --sort-keys '
        if .archives then .archives |= sort_by(.path) else . end |
        if .databases then .databases |= sort_by(.path) else . end |
        if .sql_dumps then .sql_dumps |= sort_by(.path) else . end |
        if .source_backups then .source_backups |= sort_by(.path) else . end
    ' "$input" > "${output}.tmp" && mv "${output}.tmp" "$output"
}

# =============================================================================
# Index Management Functions
# =============================================================================

# Check if catalog index exists
ensure_index_exists() {
    if [[ ! -f "$CATALOG_INDEX" ]]; then
        echo "Error: Catalog index not found at $CATALOG_INDEX" >&2
        echo "Run infrastructure setup first." >&2
        return 1
    fi
}

# Check if an org is tracked
is_org_tracked() {
    local org="$1"

    ensure_index_exists || return 1

    jq -e --arg name "$org" \
        '.tracked_orgs[] | select(.name == $name)' \
        "$CATALOG_INDEX" > /dev/null 2>&1
}

# Get a field from a tracked org
get_org_field() {
    local org="$1"
    local field="$2"

    ensure_index_exists || return 1

    jq -r --arg name "$org" --arg field "$field" \
        '.tracked_orgs[] | select(.name == $name) | .[$field] // empty' \
        "$CATALOG_INDEX"
}

# Get the GitHub org(s) for a tracked program (may differ from program name)
# Supports both single org (github_org: "foo") and multiple (github_orgs: ["foo", "bar"])
# Returns newline-separated list of orgs
get_github_orgs() {
    local org="$1"
    local meta_file="$CATALOG_ROOT/catalog/tracked/$org/meta.json"

    if [[ -f "$meta_file" ]]; then
        # Check for github_orgs array first, then github_org string, then fall back to name
        jq -r '
            if .github_orgs then
                .github_orgs[]
            elif .github_org then
                .github_org
            else
                .name
            end
        ' "$meta_file"
    else
        echo "$org"
    fi
}

# Get the first/primary GitHub org (for backward compatibility)
get_github_org() {
    local org="$1"
    get_github_orgs "$org" | head -1
}

# Count GitHub orgs for a program
count_github_orgs() {
    local org="$1"
    get_github_orgs "$org" | wc -l | xargs
}

# Add an org to the index
add_to_index() {
    local org="$1"
    local platform="$2"
    local program_url="${3:-}"

    ensure_index_exists || return 1

    # Check if already exists
    if is_org_tracked "$org"; then
        echo "Error: '$org' is already tracked" >&2
        return 1
    fi

    jq --arg name "$org" \
       --arg platform "$platform" \
       --arg url "$program_url" \
       --arg date "$(date +%Y-%m-%d)" \
       '.tracked_orgs += [{
           name: $name,
           platform: $platform,
           program_url: $url,
           added_date: $date,
           last_scan: null,
           scan_count: 0,
           status: "active"
       }]' "$CATALOG_INDEX" > "${CATALOG_INDEX}.tmp" && \
    mv "${CATALOG_INDEX}.tmp" "$CATALOG_INDEX"
}

# Update index after a scan
update_index_scan() {
    local org="$1"
    local timestamp="$2"

    ensure_index_exists || return 1

    if ! is_org_tracked "$org"; then
        echo "Error: '$org' is not tracked" >&2
        return 1
    fi

    jq --arg name "$org" \
       --arg ts "$timestamp" \
       '.tracked_orgs |= map(
           if .name == $name then
               .last_scan = $ts | .scan_count += 1
           else
               .
           end
       )' "$CATALOG_INDEX" > "${CATALOG_INDEX}.tmp" && \
    mv "${CATALOG_INDEX}.tmp" "$CATALOG_INDEX"
}

# Remove an org from the index
remove_from_index() {
    local org="$1"

    ensure_index_exists || return 1

    if ! is_org_tracked "$org"; then
        echo "Warning: '$org' is not in the index" >&2
        return 0
    fi

    jq --arg name "$org" \
       '.tracked_orgs |= map(select(.name != $name))' \
       "$CATALOG_INDEX" > "${CATALOG_INDEX}.tmp" && \
    mv "${CATALOG_INDEX}.tmp" "$CATALOG_INDEX"
}

# List all tracked orgs (one per line)
list_tracked_orgs() {
    ensure_index_exists || return 1

    jq -r '.tracked_orgs[].name' "$CATALOG_INDEX"
}

# Get count of tracked orgs
count_tracked_orgs() {
    ensure_index_exists || return 1

    jq '.tracked_orgs | length' "$CATALOG_INDEX"
}

# =============================================================================
# Path Helper Functions
# =============================================================================

# Get the catalog directory for an org
get_org_catalog_dir() {
    local org="$1"
    echo "$CATALOG_ROOT/catalog/tracked/$org"
}

# Get the repos directory for an org
get_org_repos_dir() {
    local org="$1"
    echo "$CATALOG_ROOT/repos/$org"
}

# Get the scans directory for an org
get_org_scans_dir() {
    local org="$1"
    echo "$CATALOG_ROOT/catalog/tracked/$org/scans"
}

# Get the latest scan directory for an org
get_latest_scan_dir() {
    local org="$1"
    local scans_dir
    scans_dir="$(get_org_scans_dir "$org")"

    if [[ ! -d "$scans_dir" ]]; then
        return 1
    fi

    # Get most recent scan by directory name (which is timestamp)
    local latest
    latest=$(ls -1 "$scans_dir" 2>/dev/null | sort | tail -1)

    if [[ -z "$latest" ]]; then
        return 1
    fi

    echo "$scans_dir/$latest"
}

# Get the previous scan directory for an org (second most recent)
get_previous_scan_dir() {
    local org="$1"
    local scans_dir
    scans_dir="$(get_org_scans_dir "$org")"

    if [[ ! -d "$scans_dir" ]]; then
        return 1
    fi

    # Get second most recent scan
    local previous
    previous=$(ls -1 "$scans_dir" 2>/dev/null | sort | tail -2 | head -1)

    # Check we have at least 2 scans
    local count
    count=$(ls -1 "$scans_dir" 2>/dev/null | wc -l | xargs)

    if [[ "$count" -lt 2 ]]; then
        return 1
    fi

    echo "$scans_dir/$previous"
}

# List all scan timestamps for an org
list_org_scans() {
    local org="$1"
    local scans_dir
    scans_dir="$(get_org_scans_dir "$org")"

    if [[ ! -d "$scans_dir" ]]; then
        return 1
    fi

    ls -1 "$scans_dir" 2>/dev/null | sort
}

# =============================================================================
# Validation Functions
# =============================================================================

# Check if DuckDB is available
require_duckdb() {
    if ! command -v duckdb &> /dev/null; then
        echo "Error: DuckDB is required but not installed." >&2
        echo "Install: brew install duckdb" >&2
        return 1
    fi
}

# Check if jq is available
require_jq() {
    if ! command -v jq &> /dev/null; then
        echo "Error: jq is required but not installed." >&2
        echo "Install: brew install jq" >&2
        return 1
    fi
}

# Validate org name (alphanumeric, dash, underscore only)
validate_org_name() {
    local org="$1"

    if [[ ! "$org" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "Error: Invalid org name '$org'. Use only letters, numbers, dashes, and underscores." >&2
        return 1
    fi
}

# =============================================================================
# Archived Repo Functions
# =============================================================================

# Get path to archived repos manifest
get_archived_manifest() {
    local repos_dir="$1"
    echo "$repos_dir/.archived-repos"
}

# Check if a repo is archived (returns 0 if archived, 1 if not)
is_repo_archived() {
    local repos_dir="$1"
    local repo_name="$2"
    local manifest
    manifest="$(get_archived_manifest "$repos_dir")"

    if [[ ! -f "$manifest" ]]; then
        return 1
    fi

    grep -qx "$repo_name" "$manifest"
}

# Get list of active (non-archived) repos in a directory
get_active_repos() {
    local repos_dir="$1"
    local manifest
    manifest="$(get_archived_manifest "$repos_dir")"

    find "$repos_dir" -maxdepth 1 -mindepth 1 -type d ! -name ".*" | while read -r repo; do
        local name
        name=$(basename "$repo")
        if [[ ! -f "$manifest" ]] || ! grep -qx "$name" "$manifest"; then
            echo "$repo"
        fi
    done | sort
}

# Get list of archived repos in a directory
get_archived_repos() {
    local repos_dir="$1"
    local manifest
    manifest="$(get_archived_manifest "$repos_dir")"

    if [[ ! -f "$manifest" ]]; then
        return 0
    fi

    find "$repos_dir" -maxdepth 1 -mindepth 1 -type d ! -name ".*" | while read -r repo; do
        local name
        name=$(basename "$repo")
        if grep -qx "$name" "$manifest"; then
            echo "$repo"
        fi
    done | sort
}

# Count active repos
count_active_repos() {
    local repos_dir="$1"
    get_active_repos "$repos_dir" | wc -l | xargs
}

# Count archived repos
count_archived_repos() {
    local repos_dir="$1"
    get_archived_repos "$repos_dir" | wc -l | xargs
}

# =============================================================================
# Organization Status Functions
# =============================================================================

# Get the status of an org ("active" or "archived")
# Returns "active" if status field is missing (backward compatibility)
get_org_status() {
    local org="$1"

    ensure_index_exists || return 1

    local status
    status=$(jq -r --arg name "$org" \
        '.tracked_orgs[] | select(.name == $name) | .status // "active"' \
        "$CATALOG_INDEX")

    echo "${status:-active}"
}

# Check if an org is archived (returns 0 if archived, 1 if not)
is_org_status_archived() {
    local org="$1"
    local status
    status=$(get_org_status "$org")
    [[ "$status" == "archived" ]]
}

# Set the status of an org (updates both index.json and meta.json)
set_org_status() {
    local org="$1"
    local status="$2"  # "active" or "archived"

    ensure_index_exists || return 1

    if ! is_org_tracked "$org"; then
        echo "Error: '$org' is not tracked" >&2
        return 1
    fi

    local today
    today=$(date +%Y-%m-%d)

    # Update index.json
    if [[ "$status" == "archived" ]]; then
        jq --arg name "$org" \
           --arg status "$status" \
           --arg date "$today" \
           '.tracked_orgs |= map(
               if .name == $name then
                   .status = $status | .archived_date = $date
               else
                   .
               end
           )' "$CATALOG_INDEX" > "${CATALOG_INDEX}.tmp" && \
        mv "${CATALOG_INDEX}.tmp" "$CATALOG_INDEX"
    else
        # Setting to active - remove archived_date
        jq --arg name "$org" \
           --arg status "$status" \
           '.tracked_orgs |= map(
               if .name == $name then
                   .status = $status | del(.archived_date)
               else
                   .
               end
           )' "$CATALOG_INDEX" > "${CATALOG_INDEX}.tmp" && \
        mv "${CATALOG_INDEX}.tmp" "$CATALOG_INDEX"
    fi

    # Update meta.json if it exists
    local meta_file="$CATALOG_ROOT/catalog/tracked/$org/meta.json"
    if [[ -f "$meta_file" ]]; then
        if [[ "$status" == "archived" ]]; then
            jq --arg status "$status" \
               --arg date "$today" \
               '. + {status: $status, archived_date: $date}' \
               "$meta_file" > "${meta_file}.tmp" && \
            mv "${meta_file}.tmp" "$meta_file"
        else
            jq --arg status "$status" \
               '. + {status: $status} | del(.archived_date)' \
               "$meta_file" > "${meta_file}.tmp" && \
            mv "${meta_file}.tmp" "$meta_file"
        fi
    fi
}

# Get human-readable size of repos directory
get_repos_size() {
    local org="$1"
    local repos_dir
    repos_dir="$(get_org_repos_dir "$org")"

    if [[ -d "$repos_dir" ]]; then
        du -sh "$repos_dir" 2>/dev/null | cut -f1
    else
        echo "0"
    fi
}

# Count repos in an org's repos directory
count_org_repos() {
    local org="$1"
    local repos_dir
    repos_dir="$(get_org_repos_dir "$org")"

    if [[ -d "$repos_dir" ]]; then
        find "$repos_dir" -maxdepth 1 -mindepth 1 -type d ! -name ".*" 2>/dev/null | wc -l | xargs
    else
        echo "0"
    fi
}

# Count scans for an org
count_org_scans() {
    local org="$1"
    local scans_dir
    scans_dir="$(get_org_scans_dir "$org")"

    if [[ -d "$scans_dir" ]]; then
        ls -1 "$scans_dir" 2>/dev/null | wc -l | xargs
    else
        echo "0"
    fi
}

# =============================================================================
# Output Helpers
# =============================================================================

# Print a section header
print_header() {
    local title="$1"
    local width="${2:-40}"

    echo ""
    printf '=%.0s' $(seq 1 "$width")
    echo ""
    echo "$title"
    printf '=%.0s' $(seq 1 "$width")
    echo ""
}

# Print a status line
print_status() {
    local label="$1"
    local value="$2"
    printf "  %-20s %s\n" "$label:" "$value"
}

# =============================================================================
# Quiet Mode Output Helpers
# =============================================================================

# Global quiet mode flag (set by scripts that source this file)
QUIET_MODE="${QUIET_MODE:-}"

# Print message only if not in quiet mode
log_verbose() {
    [[ -z "$QUIET_MODE" ]] && echo "$@"
}

# Print progress indicator: [current/total] message
# Always prints, even in quiet mode
log_progress() {
    local current="$1"
    local total="$2"
    local message="$3"
    printf "\r[%d/%d] %s" "$current" "$total" "$message"
}

# Print progress with newline (for when each item should be on its own line)
log_progress_line() {
    local current="$1"
    local total="$2"
    local message="$3"
    printf "[%d/%d] %s\n" "$current" "$total" "$message"
}

# Clear progress line (use before printing final output)
clear_progress() {
    printf "\r\033[K"
}

# Print final summary line (always prints)
log_summary() {
    echo "$@"
}

# Print section header only if not in quiet mode
log_header() {
    local title="$1"
    if [[ -z "$QUIET_MODE" ]]; then
        echo "========================================"
        echo "$title"
        echo "========================================"
    fi
}

# Print a quiet-mode compatible summary block
# Usage: print_scan_summary "Scanner Name" findings_count [extra_info]
print_scan_summary() {
    local scanner="$1"
    local count="$2"
    local extra="${3:-}"

    if [[ -n "$extra" ]]; then
        printf "%-12s %d %s\n" "$scanner:" "$count" "$extra"
    else
        printf "%-12s %d\n" "$scanner:" "$count"
    fi
}
