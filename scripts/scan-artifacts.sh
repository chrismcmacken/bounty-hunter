#!/usr/bin/env bash
set -euo pipefail

# Scan for artifacts that Trufflehog cannot scan or that need manual review
# - Archives: .zip, .tar.gz, etc. (Trufflehog can't extract)
# - Binary databases: .sqlite, .db (Trufflehog can't pattern match)
# - SQL dumps: May contain PII without matching secret patterns
# - Source code backups: .php.bak, .py.old, etc. (may reveal vulnerabilities)

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <org-name> [--repos-dir <path>] [--output-dir <path>] [-q|--quiet]"
    echo "Find artifacts that need manual review or extraction for Trufflehog."
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
OUTPUT_BASE="${OUTPUT_BASE:-scans/$ORG}"

# Handle both relative and absolute paths
if [[ "$OUTPUT_BASE" = /* ]]; then
    OUTPUT_DIR="${OUTPUT_BASE}/artifact-results"
else
    OUTPUT_DIR="$(pwd)/${OUTPUT_BASE}/artifact-results"
fi

if [[ ! -d "$REPOS_DIR" ]]; then
    echo "Error: Directory '$REPOS_DIR' not found."
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Source utility functions for archived repo detection
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

# Exclusion patterns
EXCLUDE_PATTERN="node_modules|vendor|3rdparty|\.git|__pycache__|\.venv|venv|dist|build|\.next|coverage|test-data|fixtures|testdata|mocks"

# Get only active (non-archived) repos - archived repos are secrets-only
REPOS=$(get_active_repos "$REPOS_DIR")
REPO_COUNT=$(echo "$REPOS" | grep -c . || echo 0)
ARCHIVED_COUNT=$(count_archived_repos "$REPOS_DIR")

log_verbose "Scanning $REPO_COUNT repositories in $REPOS_DIR for artifacts"
[[ "$ARCHIVED_COUNT" -gt 0 ]] && log_verbose "  (skipping $ARCHIVED_COUNT archived repos - secrets-only)"
log_verbose ""

# Track totals
total_archives=0
total_databases=0
total_sql_dumps=0
total_source_backups=0

# Convert repos to array for counting
REPOS_ARRAY=()
while IFS= read -r repo; do
    [[ -n "$repo" ]] && REPOS_ARRAY+=("$repo")
done <<< "$REPOS"

current=0
for repo in "${REPOS_ARRAY[@]}"; do
    current=$((current + 1))
    name=$(basename "$repo")
    output_file="${OUTPUT_DIR}/${name}.json.gz"
    repo_abs_path="$(cd "$repo" && pwd)"

    if [[ -n "$QUIET_MODE" ]]; then
        log_progress "$current" "$REPO_COUNT" "$name"
    fi

    archives=()
    databases=()
    sql_dumps=()
    source_backups=()

    # Find archives (Trufflehog can't extract these)
    while IFS= read -r -d '' file; do
        [[ -n "$file" ]] || continue
        echo "$file" | grep -qE "$EXCLUDE_PATTERN" && continue
        rel_path="${file#$repo/}"
        size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
        archives+=("{\"path\":\"$rel_path\",\"size\":$size}")
    done < <(find "$repo" -type f \( -name "*.zip" -o -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" -o -name "*.rar" -o -name "*.7z" -o -name "*.gz" -o -name "*.bz2" \) -print0 2>/dev/null)

    # Find binary databases (Trufflehog can't pattern match inside)
    while IFS= read -r -d '' file; do
        [[ -n "$file" ]] || continue
        echo "$file" | grep -qE "$EXCLUDE_PATTERN" && continue
        rel_path="${file#$repo/}"
        size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
        databases+=("{\"path\":\"$rel_path\",\"size\":$size}")
    done < <(find "$repo" -type f \( -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.db" -o -name "*.mdb" -o -name "*.accdb" \) -print0 2>/dev/null)

    # Find SQL dumps (may contain PII, needs manual review)
    while IFS= read -r -d '' file; do
        [[ -n "$file" ]] || continue
        echo "$file" | grep -qE "$EXCLUDE_PATTERN" && continue
        rel_path="${file#$repo/}"
        size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
        # Check if it looks like real data vs schema-only
        has_data="false"
        if grep -qE "INSERT INTO|COPY .* FROM stdin" "$file" 2>/dev/null; then
            has_data="true"
        fi
        sql_dumps+=("{\"path\":\"$rel_path\",\"size\":$size,\"has_data\":$has_data}")
    done < <(find "$repo" -type f \( -name "*.sql" -o -name "*.dump" -o -name "*.mysql" -o -name "*.pgsql" \) -print0 2>/dev/null)

    # Find source code backups (may reveal vulnerabilities in "fixed" code)
    while IFS= read -r -d '' file; do
        [[ -n "$file" ]] || continue
        echo "$file" | grep -qE "$EXCLUDE_PATTERN" && continue
        rel_path="${file#$repo/}"
        size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
        source_backups+=("{\"path\":\"$rel_path\",\"size\":$size}")
    done < <(find "$repo" -type f \( \
        -name "*.php.bak" -o -name "*.php.old" -o -name "*.php.orig" -o -name "*.php~" \
        -o -name "*.py.bak" -o -name "*.py.old" -o -name "*.py.orig" -o -name "*.py~" \
        -o -name "*.js.bak" -o -name "*.js.old" -o -name "*.js.orig" -o -name "*.js~" \
        -o -name "*.rb.bak" -o -name "*.rb.old" -o -name "*.rb.orig" -o -name "*.rb~" \
        -o -name "*.java.bak" -o -name "*.java.old" -o -name "*.java.orig" \
        -o -name "*.go.bak" -o -name "*.go.old" -o -name "*.go.orig" \
        -o -name "*.env.bak" -o -name "*.env.old" -o -name "*.env.backup" -o -name ".env.local" \
        -o -name "config.*.bak" -o -name "config.*.old" -o -name "settings.*.bak" \
    \) -print0 2>/dev/null)

    # Build JSON output
    archive_count=${#archives[@]}
    db_count=${#databases[@]}
    sql_count=${#sql_dumps[@]}
    source_count=${#source_backups[@]}

    total_archives=$((total_archives + archive_count))
    total_databases=$((total_databases + db_count))
    total_sql_dumps=$((total_sql_dumps + sql_count))
    total_source_backups=$((total_source_backups + source_count))

    total=$((archive_count + db_count + sql_count + source_count))

    if [[ $total -gt 0 ]]; then
        # Pipe JSON through gzip
        cat << EOF | gzip > "$output_file"
{
  "repo": "$name",
  "scanned_from": "$repo_abs_path",
  "archives": $(printf '%s\n' "${archives[@]:-}" | jq -s '.' 2>/dev/null || echo "[]"),
  "databases": $(printf '%s\n' "${databases[@]:-}" | jq -s '.' 2>/dev/null || echo "[]"),
  "sql_dumps": $(printf '%s\n' "${sql_dumps[@]:-}" | jq -s '.' 2>/dev/null || echo "[]"),
  "source_backups": $(printf '%s\n' "${source_backups[@]:-}" | jq -s '.' 2>/dev/null || echo "[]")
}
EOF
        if [[ -z "$QUIET_MODE" ]]; then
            echo "[$name] Found: $archive_count archives, $db_count databases, $sql_count SQL dumps, $source_count source backups"
        fi
    else
        rm -f "$output_file"
    fi
done

# Clear progress line if in quiet mode
[[ -n "$QUIET_MODE" ]] && clear_progress

total_all=$((total_archives + total_databases + total_sql_dumps + total_source_backups))

log_verbose ""
log_verbose "========================================"
log_verbose "Artifact Scan Summary"
log_verbose "========================================"
log_verbose "Archives (need extraction):    $total_archives"
log_verbose "Binary databases:              $total_databases"
log_verbose "SQL dumps (review for PII):    $total_sql_dumps"
log_verbose "Source code backups:           $total_source_backups"
log_verbose "========================================"

echo "Artifacts: $total_all items ($total_archives archives, $total_databases DBs, $total_sql_dumps SQL, $total_source_backups backups)"

if [[ $total_archives -gt 0 ]] && [[ -z "$QUIET_MODE" ]]; then
    echo ""
    echo "To extract archives and scan with Trufflehog:"
    echo "  ./scripts/extract-and-scan-archives.sh $ORG [repo]"
fi

if [[ $((total_sql_dumps + total_source_backups)) -gt 0 ]] && [[ -z "$QUIET_MODE" ]]; then
    echo ""
    echo "Extract findings:"
    echo "  ./scripts/extract-artifact-findings.sh $ORG              # Summary view"
    echo "  ./scripts/extract-artifact-findings.sh $ORG archives     # Archives only"
    echo "  ./scripts/extract-artifact-findings.sh $ORG sql          # SQL dumps with data"
fi

log_verbose ""
log_verbose "Review with Claude:"
log_verbose "  /review-artifacts $ORG"
