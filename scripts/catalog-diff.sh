#!/usr/bin/env bash
# Compare scan results between two scans for a tracked organization
#
# Usage: ./scripts/catalog-diff.sh <org-name> [scan1] [scan2] [options]
#
# Examples:
#   ./scripts/catalog-diff.sh acme-corp                    # Compare latest two scans
#   ./scripts/catalog-diff.sh acme-corp 2025-01-10-1000   # Compare specific scan to latest
#   ./scripts/catalog-diff.sh acme-corp scan1 scan2 --code # Include code changes
#   ./scripts/catalog-diff.sh acme-corp --summary          # Just show counts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

usage() {
    cat << EOF
Usage: $0 <org-name> [scan1] [scan2] [options]

Compare scan results between two scans.

Arguments:
    org-name    Name of the tracked organization
    scan1       First scan timestamp (default: second-to-last scan)
    scan2       Second scan timestamp (default: latest scan)

Options:
    --code      Show code changes between commit SHAs
    --summary   Show only summary counts (no diff output)
    --scanner <name>  Only diff specific scanner (semgrep, trufflehog, kics, artifacts)
    -h, --help  Show this help message

Examples:
    $0 acme-corp                          # Compare latest two scans
    $0 acme-corp 2025-01-10-1000         # Compare specific scan to latest
    $0 acme-corp --summary               # Quick overview of changes
    $0 acme-corp --scanner semgrep       # Only show semgrep diff
    $0 acme-corp scan1 scan2 --code      # Include code commit history
EOF
    exit 1
}

# Parse arguments
ORG=""
SCAN1=""
SCAN2=""
SHOW_CODE=""
SUMMARY_ONLY=""
SCANNER_FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --code)
            SHOW_CODE="1"
            shift
            ;;
        --summary)
            SUMMARY_ONLY="1"
            shift
            ;;
        --scanner)
            SCANNER_FILTER="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            ;;
        *)
            # Positional arguments: org, scan1, scan2
            if [[ -z "$ORG" ]]; then
                ORG="$1"
            elif [[ -z "$SCAN1" ]]; then
                SCAN1="$1"
            elif [[ -z "$SCAN2" ]]; then
                SCAN2="$1"
            else
                echo "Too many arguments"
                usage
            fi
            shift
            ;;
    esac
done

if [[ -z "$ORG" ]]; then
    usage
fi

# Check if org is tracked
if ! is_org_tracked "$ORG"; then
    echo "Error: '$ORG' is not tracked"
    exit 1
fi

SCANS_DIR="$CATALOG_ROOT/catalog/tracked/$ORG/scans"

if [[ ! -d "$SCANS_DIR" ]]; then
    echo "Error: No scans directory found for $ORG"
    exit 1
fi

# Get available scans sorted by timestamp (macOS compatible)
SCANS=()
while IFS= read -r scan; do
    [[ -n "$scan" ]] && SCANS+=("$scan")
done < <(ls -1 "$SCANS_DIR" 2>/dev/null | sort)

SCAN_COUNT=${#SCANS[@]}

if [[ "$SCAN_COUNT" -eq 0 ]]; then
    echo "Error: No scans found for $ORG"
    exit 1
fi

if [[ "$SCAN_COUNT" -lt 2 && -z "$SCAN1" ]]; then
    echo "Error: Need at least 2 scans to compare (found $SCAN_COUNT)"
    echo ""
    echo "Available scans:"
    for scan in "${SCANS[@]}"; do
        echo "  $scan"
    done
    exit 1
fi

# Default to latest two scans (get last two elements)
if [[ -z "$SCAN1" ]]; then
    SCAN1="${SCANS[$((SCAN_COUNT - 2))]}"
fi
if [[ -z "$SCAN2" ]]; then
    SCAN2="${SCANS[$((SCAN_COUNT - 1))]}"
fi

DIR1="$SCANS_DIR/$SCAN1"
DIR2="$SCANS_DIR/$SCAN2"

if [[ ! -d "$DIR1" ]]; then
    echo "Error: Scan not found: $SCAN1"
    echo ""
    echo "Available scans:"
    for scan in "${SCANS[@]}"; do
        echo "  $scan"
    done
    exit 1
fi

if [[ ! -d "$DIR2" ]]; then
    echo "Error: Scan not found: $SCAN2"
    echo ""
    echo "Available scans:"
    for scan in "${SCANS[@]}"; do
        echo "  $scan"
    done
    exit 1
fi

echo "========================================"
echo "Scan Diff: $ORG"
echo "========================================"
echo "From: $SCAN1"
echo "To:   $SCAN2"
echo "========================================"
echo ""

# Function to read JSON file (handles both .json and .json.gz)
read_json_file() {
    local file="$1"
    if [[ "$file" == *.gz ]]; then
        gzip -dc "$file" 2>/dev/null
    else
        cat "$file" 2>/dev/null
    fi
}

# Function to find scanner result file (checks for .json.gz first, then .json)
find_scanner_file() {
    local dir="$1"
    local scanner="$2"

    if [[ -f "$dir/$scanner.json.gz" ]]; then
        echo "$dir/$scanner.json.gz"
    elif [[ -f "$dir/$scanner.json" ]]; then
        echo "$dir/$scanner.json"
    else
        echo ""
    fi
}

# Function to count findings in a scanner result file
count_findings() {
    local file="$1"
    local scanner="$2"

    if [[ -z "$file" ]]; then
        echo "0"
        return
    fi
    if [[ ! -f "$file" ]]; then
        echo "0"
        return
    fi

    case "$scanner" in
        semgrep)
            read_json_file "$file" | jq '.results | length' 2>/dev/null || echo "0"
            ;;
        trufflehog)
            read_json_file "$file" | wc -l | xargs
            ;;
        kics)
            read_json_file "$file" | jq '.total_counter // (.queries | length)' 2>/dev/null || echo "0"
            ;;
        artifacts)
            read_json_file "$file" | jq '.totals | add // 0' 2>/dev/null || echo "0"
            ;;
        *)
            echo "0"
            ;;
    esac
}

# Function to get finding identifiers for diff
get_finding_ids() {
    local file="$1"
    local scanner="$2"

    if [[ -z "$file" ]]; then
        return
    fi
    if [[ ! -f "$file" ]]; then
        return
    fi

    case "$scanner" in
        semgrep)
            read_json_file "$file" | jq -r '.results[] | "\(.check_id):\(.path):\(.start.line)"' 2>/dev/null | sort
            ;;
        trufflehog)
            read_json_file "$file" | jq -r '"\(.DetectorName):\(.SourceMetadata.Data.Git.file // .SourceMetadata.Data.Filesystem.file // "unknown")"' 2>/dev/null | sort
            ;;
        kics)
            read_json_file "$file" | jq -r '.queries[]? | .files[]? | "\(.query_name):\(.file_name):\(.line)"' 2>/dev/null | sort
            ;;
        artifacts)
            read_json_file "$file" | jq -r '(.repos[]? | .archives[]?.path, .databases[]?.path, .sql_dumps[]?.path, .source_backups[]?.path) // empty' 2>/dev/null | sort
            ;;
    esac
}

# Determine which scanners to diff
if [[ -n "$SCANNER_FILTER" ]]; then
    SCANNERS=("$SCANNER_FILTER")
else
    SCANNERS=(semgrep trufflehog kics artifacts)
fi

# Summary table
echo "Summary:"
echo "----------------------------------------"
printf "%-12s %8s %8s %8s %8s\n" "SCANNER" "BEFORE" "AFTER" "NEW" "REMOVED"
echo "----------------------------------------"

# Use simple variables instead of associative arrays (bash 3 compat)
TOTAL_NEW_ALL=0
TOTAL_REMOVED_ALL=0
NEW_semgrep=0; NEW_trufflehog=0; NEW_kics=0; NEW_artifacts=0
REMOVED_semgrep=0; REMOVED_trufflehog=0; REMOVED_kics=0; REMOVED_artifacts=0

for scanner in "${SCANNERS[@]}"; do
    file1=$(find_scanner_file "$DIR1" "$scanner")
    file2=$(find_scanner_file "$DIR2" "$scanner")

    count1=$(count_findings "$file1" "$scanner")
    count2=$(count_findings "$file2" "$scanner")

    # Get finding IDs and compute diff
    ids1=$(get_finding_ids "$file1" "$scanner")
    ids2=$(get_finding_ids "$file2" "$scanner")

    # Count new (in ids2 but not ids1) and removed (in ids1 but not ids2)
    new_count=0
    removed_count=0
    if [[ -n "$ids1" ]] || [[ -n "$ids2" ]]; then
        new_count=$(comm -13 <(echo "$ids1") <(echo "$ids2") 2>/dev/null | grep -c . 2>/dev/null) || new_count=0
        removed_count=$(comm -23 <(echo "$ids1") <(echo "$ids2") 2>/dev/null | grep -c . 2>/dev/null) || removed_count=0
    fi

    # Ensure counts are valid integers (strip any whitespace)
    new_count=$(echo "$new_count" | tr -d '[:space:]')
    removed_count=$(echo "$removed_count" | tr -d '[:space:]')
    [[ -z "$new_count" || ! "$new_count" =~ ^[0-9]+$ ]] && new_count=0
    [[ -z "$removed_count" || ! "$removed_count" =~ ^[0-9]+$ ]] && removed_count=0

    # Store counts using eval for dynamic variable names
    eval "NEW_${scanner}=$new_count"
    eval "REMOVED_${scanner}=$removed_count"
    TOTAL_NEW_ALL=$((TOTAL_NEW_ALL + new_count))
    TOTAL_REMOVED_ALL=$((TOTAL_REMOVED_ALL + removed_count))

    # Format output
    if [[ "$new_count" -gt 0 ]]; then
        new_str="+$new_count"
    else
        new_str="-"
    fi

    if [[ "$removed_count" -gt 0 ]]; then
        removed_str="-$removed_count"
    else
        removed_str="-"
    fi

    printf "%-12s %8s %8s %8s %8s\n" "$scanner" "$count1" "$count2" "$new_str" "$removed_str"
done

echo "----------------------------------------"
printf "%-12s %8s %8s %8s %8s\n" "TOTAL" "" "" "+${TOTAL_NEW_ALL}" "-${TOTAL_REMOVED_ALL}"
echo ""

# Exit early if summary only
if [[ -n "$SUMMARY_ONLY" ]]; then
    exit 0
fi

# Detailed diffs for each scanner
for scanner in "${SCANNERS[@]}"; do
    file1=$(find_scanner_file "$DIR1" "$scanner")
    file2=$(find_scanner_file "$DIR2" "$scanner")

    # Get counts using eval for dynamic variable names
    eval "new_count=\$NEW_${scanner}"
    eval "removed_count=\$REMOVED_${scanner}"
    new_count=${new_count:-0}
    removed_count=${removed_count:-0}

    # Skip if no changes
    if [[ "$new_count" -eq 0 && "$removed_count" -eq 0 ]]; then
        continue
    fi

    echo "========================================"
    echo "$scanner: +$new_count new, -$removed_count removed"
    echo "========================================"
    echo ""

    # Show new findings
    if [[ "$new_count" -gt 0 ]]; then
        echo "NEW FINDINGS:"
        echo "-------------"

        ids1=$(get_finding_ids "$file1" "$scanner")
        ids2=$(get_finding_ids "$file2" "$scanner")
        new_ids=$(comm -13 <(echo "$ids1") <(echo "$ids2") 2>/dev/null)

        case "$scanner" in
            semgrep)
                # Show details for new semgrep findings
                echo "$new_ids" | head -20 | while IFS=: read -r check_id path line; do
                    [[ -z "$check_id" ]] && continue
                    echo "  + [$check_id] $path:$line"
                done
                remaining=$((new_count - 20))
                [[ "$remaining" -gt 0 ]] && echo "  ... and $remaining more"
                ;;
            trufflehog)
                echo "$new_ids" | head -20 | while IFS=: read -r detector file; do
                    [[ -z "$detector" ]] && continue
                    echo "  + [$detector] $file"
                done
                remaining=$((new_count - 20))
                [[ "$remaining" -gt 0 ]] && echo "  ... and $remaining more"
                ;;
            kics)
                echo "$new_ids" | head -20 | while IFS=: read -r query file line; do
                    [[ -z "$query" ]] && continue
                    echo "  + [$query] $file:$line"
                done
                remaining=$((new_count - 20))
                [[ "$remaining" -gt 0 ]] && echo "  ... and $remaining more"
                ;;
            artifacts)
                echo "$new_ids" | head -20 | while read -r path; do
                    [[ -z "$path" ]] && continue
                    echo "  + $path"
                done
                remaining=$((new_count - 20))
                [[ "$remaining" -gt 0 ]] && echo "  ... and $remaining more"
                ;;
        esac
        echo ""
    fi

    # Show removed findings
    if [[ "$removed_count" -gt 0 ]]; then
        echo "REMOVED FINDINGS:"
        echo "-----------------"

        ids1=$(get_finding_ids "$file1" "$scanner")
        ids2=$(get_finding_ids "$file2" "$scanner")
        removed_ids=$(comm -23 <(echo "$ids1") <(echo "$ids2") 2>/dev/null)

        case "$scanner" in
            semgrep)
                echo "$removed_ids" | head -20 | while IFS=: read -r check_id path line; do
                    [[ -z "$check_id" ]] && continue
                    echo "  - [$check_id] $path:$line"
                done
                remaining=$((removed_count - 20))
                [[ "$remaining" -gt 0 ]] && echo "  ... and $remaining more"
                ;;
            trufflehog)
                echo "$removed_ids" | head -20 | while IFS=: read -r detector file; do
                    [[ -z "$detector" ]] && continue
                    echo "  - [$detector] $file"
                done
                remaining=$((removed_count - 20))
                [[ "$remaining" -gt 0 ]] && echo "  ... and $remaining more"
                ;;
            kics)
                echo "$removed_ids" | head -20 | while IFS=: read -r query file line; do
                    [[ -z "$query" ]] && continue
                    echo "  - [$query] $file:$line"
                done
                remaining=$((removed_count - 20))
                [[ "$remaining" -gt 0 ]] && echo "  ... and $remaining more"
                ;;
            artifacts)
                echo "$removed_ids" | head -20 | while read -r path; do
                    [[ -z "$path" ]] && continue
                    echo "  - $path"
                done
                remaining=$((removed_count - 20))
                [[ "$remaining" -gt 0 ]] && echo "  ... and $remaining more"
                ;;
        esac
        echo ""
    fi
done

# Code changes if requested
if [[ -n "$SHOW_CODE" ]]; then
    commits1="$DIR1/commits.json"
    commits2="$DIR2/commits.json"

    if [[ ! -f "$commits1" || ! -f "$commits2" ]]; then
        echo "Warning: commits.json not found in one or both scans"
        echo "Code diff requires commit tracking."
    else
        echo "========================================"
        echo "Code Changes"
        echo "========================================"
        echo ""

        # Get list of repos from both commits files
        repos=$(jq -r '.repos | keys[]' "$commits1" "$commits2" 2>/dev/null | sort -u)

        changed_repos=0
        for repo in $repos; do
            sha1=$(jq -r --arg r "$repo" '.repos[$r] // empty' "$commits1" 2>/dev/null)
            sha2=$(jq -r --arg r "$repo" '.repos[$r] // empty' "$commits2" 2>/dev/null)

            # Skip if SHAs are the same or missing
            if [[ -z "$sha1" || -z "$sha2" || "$sha1" == "$sha2" ]]; then
                continue
            fi

            changed_repos=$((changed_repos + 1))
            echo "=== $repo ==="
            echo "From: ${sha1:0:8}"
            echo "To:   ${sha2:0:8}"
            echo ""

            repo_dir="$CATALOG_ROOT/repos/$ORG/$repo"
            if [[ -d "$repo_dir/.git" ]]; then
                # Show commit log between SHAs
                commits=$(git -C "$repo_dir" log --oneline "$sha1..$sha2" 2>/dev/null | head -10)
                if [[ -n "$commits" ]]; then
                    echo "Commits:"
                    echo "$commits" | sed 's/^/  /'

                    total_commits=$(git -C "$repo_dir" log --oneline "$sha1..$sha2" 2>/dev/null | wc -l | xargs)
                    if [[ "$total_commits" -gt 10 ]]; then
                        echo "  ... and $((total_commits - 10)) more commits"
                    fi
                else
                    echo "  (no commits found between these SHAs)"
                fi

                # Show diffstat
                echo ""
                echo "Files changed:"
                git -C "$repo_dir" diff --stat "$sha1..$sha2" 2>/dev/null | tail -5 | sed 's/^/  /'
            else
                echo "  (repository not available locally)"
            fi
            echo ""
        done

        if [[ "$changed_repos" -eq 0 ]]; then
            echo "No code changes detected between scans."
            echo ""
        fi
    fi
fi

# Recommendations
if [[ "$TOTAL_NEW_ALL" -gt 0 ]]; then
    echo "----------------------------------------"
    echo "Next steps:"
    echo "  Review new findings: /review-all $ORG"
    echo "  Extract details:     ./scripts/extract-semgrep-findings.sh $ORG summary"
    echo ""
fi
