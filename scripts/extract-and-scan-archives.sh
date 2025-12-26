#!/usr/bin/env bash
set -euo pipefail

# Extract archives and scan with Trufflehog
# Archives are extracted to a temporary directory and cleaned up after scanning
#
# SECURITY: Uses safe-extract-archive.sh for secure extraction with:
# - Path traversal protection
# - Symlink/hardlink rejection
# - Size and file count limits
#
# See safe-extract-archive.sh for configuration options.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_EXTRACT="$SCRIPT_DIR/safe-extract-archive.sh"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <organization> [repo-name]"
    echo ""
    echo "Extract archives found by scan-artifacts.sh and scan with Trufflehog."
    echo "Results are appended to trufflehog-results/<repo>-archives.json"
    exit 1
fi

ORG="$1"
REPO="${2:-}"
ARTIFACT_DIR="scans/$ORG/artifact-results"
TRUFFLEHOG_DIR="scans/$ORG/trufflehog-results"

if [[ ! -d "$ARTIFACT_DIR" ]]; then
    echo "Error: No artifact results found. Run scan-artifacts.sh first."
    exit 1
fi

if ! command -v trufflehog &> /dev/null; then
    echo "Error: trufflehog is required but not installed."
    exit 1
fi

if [[ ! -x "$SAFE_EXTRACT" ]]; then
    echo "Error: safe-extract-archive.sh not found or not executable."
    echo "Expected at: $SAFE_EXTRACT"
    exit 1
fi

# Create temp directory for extraction
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "Archives will be extracted to: $TEMP_DIR"
echo "This directory will be deleted after scanning."
echo ""

extract_and_scan() {
    local archive_path="$1"
    local repo_name="$2"
    local rel_path="$3"

    local archive_name=$(basename "$archive_path")
    local extract_dir="$TEMP_DIR/$repo_name/$archive_name"
    mkdir -p "$extract_dir"

    echo "  Extracting: $rel_path"

    # Use the safe extraction script
    local safe_output
    if ! safe_output=$("$SAFE_EXTRACT" "$archive_path" "$extract_dir" 2>&1); then
        echo "    SKIPPED: $safe_output"
        rm -rf "$extract_dir"
        return
    fi

    # Count extracted files
    local file_count=$(find "$extract_dir" -type f | wc -l | xargs)
    echo "    Extracted $file_count files (safe extraction)"

    # Scan with Trufflehog
    echo "    Scanning with Trufflehog..."
    local output_file="$TRUFFLEHOG_DIR/${repo_name}-archives.json"

    local findings
    findings=$(trufflehog filesystem "$extract_dir" --json 2>/dev/null || true)

    if [[ -n "$findings" ]]; then
        local finding_count=$(echo "$findings" | wc -l | xargs)
        echo "    FOUND: $finding_count potential secrets!"

        # Append to results with source archive annotation
        echo "$findings" | while read -r line; do
            # Add archive source to each finding
            echo "$line" | jq --arg archive "$rel_path" '. + {SourceArchive: $archive}' >> "$output_file"
        done
    else
        echo "    No secrets found"
    fi

    # Clean up this extraction
    rm -rf "$extract_dir"
}

process_repo() {
    local json_file="$1"
    local repo_name=$(jq -r '.repo' "$json_file")
    local scanned_from=$(jq -r '.scanned_from // empty' "$json_file")

    # Use scanned_from if available, otherwise fall back to relative path
    local repo_path
    if [[ -n "$scanned_from" ]]; then
        repo_path="$scanned_from"
    else
        repo_path="$ORG/$repo_name"
    fi

    local archive_count=$(jq '.archives | length' "$json_file")
    if [[ "$archive_count" == "0" ]]; then
        return
    fi

    echo ""
    echo "=== $repo_name ($archive_count archives) ==="
    if [[ -n "$scanned_from" ]]; then
        echo "  Path: $scanned_from"
    fi

    # Process each archive
    jq -r '.archives[].path' "$json_file" | while read -r rel_path; do
        local full_path="$repo_path/$rel_path"
        if [[ -f "$full_path" ]]; then
            extract_and_scan "$full_path" "$repo_name" "$rel_path"
        else
            echo "  MISSING: $rel_path (repo may need to be re-cloned)"
        fi
    done
}

# Ensure trufflehog results dir exists
mkdir -p "$TRUFFLEHOG_DIR"

# Process files
if [[ -n "$REPO" ]]; then
    FILE="$ARTIFACT_DIR/$REPO.json"
    if [[ ! -f "$FILE" ]]; then
        echo "No artifact findings for repo: $REPO"
        exit 0
    fi
    process_repo "$FILE"
else
    for file in "$ARTIFACT_DIR"/*.json; do
        [[ -f "$file" ]] || continue
        process_repo "$file"
    done
fi

echo ""
echo "========================================"
echo "Archive scanning complete"
echo ""
echo "Results saved to: $TRUFFLEHOG_DIR/*-archives.json"
echo "Review with: ./scripts/extract-trufflehog-findings.sh $ORG"
echo "========================================"
