#!/usr/bin/env bash
# Migrate uncompressed JSON scan results to gzipped format
#
# This script:
# 1. Finds all uncompressed .json scan files (semgrep, trufflehog, kics, artifacts)
# 2. Compresses them to .json.gz
# 3. Removes the original .json files from git and disk
# 4. Optionally cleans git history (requires BFG or git-filter-repo)
#
# Usage:
#   ./scripts/migrate-to-gzip.sh              # Dry run (show what would change)
#   ./scripts/migrate-to-gzip.sh --execute    # Actually compress and remove files
#   ./scripts/migrate-to-gzip.sh --clean-git  # Also clean git history (requires BFG)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DRY_RUN=true
CLEAN_GIT=false

for arg in "$@"; do
    case "$arg" in
        --execute)
            DRY_RUN=false
            ;;
        --clean-git)
            CLEAN_GIT=true
            ;;
        -h|--help)
            echo "Usage: $0 [--execute] [--clean-git]"
            echo ""
            echo "Options:"
            echo "  --execute     Actually compress files (default: dry run)"
            echo "  --clean-git   Also clean git history (requires BFG Repo-Cleaner)"
            echo ""
            echo "This script finds uncompressed JSON scan files and converts them to .json.gz"
            exit 0
            ;;
    esac
done

cd "$ROOT_DIR"

echo "========================================"
echo "JSON to Gzip Migration"
echo "========================================"
echo "Mode: $( [[ "$DRY_RUN" == true ]] && echo "DRY RUN (use --execute to apply)" || echo "EXECUTE" )"
echo ""

# Find scan result JSON files that should be gzipped
# Patterns: semgrep.json, trufflehog.json, kics.json, artifacts.json in catalog scans
# Also: *.json in findings/*/semgrep-results, trufflehog-results, etc.

SCAN_PATTERNS=(
    "catalog/tracked/*/scans/*/semgrep.json"
    "catalog/tracked/*/scans/*/trufflehog.json"
    "catalog/tracked/*/scans/*/kics.json"
    "catalog/tracked/*/scans/*/artifacts.json"
    "findings/*/semgrep-results/*.json"
    "findings/*/trufflehog-results/*.json"
    "findings/*/kics-results/*.json"
    "findings/*/artifact-results/*.json"
    "findings/*/inventory/*-sbom.json"
)

found_files=()
total_size=0

echo "Scanning for uncompressed JSON files..."
echo ""

for pattern in "${SCAN_PATTERNS[@]}"; do
    while IFS= read -r -d '' file; do
        # Skip if already has .gz companion
        if [[ -f "${file}.gz" ]]; then
            continue
        fi

        size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
        size_mb=$((size / 1024 / 1024))

        found_files+=("$file")
        total_size=$((total_size + size))

        echo "  $file (${size_mb}MB)"
    done < <(find . -path "./$pattern" -type f -print0 2>/dev/null || true)
done

total_mb=$((total_size / 1024 / 1024))
echo ""
echo "Found ${#found_files[@]} uncompressed files (${total_mb}MB total)"
echo ""

if [[ ${#found_files[@]} -eq 0 ]]; then
    echo "No uncompressed JSON files found. All scan results are already gzipped."
    exit 0
fi

# Process files
if [[ "$DRY_RUN" == true ]]; then
    echo "Would compress and remove:"
    for file in "${found_files[@]}"; do
        echo "  $file -> ${file}.gz"
    done
    echo ""
    echo "Run with --execute to apply changes."
else
    echo "Compressing files..."
    compressed=0
    removed=0

    for file in "${found_files[@]}"; do
        echo "  Compressing: $file"

        # Compress
        gzip -c "$file" > "${file}.gz"

        # Remove from git (if tracked)
        if git ls-files --error-unmatch "$file" &>/dev/null; then
            git rm --cached "$file" 2>/dev/null || true
            removed=$((removed + 1))
        fi

        # Remove from disk
        rm -f "$file"

        compressed=$((compressed + 1))
    done

    echo ""
    echo "Compressed $compressed files"
    echo "Removed $removed files from git index"
    echo ""

    # Stage new gzipped files
    echo "Staging gzipped files..."
    for file in "${found_files[@]}"; do
        git add "${file}.gz" 2>/dev/null || true
    done

    echo ""
    echo "Changes staged. Review with: git status"
    echo ""
    echo "To commit:"
    echo "  git commit -m 'Migrate scan results to gzipped format'"
fi

# Git history cleanup
if [[ "$CLEAN_GIT" == true ]]; then
    echo ""
    echo "========================================"
    echo "Git History Cleanup"
    echo "========================================"

    if ! command -v bfg &>/dev/null; then
        echo "BFG Repo-Cleaner not found."
        echo ""
        echo "Install: brew install bfg"
        echo ""
        echo "Alternative: Use git-filter-repo"
        echo "  pip install git-filter-repo"
        echo "  git filter-repo --path-glob '*.json' --invert-paths --path catalog/index.json --path catalog/platforms/ --path catalog/tracked/*/meta.json"
        exit 1
    fi

    if [[ "$DRY_RUN" == true ]]; then
        echo "Would clean git history of large JSON files."
        echo ""
        echo "Run with --execute --clean-git to apply."
    else
        echo "Creating backup..."
        git clone --mirror . "../$(basename "$ROOT_DIR")-backup.git"

        echo ""
        echo "Running BFG to remove large blobs..."
        # Remove blobs larger than 50MB
        bfg --strip-blobs-bigger-than 50M .

        echo ""
        echo "Cleaning up..."
        git reflog expire --expire=now --all
        git gc --prune=now --aggressive

        echo ""
        echo "History cleaned. You will need to force push:"
        echo "  git push --force"
        echo ""
        echo "Backup saved to: ../$(basename "$ROOT_DIR")-backup.git"
    fi
fi

echo ""
echo "========================================"
echo "Next Steps"
echo "========================================"
echo ""
if [[ "$DRY_RUN" == true ]]; then
    echo "1. Run with --execute to compress files"
    echo "2. Commit the changes"
    echo "3. Run with --execute --clean-git to remove from history (optional)"
    echo "4. Force push to update remote"
else
    echo "1. Review staged changes: git status"
    echo "2. Commit: git commit -m 'Migrate scan results to gzipped format'"
    if [[ "$CLEAN_GIT" == false ]]; then
        echo "3. To remove large files from history:"
        echo "   ./scripts/migrate-to-gzip.sh --execute --clean-git"
    fi
    echo "4. Force push: git push --force"
fi
