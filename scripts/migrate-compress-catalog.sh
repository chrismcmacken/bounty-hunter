#!/usr/bin/env bash
# Migrate existing catalog scan results to gzip compression
#
# This script compresses existing .json files to .json.gz in the catalog
# and removes the original uncompressed files after verification.
#
# Usage: ./scripts/migrate-compress-catalog.sh [--dry-run]

set -euo pipefail

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="1"
    echo "DRY RUN MODE - no changes will be made"
    echo ""
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CATALOG_DIR="$SCRIPT_DIR/../catalog/tracked"

if [[ ! -d "$CATALOG_DIR" ]]; then
    echo "No catalog directory found at: $CATALOG_DIR"
    exit 0
fi

echo "Migrating catalog scan files to gzip compression..."
echo ""

total_before=0
total_after=0
files_migrated=0
files_skipped=0

# Find all scan result JSON files (excluding commits.json which stays uncompressed)
while IFS= read -r -d '' file; do
    filename=$(basename "$file")

    # Skip commits.json - it's small and needs to stay uncompressed
    if [[ "$filename" == "commits.json" ]]; then
        continue
    fi

    # Skip if already has a .gz version
    if [[ -f "${file}.gz" ]]; then
        echo "SKIP: $file (already has .gz version)"
        files_skipped=$((files_skipped + 1))
        continue
    fi

    # Get file sizes
    orig_size=$(wc -c < "$file" | tr -d ' ')

    if [[ -z "$DRY_RUN" ]]; then
        # Compress the file
        gzip -c "$file" > "${file}.gz"
        gz_size=$(wc -c < "${file}.gz" | tr -d ' ')

        # Verify the compressed file is readable
        if gzip -t "${file}.gz" 2>/dev/null; then
            # Remove the original
            rm "$file"
            echo "OK:   $file"
            echo "      $(echo "scale=2; $orig_size/1024/1024" | bc) MB -> $(echo "scale=2; $gz_size/1024/1024" | bc) MB"
            total_before=$((total_before + orig_size))
            total_after=$((total_after + gz_size))
            files_migrated=$((files_migrated + 1))
        else
            # Compression failed, remove the bad gz file
            rm "${file}.gz"
            echo "ERR:  $file (compression verification failed)"
        fi
    else
        # Dry run - estimate compression
        gz_size=$(gzip -c "$file" | wc -c | tr -d ' ')
        echo "WOULD: $file"
        echo "       $(echo "scale=2; $orig_size/1024/1024" | bc) MB -> $(echo "scale=2; $gz_size/1024/1024" | bc) MB"
        total_before=$((total_before + orig_size))
        total_after=$((total_after + gz_size))
        files_migrated=$((files_migrated + 1))
    fi

done < <(find "$CATALOG_DIR" -path "*/scans/*" -name "*.json" -type f -print0 2>/dev/null)

echo ""
echo "========================================"
echo "Migration Summary"
echo "========================================"
echo "Files migrated:  $files_migrated"
echo "Files skipped:   $files_skipped"
echo ""
if [[ "$files_migrated" -gt 0 ]]; then
    echo "Total before:    $(echo "scale=2; $total_before/1024/1024" | bc) MB"
    echo "Total after:     $(echo "scale=2; $total_after/1024/1024" | bc) MB"
    savings=$((total_before - total_after))
    echo "Space saved:     $(echo "scale=2; $savings/1024/1024" | bc) MB"
    if [[ "$total_before" -gt 0 ]]; then
        pct=$(echo "scale=1; 100 - ($total_after * 100 / $total_before)" | bc)
        echo "Reduction:       ${pct}%"
    fi
fi

if [[ -n "$DRY_RUN" ]]; then
    echo ""
    echo "This was a dry run. Run without --dry-run to apply changes."
fi
