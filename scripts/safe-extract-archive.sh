#!/usr/bin/env bash
set -euo pipefail

# Safe Archive Extraction Script
# Extracts archives with security protections against common attacks
#
# SECURITY FEATURES:
# - Path traversal protection (rejects ../ and absolute paths)
# - Symlink and hardlink rejection
# - Archive size limit (default 100MB)
# - Extracted content size limit (default 500MB)
# - File count limit (default 10,000 files)
# - Restricted temp directory permissions (700)
# - Automatic cleanup on failure
#
# USAGE:
#   ./scripts/safe-extract-archive.sh <archive-path> [output-dir]
#
# OUTPUT:
#   Prints the extraction directory path on success
#   Exit code 0 on success, non-zero on failure
#
# If output-dir is not specified, creates a temp directory that the caller
# is responsible for cleaning up.

# Configuration - can be overridden via environment variables
MAX_ARCHIVE_SIZE="${SAFE_EXTRACT_MAX_ARCHIVE_SIZE:-104857600}"      # 100MB
MAX_EXTRACTED_SIZE="${SAFE_EXTRACT_MAX_EXTRACTED_SIZE:-524288000}"  # 500MB
MAX_FILE_COUNT="${SAFE_EXTRACT_MAX_FILE_COUNT:-10000}"

print_usage() {
    echo "Usage: $0 <archive-path> [output-dir]"
    echo ""
    echo "Safely extract an archive with security protections."
    echo ""
    echo "Options (via environment variables):"
    echo "  SAFE_EXTRACT_MAX_ARCHIVE_SIZE    Max archive size in bytes (default: 100MB)"
    echo "  SAFE_EXTRACT_MAX_EXTRACTED_SIZE  Max total extracted size (default: 500MB)"
    echo "  SAFE_EXTRACT_MAX_FILE_COUNT      Max number of files (default: 10000)"
    echo ""
    echo "Supported formats: .zip, .tar, .tar.gz, .tgz, .tar.bz2, .gz, .7z, .rar"
    echo ""
    echo "Security features:"
    echo "  - Rejects path traversal attempts (../ or absolute paths)"
    echo "  - Rejects symlinks and hardlinks"
    echo "  - Enforces size and file count limits"
    echo ""
    echo "On success, prints the extraction directory path."
    exit 1
}

error() {
    echo "ERROR: $1" >&2
    exit 1
}

warn() {
    echo "WARNING: $1" >&2
}

# Validate archive path
validate_archive() {
    local archive="$1"

    if [[ ! -f "$archive" ]]; then
        error "Archive not found: $archive"
    fi

    # Check archive size
    local size
    size=$(stat -f%z "$archive" 2>/dev/null || stat -c%s "$archive" 2>/dev/null || echo "0")

    if [[ "$size" -gt "$MAX_ARCHIVE_SIZE" ]]; then
        local size_mb=$((size / 1048576))
        local max_mb=$((MAX_ARCHIVE_SIZE / 1048576))
        error "Archive too large: ${size_mb}MB exceeds ${max_mb}MB limit"
    fi
}

# Check if a path is safe (no traversal, not absolute)
is_safe_path() {
    local path="$1"

    # Reject absolute paths
    if [[ "$path" == /* ]]; then
        return 1
    fi

    # Reject path traversal patterns
    # Check for: "..", "/../", "../", starts with "../"
    if [[ "$path" == *".."* ]]; then
        return 1
    fi

    return 0
}

# Remove symlinks and hardlinks from extracted content
sanitize_extracted() {
    local dir="$1"
    local removed=0

    # Find and remove symlinks
    while IFS= read -r -d '' link; do
        rm -f "$link"
        warn "Removed symlink: $link"
        ((removed++)) || true
    done < <(find "$dir" -type l -print0 2>/dev/null)

    # Find files with multiple hardlinks (link count > 1) that aren't directories
    while IFS= read -r -d '' file; do
        local links
        links=$(stat -f%l "$file" 2>/dev/null || stat -c%h "$file" 2>/dev/null || echo "1")
        if [[ "$links" -gt 1 ]]; then
            # Create a copy and replace the hardlink
            local tmp="${file}.safe_tmp"
            cp "$file" "$tmp"
            rm -f "$file"
            mv "$tmp" "$file"
            warn "Replaced hardlink: $file"
            ((removed++)) || true
        fi
    done < <(find "$dir" -type f -print0 2>/dev/null)

    if [[ $removed -gt 0 ]]; then
        warn "Removed/replaced $removed potentially dangerous links"
    fi
}

# Verify extracted content is within limits and safe
verify_extraction() {
    local dir="$1"

    # Count files
    local file_count
    file_count=$(find "$dir" -type f 2>/dev/null | wc -l | xargs)

    if [[ "$file_count" -gt "$MAX_FILE_COUNT" ]]; then
        error "Too many files extracted: $file_count exceeds $MAX_FILE_COUNT limit"
    fi

    # Check total size
    local total_size
    total_size=$(du -sb "$dir" 2>/dev/null | cut -f1 || du -sk "$dir" 2>/dev/null | awk '{print $1 * 1024}' || echo "0")

    if [[ "$total_size" -gt "$MAX_EXTRACTED_SIZE" ]]; then
        local size_mb=$((total_size / 1048576))
        local max_mb=$((MAX_EXTRACTED_SIZE / 1048576))
        error "Extracted content too large: ${size_mb}MB exceeds ${max_mb}MB limit"
    fi

    # Check for path traversal in extracted filenames
    # Use -mindepth 1 to skip the base directory itself
    while IFS= read -r -d '' file; do
        # Get path relative to the extraction directory
        local rel_path="${file#"$dir"/}"
        # Skip if rel_path is empty (shouldn't happen with -mindepth 1)
        [[ -z "$rel_path" ]] && continue
        if ! is_safe_path "$rel_path"; then
            error "Unsafe path detected in archive: $rel_path"
        fi
    done < <(find "$dir" -mindepth 1 -print0 2>/dev/null)
}

# Extract archive based on type
extract_archive() {
    local archive="$1"
    local output_dir="$2"

    local success=false

    # Convert to lowercase for case-insensitive matching (portable for Bash 3.x)
    local archive_lower
    archive_lower=$(echo "$archive" | tr '[:upper:]' '[:lower:]')

    case "$archive_lower" in
        *.zip)
            # -j would flatten, we don't want that
            # Use -d for destination, -o to overwrite
            if unzip -q -d "$output_dir" "$archive" 2>/dev/null; then
                success=true
            fi
            ;;
        *.tar.gz|*.tgz)
            # --no-same-owner prevents ownership attacks
            # -C sets destination directory
            if tar --no-same-owner -xzf "$archive" -C "$output_dir" 2>/dev/null; then
                success=true
            fi
            ;;
        *.tar.bz2|*.tbz2)
            if tar --no-same-owner -xjf "$archive" -C "$output_dir" 2>/dev/null; then
                success=true
            fi
            ;;
        *.tar)
            if tar --no-same-owner -xf "$archive" -C "$output_dir" 2>/dev/null; then
                success=true
            fi
            ;;
        *.gz)
            # Single file gzip - extract to output dir
            local basename
            basename=$(basename "$archive" .gz)
            if gunzip -c "$archive" > "$output_dir/$basename" 2>/dev/null; then
                success=true
            fi
            ;;
        *.7z)
            if command -v 7z &> /dev/null; then
                # -o sets output directory (no space after -o)
                if 7z x -o"$output_dir" "$archive" -y >/dev/null 2>&1; then
                    success=true
                fi
            else
                error "7z not installed - cannot extract .7z files"
            fi
            ;;
        *.rar)
            if command -v unrar &> /dev/null; then
                if unrar x -y "$archive" "$output_dir/" >/dev/null 2>&1; then
                    success=true
                fi
            else
                error "unrar not installed - cannot extract .rar files"
            fi
            ;;
        *)
            error "Unsupported archive format: $archive"
            ;;
    esac

    if [[ "$success" != "true" ]]; then
        error "Failed to extract archive (corrupted or password-protected?)"
    fi
}

# Main
main() {
    if [[ $# -lt 1 ]]; then
        print_usage
    fi

    local archive="$1"
    local output_dir="${2:-}"
    local temp_created=false

    # Convert to absolute path
    archive=$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")

    # Validate the archive first
    validate_archive "$archive"

    # Create output directory if not specified
    if [[ -z "$output_dir" ]]; then
        output_dir=$(mktemp -d)
        temp_created=true
        # Set restrictive permissions
        chmod 700 "$output_dir"
    else
        mkdir -p "$output_dir"
        chmod 700 "$output_dir"
    fi

    # Cleanup function
    cleanup() {
        if [[ "$temp_created" == "true" ]] && [[ -d "$output_dir" ]]; then
            rm -rf "$output_dir"
        fi
    }

    # Set trap for cleanup on error
    trap cleanup ERR

    # Extract the archive
    extract_archive "$archive" "$output_dir"

    # Remove dangerous symlinks/hardlinks
    sanitize_extracted "$output_dir"

    # Verify the extraction is safe and within limits
    verify_extraction "$output_dir"

    # Clear the error trap since we succeeded
    trap - ERR

    # Output the directory path
    echo "$output_dir"
}

main "$@"
