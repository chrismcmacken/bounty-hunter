#!/usr/bin/env bash
#
# copy-setup.sh - Copy threat hunting setup to a new directory
#
# Usage: ./scripts/copy-setup.sh <destination>
#        ./scripts/copy-setup.sh ~/new-threat-hunting
#        ./scripts/copy-setup.sh /path/to/dest --include-findings
#        ./scripts/copy-setup.sh /path/to/dest --include-catalog-scans
#
# Copies:
#   - scripts/           Custom scripts and libraries
#   - custom-rules/      Semgrep rules (including submodules)
#   - catalog/           Catalog structure (index, platforms, tracked orgs)
#   - .claude/           Claude skills, commands, and settings
#   - docs/              Documentation
#   - .env               Environment file with API tokens
#   - .env.example       Environment template
#   - .gitignore         Git ignore patterns
#   - .gitattributes     Git attributes
#   - .gitmodules        Submodule definitions
#   - README.md          Project readme
#   - templates/         Templates directory
#
# Does NOT copy by default:
#   - repos/             Cloned repositories (large, can be re-cloned)
#   - findings/          Scan results (can be regenerated)
#   - .git/              Git history
#   - .tmp/              Temporary files
#   - catalog/tracked/*/scans/  Historical scan data (use --include-catalog-scans)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $(basename "$0") <destination> [options]

Copy threat hunting setup to a new directory.

Options:
    --include-findings       Also copy findings/ directory
    --include-catalog-scans  Also copy historical scan data in catalog/tracked/*/scans/
    --include-repos          Also copy repos/ directory (warning: can be very large)
    --dry-run                Show what would be copied without copying
    -h, --help               Show this help message

Examples:
    $(basename "$0") ~/new-threat-hunting
    $(basename "$0") /opt/hunting --include-findings
    $(basename "$0") ~/backup --include-catalog-scans --dry-run
EOF
}

# Parse arguments
DEST=""
INCLUDE_FINDINGS=false
INCLUDE_CATALOG_SCANS=false
INCLUDE_REPOS=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --include-findings)
            INCLUDE_FINDINGS=true
            shift
            ;;
        --include-catalog-scans)
            INCLUDE_CATALOG_SCANS=true
            shift
            ;;
        --include-repos)
            INCLUDE_REPOS=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo -e "${RED}Unknown option: $1${NC}" >&2
            usage
            exit 1
            ;;
        *)
            if [[ -z "$DEST" ]]; then
                DEST="$1"
            else
                echo -e "${RED}Too many arguments${NC}" >&2
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "$DEST" ]]; then
    echo -e "${RED}Error: Destination directory required${NC}" >&2
    usage
    exit 1
fi

# Expand ~ and resolve to absolute path
DEST="${DEST/#\~/$HOME}"
DEST="$(cd "$(dirname "$DEST")" 2>/dev/null && pwd)/$(basename "$DEST")" || DEST="$DEST"

echo -e "${BLUE}=== Threat Hunting Setup Copy ===${NC}"
echo -e "Source:      ${SOURCE_DIR}"
echo -e "Destination: ${DEST}"
echo ""

# Check if destination exists
if [[ -e "$DEST" ]]; then
    echo -e "${YELLOW}Warning: Destination already exists${NC}"
    if [[ "$DRY_RUN" == "false" ]]; then
        read -p "Overwrite existing files? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 1
        fi
    fi
fi

# Function to copy with progress
copy_item() {
    local src="$1"
    local desc="$2"
    local exclude="${3:-}"

    if [[ ! -e "$SOURCE_DIR/$src" ]]; then
        echo -e "  ${YELLOW}Skip${NC} $src (not found)"
        return
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${BLUE}Would copy${NC} $src ($desc)"
        return
    fi

    echo -e "  ${GREEN}Copying${NC} $src ($desc)"

    # Create parent directory if needed
    local dest_parent
    dest_parent="$(dirname "$DEST/$src")"
    mkdir -p "$dest_parent"

    if [[ -d "$SOURCE_DIR/$src" ]]; then
        if [[ -n "$exclude" ]]; then
            rsync -a --exclude="$exclude" "$SOURCE_DIR/$src/" "$DEST/$src/"
        else
            rsync -a "$SOURCE_DIR/$src/" "$DEST/$src/"
        fi
    else
        cp -p "$SOURCE_DIR/$src" "$DEST/$src"
    fi
}

# Function to copy catalog with optional scan exclusion
copy_catalog() {
    if [[ ! -d "$SOURCE_DIR/catalog" ]]; then
        echo -e "  ${YELLOW}Skip${NC} catalog (not found)"
        return
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        if [[ "$INCLUDE_CATALOG_SCANS" == "true" ]]; then
            echo -e "  ${BLUE}Would copy${NC} catalog/ (full catalog with scan history)"
        else
            echo -e "  ${BLUE}Would copy${NC} catalog/ (structure only, excluding scan history)"
        fi
        return
    fi

    mkdir -p "$DEST/catalog"

    if [[ "$INCLUDE_CATALOG_SCANS" == "true" ]]; then
        echo -e "  ${GREEN}Copying${NC} catalog/ (full catalog with scan history)"
        rsync -a "$SOURCE_DIR/catalog/" "$DEST/catalog/"
    else
        echo -e "  ${GREEN}Copying${NC} catalog/ (structure only, excluding scan history)"
        # Copy everything except scans directories
        rsync -a --exclude='scans' "$SOURCE_DIR/catalog/" "$DEST/catalog/"

        # Create empty scans directories for tracked orgs
        if [[ -d "$SOURCE_DIR/catalog/tracked" ]]; then
            for org_dir in "$SOURCE_DIR/catalog/tracked"/*/; do
                if [[ -d "$org_dir" ]]; then
                    org_name="$(basename "$org_dir")"
                    mkdir -p "$DEST/catalog/tracked/$org_name/scans"
                fi
            done
        fi
    fi
}

# Create destination
if [[ "$DRY_RUN" == "false" ]]; then
    mkdir -p "$DEST"
fi

echo -e "${BLUE}Core components:${NC}"
copy_item "scripts"        "automation scripts"
copy_item "custom-rules"   "semgrep rules"
copy_item ".claude"        "claude skills, commands, settings"
copy_item "docs"           "documentation"
copy_item "templates"      "templates"

echo ""
echo -e "${BLUE}Configuration files:${NC}"
copy_item ".env"           "API tokens (sensitive)"
copy_item ".env.example"   "environment template"
copy_item ".gitignore"     "git ignore patterns"
copy_item ".gitattributes" "git attributes"
copy_item ".gitmodules"    "submodule definitions"
copy_item "README.md"      "project readme"

echo ""
echo -e "${BLUE}Data directories:${NC}"
copy_catalog

if [[ "$INCLUDE_FINDINGS" == "true" ]]; then
    copy_item "findings" "scan results"
else
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${YELLOW}Skip${NC} findings/ (use --include-findings to copy)"
    else
        echo -e "  ${YELLOW}Skip${NC} findings/ (use --include-findings to copy)"
        mkdir -p "$DEST/findings"
    fi
fi

if [[ "$INCLUDE_REPOS" == "true" ]]; then
    copy_item "repos" "cloned repositories (may be large)"
else
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${YELLOW}Skip${NC} repos/ (use --include-repos to copy)"
    else
        echo -e "  ${YELLOW}Skip${NC} repos/ (use --include-repos to copy)"
        mkdir -p "$DEST/repos"
    fi
fi

echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${BLUE}Dry run complete. No files were copied.${NC}"
else
    # Make scripts executable
    if [[ -d "$DEST/scripts" ]]; then
        find "$DEST/scripts" -name "*.sh" -exec chmod +x {} \;
    fi

    echo -e "${GREEN}Copy complete!${NC}"
    echo ""
    echo -e "Next steps:"
    echo -e "  1. cd $DEST"
    echo -e "  2. Review .env file and update tokens if needed"
    echo -e "  3. Initialize git: git init && git submodule update --init"
    echo -e "  4. Test: ./scripts/catalog-status.sh"
fi
