#!/usr/bin/env bash
# Unified bug bounty hunting command
#
# Combines: track -> clone -> scan in a single automated workflow
#
# Usage: ./scripts/hunt.sh <org> <platform> [options]
#
# Examples:
#   ./scripts/hunt.sh acme-corp hackerone
#   ./scripts/hunt.sh wise bugcrowd --github-org transferwise
#   ./scripts/hunt.sh acme-corp hackerone --skip-kics

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

usage() {
    cat << EOF
Usage: $0 <program-name> <platform> [options]
       $0 <program-name> --archive [--force]
       $0 <program-name> --unarchive

Unified bug bounty hunting: track, clone, and scan a target in one command.

Arguments:
    program-name    Program/target name (used as catalog key)
    platform        Bug bounty platform (hackerone, bugcrowd, yeswehack, intigriti, other)

Lifecycle management:
    --archive             Archive org: delete repos to save space, keep scan history
    --unarchive           Unarchive org: re-clone repos and restore active status
    --force, -f           Skip confirmation prompts (for --archive)

Options:
    --github-org <org>    GitHub org name if different from program name
                          Can be comma-separated for multiple orgs (e.g., "org1,org2")
    --repos <list>        Clone only specific repos (comma-separated)
                          Use when only certain repos are in scope
    --program-url <url>   URL to the bug bounty program page
    --skip-clone          Skip cloning (repos already exist)
    --skip-scan           Skip scanning (just track and clone)
    --include-archived    Include archived repos (secrets-only scanning)
    --no-commit           Don't prompt for git commit at end
    -h, --help            Show this help message

Scan options (passed to catalog-scan.sh):
    --semgrep             Run semgrep only
    --secrets             Run trufflehog only
    --artifacts           Run artifacts only
    --kics                Run KICS only
    --inventory           Run inventory only (scc + syft)
    --skip-semgrep        Skip semgrep scan
    --skip-secrets        Skip trufflehog scan
    --skip-artifacts      Skip artifact scan
    --skip-kics           Skip KICS scan
    --skip-inventory      Skip inventory scan (scc + syft)

Examples:
    $0 acme-corp hackerone                          # Full workflow
    $0 wise bugcrowd --github-org transferwise      # Different GitHub org
    $0 acme-corp hackerone --repos "api,web-app"    # Clone only in-scope repos
    $0 acme-corp hackerone --skip-kics              # Skip KICS scanner
    $0 acme-corp hackerone --skip-clone             # Re-scan existing repos
    $0 multi-org other --github-org "org1,org2"     # Multiple GitHub orgs
    $0 acme-corp --archive                          # Archive (delete repos, keep scans)
    $0 acme-corp --unarchive                        # Unarchive (re-clone repos)
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

# Check for archive/unarchive mode first (before requiring platform)
MODE=""
FORCE=""
for arg in "$@"; do
    case "$arg" in
        --archive) MODE="archive" ;;
        --unarchive) MODE="unarchive" ;;
        --force|-f) FORCE="1" ;;
    esac
done

# For archive/unarchive mode, handle separately
if [[ "$MODE" == "archive" || "$MODE" == "unarchive" ]]; then
    # Validate org name
    if ! validate_org_name "$ORG"; then
        exit 1
    fi

    # Ensure org is tracked
    if ! is_org_tracked "$ORG"; then
        echo "Error: '$ORG' is not tracked"
        echo ""
        echo "To track an organization first:"
        echo "  ./scripts/hunt.sh $ORG <platform>"
        exit 1
    fi

    if [[ "$MODE" == "archive" ]]; then
        # =============================================================================
        # Archive Mode: Delete repos, keep scan history
        # =============================================================================
        current_status=$(get_org_status "$ORG")
        if [[ "$current_status" == "archived" ]]; then
            echo "Error: '$ORG' is already archived"
            echo ""
            echo "To unarchive and re-clone:"
            echo "  ./scripts/hunt.sh $ORG --unarchive"
            exit 1
        fi

        REPOS_DIR="$(get_org_repos_dir "$ORG")"
        SCANS_DIR="$(get_org_scans_dir "$ORG")"
        FINDINGS_DIR="$CATALOG_ROOT/findings/$ORG"

        echo ""
        echo "========================================"
        echo "Archiving: $ORG"
        echo "========================================"
        echo ""

        # Show what will be deleted
        if [[ -d "$REPOS_DIR" ]]; then
            repo_count=$(count_org_repos "$ORG")
            repo_size=$(get_repos_size "$ORG")
            echo "Repository data to delete:"
            echo "  Path:  $REPOS_DIR"
            echo "  Size:  $repo_size"
            echo "  Repos: $repo_count"
        else
            echo "Repository data: (none - repos not cloned)"
        fi
        echo ""

        # Show what will be preserved
        scan_count=$(count_org_scans "$ORG")
        echo "Scan data preserved:"
        echo "  Path:  $SCANS_DIR"
        echo "  Scans: $scan_count"
        if [[ -d "$FINDINGS_DIR" ]]; then
            findings_count=$(find "$FINDINGS_DIR" -type f -name "*.json" 2>/dev/null | wc -l | xargs)
            echo "  Path:  $FINDINGS_DIR"
            echo "  Files: $findings_count"
        fi
        echo ""

        # Confirm unless --force
        if [[ -z "$FORCE" ]]; then
            read -rp "Continue? [y/N] " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                echo "Aborted."
                exit 0
            fi
            echo ""
        fi

        # Delete repos directory
        if [[ -d "$REPOS_DIR" ]]; then
            echo -n "Deleting $REPOS_DIR... "
            rm -rf "$REPOS_DIR"
            echo "done"
        fi

        # Update status
        echo -n "Updating catalog... "
        set_org_status "$ORG" "archived"
        echo "done"

        echo ""
        echo "========================================"
        echo "Archive Complete: $ORG"
        echo "========================================"
        echo ""
        echo "Status: archived"
        if [[ -n "${repo_count:-}" ]]; then
            echo "Repos deleted: $repo_count (${repo_size} freed)"
        fi
        echo "Scan history: preserved ($scan_count scans)"
        echo ""
        echo "To unarchive and re-clone:"
        echo "  ./scripts/hunt.sh $ORG --unarchive"
        echo ""
        exit 0

    else
        # =============================================================================
        # Unarchive Mode: Re-clone repos, restore active status
        # =============================================================================
        current_status=$(get_org_status "$ORG")
        if [[ "$current_status" != "archived" ]]; then
            echo "Error: '$ORG' is not archived (status: $current_status)"
            echo ""
            echo "To archive:"
            echo "  ./scripts/hunt.sh $ORG --archive"
            exit 1
        fi

        REPOS_DIR="$(get_org_repos_dir "$ORG")"

        echo ""
        echo "========================================"
        echo "Unarchiving: $ORG"
        echo "========================================"
        echo ""

        # Check if repos already exist
        if [[ -d "$REPOS_DIR" ]]; then
            repo_count=$(count_org_repos "$ORG")
            if [[ "$repo_count" -gt 0 ]]; then
                echo "Warning: Repos directory already exists with $repo_count repos"
                echo "  Path: $REPOS_DIR"
                echo ""
            fi
        fi

        # Clone repos
        echo "Cloning repositories..."
        "$SCRIPT_DIR/clone-org-repos.sh" "$ORG"
        echo ""

        # Update status
        echo -n "Updating catalog... "
        set_org_status "$ORG" "active"
        echo "done"

        # Get platform for next steps hint
        platform=$(get_org_field "$ORG" "platform")
        repo_count=$(count_org_repos "$ORG")

        echo ""
        echo "========================================"
        echo "Unarchive Complete: $ORG"
        echo "========================================"
        echo ""
        echo "Status: active"
        echo "Repos cloned: $repo_count"
        echo ""
        echo "Next steps:"
        echo "  ./scripts/hunt.sh $ORG $platform    # Re-scan for new findings"
        echo ""
        exit 0
    fi
fi

# Normal hunt mode - require platform
if [[ $# -lt 1 ]]; then
    echo "Error: Platform is required for hunt mode"
    usage
fi

PLATFORM="$1"
shift

# Parse options
GITHUB_ORGS=()
SPECIFIC_REPOS=()
PROGRAM_URL=""
SKIP_CLONE=""
SKIP_SCAN=""
INCLUDE_ARCHIVED=""
NO_COMMIT=""
SCAN_OPTS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --github-org)
            # Support comma-separated values
            IFS=',' read -ra ORGS <<< "$2"
            for org in "${ORGS[@]}"; do
                org=$(echo "$org" | xargs)  # Trim whitespace
                [[ -n "$org" ]] && GITHUB_ORGS+=("$org")
            done
            shift 2
            ;;
        --repos)
            # Support comma-separated repo names
            IFS=',' read -ra REPOS <<< "$2"
            for repo in "${REPOS[@]}"; do
                repo=$(echo "$repo" | xargs)  # Trim whitespace
                [[ -n "$repo" ]] && SPECIFIC_REPOS+=("$repo")
            done
            shift 2
            ;;
        --program-url)
            PROGRAM_URL="$2"
            shift 2
            ;;
        --skip-clone)
            SKIP_CLONE="1"
            shift
            ;;
        --skip-scan)
            SKIP_SCAN="1"
            shift
            ;;
        --include-archived)
            INCLUDE_ARCHIVED="1"
            shift
            ;;
        --no-commit)
            NO_COMMIT="1"
            SCAN_OPTS+=("--no-commit")
            shift
            ;;
        --semgrep|--secrets|--artifacts|--kics|--inventory)
            SCAN_OPTS+=("$1")
            shift
            ;;
        --skip-semgrep|--skip-secrets|--skip-artifacts|--skip-kics|--skip-inventory)
            SCAN_OPTS+=("$1")
            shift
            ;;
        --archive|--unarchive|--force|-f)
            # These should have been handled above, skip
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

# Validate platform
VALID_PLATFORMS="hackerone bugcrowd yeswehack intigriti other"
if [[ ! " $VALID_PLATFORMS " =~ " $PLATFORM " ]]; then
    echo "Error: Invalid platform '$PLATFORM'"
    echo "Valid platforms: $VALID_PLATFORMS"
    exit 1
fi

# Validate org name
if ! validate_org_name "$ORG"; then
    exit 1
fi

echo ""
echo "========================================"
echo "Hunt: $ORG"
echo "========================================"
echo "Platform:     $PLATFORM"
if [[ ${#GITHUB_ORGS[@]} -gt 0 ]]; then
    echo "GitHub Orgs:  ${GITHUB_ORGS[*]}"
fi
if [[ -n "${SPECIFIC_REPOS[*]:-}" ]]; then
    echo "Repos:        ${SPECIFIC_REPOS[*]} (${#SPECIFIC_REPOS[@]} in scope)"
fi
echo "========================================"
echo ""

# =============================================================================
# Step 1: Track (if not already tracked)
# =============================================================================

ALREADY_TRACKED=""
if is_org_tracked "$ORG"; then
    ALREADY_TRACKED="1"
    echo "[1/3] Track: Already tracked, skipping"
else
    echo "[1/3] Track: Adding $ORG to catalog..."

    # Build track command args
    TRACK_ARGS=("$ORG" "$PLATFORM")
    if [[ ${#GITHUB_ORGS[@]} -gt 0 ]]; then
        for gh_org in "${GITHUB_ORGS[@]}"; do
            TRACK_ARGS+=("--github-org" "$gh_org")
        done
    fi
    [[ -n "$PROGRAM_URL" ]] && TRACK_ARGS+=("--program-url" "$PROGRAM_URL")

    "$SCRIPT_DIR/catalog-track.sh" "${TRACK_ARGS[@]}"
    echo ""
fi

# =============================================================================
# Step 2: Clone
# =============================================================================

REPOS_DIR="$CATALOG_ROOT/repos/$ORG"

if [[ -n "$SKIP_CLONE" ]]; then
    echo "[2/3] Clone: Skipping (--skip-clone)"
    if [[ ! -d "$REPOS_DIR" ]]; then
        echo "Warning: Repos directory does not exist at $REPOS_DIR"
    fi
elif [[ -d "$REPOS_DIR" && -n "$ALREADY_TRACKED" && -z "${SPECIFIC_REPOS[*]:-}" ]]; then
    # Repos exist, org was already tracked, and no specific repos requested - fetch updates
    REPO_COUNT=$(find "$REPOS_DIR" -maxdepth 1 -mindepth 1 -type d ! -name ".*" 2>/dev/null | wc -l | xargs)
    if [[ "$REPO_COUNT" -gt 0 ]]; then
        echo "[2/3] Clone: Repos exist ($REPO_COUNT repos), fetching updates..."
        for repo in "$REPOS_DIR"/*/; do
            [[ -d "$repo/.git" ]] || continue
            name=$(basename "$repo")
            echo "  [$name] Fetching..."
            git -C "$repo" fetch --all 2>/dev/null || echo "  [$name] Fetch failed"
        done
        echo ""
    else
        echo "[2/3] Clone: Cloning repositories..."
        CLONE_ARGS=("$ORG")
        [[ -n "$INCLUDE_ARCHIVED" ]] && CLONE_ARGS+=("--include-archived")
        "$SCRIPT_DIR/clone-org-repos.sh" "${CLONE_ARGS[@]}"
        echo ""
    fi
else
    # Clone repos (either fresh clone or specific repos requested)
    if [[ -n "${SPECIFIC_REPOS[*]:-}" ]]; then
        echo "[2/3] Clone: Cloning ${#SPECIFIC_REPOS[@]} in-scope repositories..."
    else
        echo "[2/3] Clone: Cloning repositories..."
    fi
    CLONE_ARGS=("$ORG")
    [[ -n "$INCLUDE_ARCHIVED" ]] && CLONE_ARGS+=("--include-archived")
    # Add specific repos as positional arguments (clone-org-repos.sh expects them at the end)
    for repo in ${SPECIFIC_REPOS[@]+"${SPECIFIC_REPOS[@]}"}; do
        CLONE_ARGS+=("$repo")
    done
    "$SCRIPT_DIR/clone-org-repos.sh" "${CLONE_ARGS[@]}"
    echo ""
fi

# =============================================================================
# Step 3: Scan
# =============================================================================

if [[ -n "$SKIP_SCAN" ]]; then
    echo "[3/3] Scan: Skipping (--skip-scan)"
else
    echo "[3/3] Scan: Running security scans..."
    echo ""

    # Add --no-pull since we just cloned/fetched
    SCAN_OPTS+=("--no-pull")

    "$SCRIPT_DIR/catalog-scan.sh" "$ORG" ${SCAN_OPTS[@]+"${SCAN_OPTS[@]}"}
fi

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "========================================"
echo "Hunt Complete: $ORG"
echo "========================================"
echo ""
echo "Catalog:   catalog/tracked/$ORG/"
echo "Repos:     repos/$ORG/"
echo "Findings:  findings/$ORG/"
echo ""
echo "Next steps:"
echo "  Review:   /review-all $ORG"
echo "  Status:   ./scripts/catalog-status.sh"
echo "  Diff:     ./scripts/catalog-diff.sh $ORG"
echo ""
