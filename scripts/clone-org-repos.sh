#!/usr/bin/env bash
set -euo pipefail

show_help() {
    echo "Usage: $0 [--standalone] <organization> [options] [repo1 repo2 ...]"
    echo "Clone repositories from a GitHub organization."
    echo ""
    echo "By default, clones to repos/<org>/ for catalog integration."
    echo ""
    echo "Options:"
    echo "  --standalone            Clone to ./<org>/ instead of repos/<org>/"
    echo "  --include-archived      Also clone archived repositories (secrets-only scanning)"
    echo "  -f, --filter <pattern>  Filter repos by glob pattern (e.g., '*-sdk', 'api-*')"
    echo "  -j, --jobs <n>          Number of parallel clone jobs (default: 4, requires GNU parallel)"
    echo "  --serial                Force serial cloning (disable parallel)"
    echo ""
    echo "Examples:"
    echo "  $0 MetaMask                           # Clone to repos/MetaMask/ (default)"
    echo "  $0 MetaMask --standalone              # Clone to ./MetaMask/"
    echo "  $0 MetaMask --include-archived        # Include archived repos"
    echo "  $0 MetaMask -f '*-sdk'                # Clone repos matching *-sdk"
    echo "  $0 MetaMask -f 'snaps-*'              # Clone repos starting with snaps-"
    echo "  $0 MetaMask -j 8                      # Clone with 8 parallel jobs"
    echo "  $0 MetaMask --serial                  # Force serial cloning"
    echo "  $0 MetaMask repo1 repo2               # Clone specific repos by name"
    exit 0
}

if [[ $# -lt 1 ]]; then
    show_help
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
fi

# Check for --standalone flag before org name
STANDALONE_MODE=""
if [[ "$1" == "--standalone" ]]; then
    STANDALONE_MODE="1"
    shift
fi

if [[ $# -lt 1 ]]; then
    echo "Error: Organization name required"
    show_help
fi

ORG="$1"
shift

# Source catalog utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

# Set clone directory and resolve GitHub org name(s)
if [[ -n "$STANDALONE_MODE" ]]; then
    # Standalone mode: clone to ./<org>/, use org name directly
    CLONE_DIR="$ORG"
    GITHUB_ORGS=("$ORG")
else
    # Default (catalog) mode: clone to repos/<org>/, read from meta.json if tracked
    CLONE_DIR="repos/$ORG"
    GITHUB_ORGS=()
    while IFS= read -r gh_org; do
        [[ -n "$gh_org" ]] && GITHUB_ORGS+=("$gh_org")
    done < <(get_github_orgs "$ORG")
    if [[ ${#GITHUB_ORGS[@]} -eq 1 && "${GITHUB_ORGS[0]}" != "$ORG" ]]; then
        echo "Program: $ORG -> GitHub org: ${GITHUB_ORGS[0]}"
    elif [[ ${#GITHUB_ORGS[@]} -gt 1 ]]; then
        echo "Program: $ORG -> GitHub orgs: ${GITHUB_ORGS[*]}"
    fi
fi

FILTER_PATTERN=""
INCLUDE_ARCHIVED=""
PARALLEL_JOBS=4
FORCE_SERIAL=""
SPECIFIC_REPOS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--filter)
            FILTER_PATTERN="$2"
            shift 2
            ;;
        -j|--jobs)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        --serial)
            FORCE_SERIAL="1"
            shift
            ;;
        --include-archived)
            INCLUDE_ARCHIVED="1"
            shift
            ;;
        -h|--help)
            show_help
            ;;
        -*)
            echo "Unknown option: $1"
            exit 1
            ;;
        *)
            SPECIFIC_REPOS+=("$1")
            shift
            ;;
    esac
done

# Check for gh CLI
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is required but not installed."
    exit 1
fi

# Check gh authentication
if ! gh auth status &> /dev/null; then
    echo "Error: Not authenticated with GitHub CLI. Run: gh auth login"
    exit 1
fi

# Check for GNU parallel and determine cloning mode
USE_PARALLEL=""
if [[ -z "$FORCE_SERIAL" ]] && command -v parallel &> /dev/null; then
    USE_PARALLEL="1"
fi

# Clone function - handles a single repository
# Args: name url is_archived clone_dir
clone_single_repo() {
    local name="$1"
    local url="$2"
    local is_archived="$3"
    local clone_dir="$4"

    local archived_tag=""
    [[ "$is_archived" == "true" ]] && archived_tag=" [ARCHIVED]"

    if [[ -d "$clone_dir/$name" ]]; then
        echo "[$name]$archived_tag Already exists, fetching updates..."
        if git -C "$clone_dir/$name" fetch --all 2>&1 | sed 's/^/  /'; then
            echo "[$name] Done"
        else
            echo "[$name] Fetch failed"
            return 1
        fi
    else
        echo "[$name]$archived_tag Cloning..."
        if git clone --quiet "$url" "$clone_dir/$name" 2>&1 | sed 's/^/  /'; then
            echo "[$name] Fetching all branches..."
            git -C "$clone_dir/$name" fetch --all --quiet 2>&1 | sed 's/^/  /'
            echo "[$name] Done"
        else
            echo "[$name] Failed to clone"
            return 1
        fi
    fi
}
export -f clone_single_repo

if [[ ${#SPECIFIC_REPOS[@]} -gt 0 ]]; then
    # Clone only specified repositories
    echo "Cloning ${#SPECIFIC_REPOS[@]} specified repositories from: $ORG"

    # Build JSON array of specified repos (use first org for URL)
    REPOS="[]"
    ARCHIVED_REPOS="[]"
    for repo in "${SPECIFIC_REPOS[@]}"; do
        REPOS=$(echo "$REPOS" | jq --arg name "$repo" --arg url "https://github.com/${GITHUB_ORGS[0]}/$repo" '. + [{"name": $name, "url": $url, "isArchived": false}]')
    done
    REPO_COUNT=${#SPECIFIC_REPOS[@]}
else
    # Clone all public non-fork repositories from all GitHub orgs
    if [[ -n "$FILTER_PATTERN" ]]; then
        if [[ -n "$INCLUDE_ARCHIVED" ]]; then
            echo "Fetching public repositories matching '$FILTER_PATTERN' (skipping forks, including archived)"
        else
            echo "Fetching public repositories matching '$FILTER_PATTERN' (skipping forks and archived)"
        fi
    else
        if [[ -n "$INCLUDE_ARCHIVED" ]]; then
            echo "Fetching public repositories (skipping forks, including archived)"
        else
            echo "Fetching public repositories (skipping forks and archived)"
        fi
    fi

    # Fetch repos from all GitHub orgs
    ALL_REPOS="[]"
    TOTAL_FORKS=0
    for github_org in "${GITHUB_ORGS[@]}"; do
        echo "  Fetching from: $github_org"
        ORG_REPOS=$(gh repo list "$github_org" --visibility=public --limit 500 --json name,url,isFork,isArchived 2>&1) || {
            echo "  Warning: Failed to fetch repositories for '$github_org'"
            echo "  $ORG_REPOS"
            continue
        }
        # Merge repos
        ALL_REPOS=$(echo "$ALL_REPOS" "$ORG_REPOS" | jq -s 'add')
        fork_count=$(echo "$ORG_REPOS" | jq '[.[] | select(.isFork == true)] | length')
        TOTAL_FORKS=$((TOTAL_FORKS + fork_count))
    done

    # Separate active and archived repos
    ACTIVE_REPOS=$(echo "$ALL_REPOS" | jq '[.[] | select(.isFork == false and .isArchived == false)]')
    ARCHIVED_REPOS=$(echo "$ALL_REPOS" | jq '[.[] | select(.isFork == false and .isArchived == true)]')
    FORK_COUNT=$TOTAL_FORKS

    # Apply filter pattern if specified
    if [[ -n "$FILTER_PATTERN" ]]; then
        # Convert glob pattern to jq regex: * becomes .*, ? becomes .
        REGEX_PATTERN=$(echo "$FILTER_PATTERN" | sed 's/\./\\./g' | sed 's/\*/.*/g' | sed 's/\?/./g')
        ACTIVE_REPOS=$(echo "$ACTIVE_REPOS" | jq --arg pattern "^${REGEX_PATTERN}$" '[.[] | select(.name | test($pattern; "i"))]')
        ARCHIVED_REPOS=$(echo "$ARCHIVED_REPOS" | jq --arg pattern "^${REGEX_PATTERN}$" '[.[] | select(.name | test($pattern; "i"))]')
    fi

    # Combine repos based on --include-archived flag
    if [[ -n "$INCLUDE_ARCHIVED" ]]; then
        REPOS=$(echo "$ACTIVE_REPOS" "$ARCHIVED_REPOS" | jq -s 'add')
    else
        REPOS="$ACTIVE_REPOS"
    fi

    REPO_COUNT=$(echo "$REPOS" | jq length)
    # FORK_COUNT already set during fetch loop
    ARCHIVED_COUNT=$(echo "$ARCHIVED_REPOS" | jq 'length')
    ACTIVE_COUNT=$(echo "$ACTIVE_REPOS" | jq 'length')

    if [[ "$REPO_COUNT" -eq 0 ]]; then
        if [[ -n "$FILTER_PATTERN" ]]; then
            echo "No repositories matching '$FILTER_PATTERN' found for: $ORG"
        else
            echo "No public non-fork repositories found for: $ORG"
        fi
        exit 0
    fi

    if [[ -n "$FILTER_PATTERN" ]]; then
        if [[ -n "$INCLUDE_ARCHIVED" ]]; then
            echo "Found $REPO_COUNT matching repositories ($ACTIVE_COUNT active, $ARCHIVED_COUNT archived)"
        else
            echo "Found $REPO_COUNT matching repositories (from $ACTIVE_COUNT total, skipping $ARCHIVED_COUNT archived)"
        fi
    else
        if [[ -n "$INCLUDE_ARCHIVED" ]]; then
            echo "Found $REPO_COUNT repositories ($ACTIVE_COUNT active, $ARCHIVED_COUNT archived, skipping $FORK_COUNT forks)"
        else
            echo "Found $REPO_COUNT active repositories (skipping $FORK_COUNT forks, $ARCHIVED_COUNT archived)"
        fi
    fi
fi
echo "Cloning to: ./$CLONE_DIR"
echo ""

mkdir -p "$CLONE_DIR"
mkdir -p "findings/$ORG/"{semgrep-results,trufflehog-results,artifact-results,reports}

# Create/update archived repos manifest
ARCHIVED_MANIFEST="$CLONE_DIR/.archived-repos"
if [[ -n "$INCLUDE_ARCHIVED" ]]; then
    # Write list of archived repo names
    echo "$ARCHIVED_REPOS" | jq -r '.[].name' > "$ARCHIVED_MANIFEST"
    ARCHIVED_TO_CLONE=$(echo "$ARCHIVED_REPOS" | jq 'length')
    if [[ "$ARCHIVED_TO_CLONE" -gt 0 ]]; then
        echo "Archived repos manifest: $ARCHIVED_MANIFEST ($ARCHIVED_TO_CLONE repos)"
        echo "  Note: Archived repos will only be scanned for secrets (trufflehog)"
        echo ""
    fi
else
    # Clear manifest if not including archived
    rm -f "$ARCHIVED_MANIFEST"
fi

# Clone repositories - parallel or serial
if [[ -n "$USE_PARALLEL" ]]; then
    # For large repos, reduce parallelism to avoid file handle exhaustion
    if [[ "$REPO_COUNT" -gt 200 ]]; then
        PARALLEL_JOBS=2
        echo "Large repo count ($REPO_COUNT), using $PARALLEL_JOBS parallel jobs to avoid file handle limits..."
        echo "Hint: Run 'ulimit -n 4096' first if you want more parallelism"
    elif [[ "$REPO_COUNT" -gt 100 && "$PARALLEL_JOBS" -gt 4 ]]; then
        PARALLEL_JOBS=4
        echo "Moderate repo count ($REPO_COUNT), capping at $PARALLEL_JOBS parallel jobs..."
    fi
    echo "Using GNU parallel with $PARALLEL_JOBS jobs..."
    echo ""

    # Export CLONE_DIR for parallel subprocesses
    export CLONE_DIR

    # Use parallel with grouped output (keeps each repo's output together)
    # shellcheck disable=SC1083 # {1},{2},{3} are GNU parallel placeholders
    echo "$REPOS" | jq -r '.[] | "\(.name)\t\(.url)\t\(.isArchived // false)"' | \
        parallel --will-cite --colsep '\t' -j "$PARALLEL_JOBS" --group --keep-order --noswap \
            clone_single_repo '{1}' '{2}' '{3}' "$CLONE_DIR"
else
    if [[ -z "$FORCE_SERIAL" ]]; then
        echo "Note: GNU parallel not found. Install with: brew install parallel"
        echo "Falling back to serial cloning..."
    else
        echo "Serial cloning mode..."
    fi
    echo ""

    echo "$REPOS" | jq -r '.[] | "\(.name)\t\(.url)\t\(.isArchived // false)"' | \
        while IFS=$'\t' read -r name url is_archived; do
            clone_single_repo "$name" "$url" "$is_archived" "$CLONE_DIR"
        done
fi

TOTAL_CLONED=$(ls -d "$CLONE_DIR"/*/ 2>/dev/null | wc -l | xargs)
ARCHIVED_CLONED=0
if [[ -f "$ARCHIVED_MANIFEST" ]]; then
    ARCHIVED_CLONED=$(wc -l < "$ARCHIVED_MANIFEST" | xargs)
fi

echo ""
if [[ "$ARCHIVED_CLONED" -gt 0 ]]; then
    echo "Completed. Total repos: $TOTAL_CLONED ($ARCHIVED_CLONED archived, secrets-only)"
else
    echo "Completed. Total repos: $TOTAL_CLONED"
fi
