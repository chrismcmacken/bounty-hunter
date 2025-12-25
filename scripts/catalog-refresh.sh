#!/usr/bin/env bash
# Fetch bug bounty program targets from platforms using bbscope
#
# Usage: ./scripts/catalog-refresh.sh [platform]
#
# Examples:
#   ./scripts/catalog-refresh.sh              # Refresh all platforms
#   ./scripts/catalog-refresh.sh hackerone    # Refresh only HackerOne
#   ./scripts/catalog-refresh.sh --list       # List available platforms

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CATALOG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat << EOF
Usage: $0 [platform] [options]

Fetch bug bounty program targets from platforms using bbscope.

Platforms:
    hackerone   Fetch from HackerOne
    bugcrowd    Fetch from Bugcrowd
    yeswehack   Fetch from YesWeHack
    intigriti   Fetch from Intigriti
    all         Fetch from all platforms (default)

Options:
    --list      List available platforms and token status
    --dry-run   Show what would be fetched without actually fetching
    --query <program>  Query scopes for a program (uses DuckDB)
    --stats     Show statistics about fetched platform data
    -h, --help  Show this help message

Setup:
    1. Install bbscope: go install github.com/sw33tLie/bbscope@latest
    2. Copy .env.example to .env and add your API tokens
    3. Run this script to fetch program data

Examples:
    $0                        # Refresh all configured platforms
    $0 hackerone              # Refresh only HackerOne
    $0 --list                 # Check which platforms are configured
    $0 --query dynatrace      # Find all scopes matching 'dynatrace'
    $0 --stats                # Show scope counts per platform
EOF
    exit 1
}

# Load environment
load_env() {
    if [[ -f "$CATALOG_ROOT/.env" ]]; then
        # Source .env file, handling comments and empty lines
        set -a
        # shellcheck disable=SC1091
        source "$CATALOG_ROOT/.env"
        set +a
    fi
}

# Check if a platform token is configured
has_token() {
    local platform="$1"
    case "$platform" in
        hackerone)
            [[ -n "${HACKERONE_TOKEN:-}" ]]
            ;;
        bugcrowd)
            # Bugcrowd supports session token OR email/password auth
            [[ -n "${BUGCROWD_TOKEN:-}" ]] || \
            [[ -n "${BUGCROWD_USER:-}" && -n "${BUGCROWD_PASSWORD:-}" ]]
            ;;
        yeswehack)
            [[ -n "${YESWEHACK_TOKEN:-}" ]]
            ;;
        intigriti)
            [[ -n "${INTIGRITI_TOKEN:-}" ]]
            ;;
        *)
            return 1
            ;;
    esac
}

# List platforms and their token status
list_platforms() {
    echo "Platform Status:"
    echo "----------------------------------------"

    load_env

    for platform in hackerone bugcrowd yeswehack intigriti; do
        if has_token "$platform"; then
            # Show auth method for bugcrowd
            if [[ "$platform" == "bugcrowd" ]]; then
                if [[ -n "${BUGCROWD_TOKEN:-}" ]]; then
                    echo "  $platform: configured (session token)"
                else
                    echo "  $platform: configured (email/password)"
                fi
            else
                echo "  $platform: configured"
            fi
        else
            if [[ "$platform" == "bugcrowd" ]]; then
                echo "  $platform: not configured (need BUGCROWD_TOKEN or BUGCROWD_USER+BUGCROWD_PASSWORD)"
            else
                echo "  $platform: not configured (no token)"
            fi
        fi
    done

    echo ""
    echo "To configure tokens, edit .env file:"
    echo "  cp .env.example .env"
    echo "  # Then add your API tokens"
}

# Refresh a single platform
refresh_platform() {
    local platform="$1"
    local dry_run="${2:-}"
    local output_dir="$CATALOG_ROOT/catalog/platforms"
    local output_file="$output_dir/$platform.json"
    local temp_file="${output_file}.tmp"
    local temp_file_paid="${output_file}.paid.tmp"

    echo "----------------------------------------"
    echo "Refreshing: $platform"
    echo "----------------------------------------"

    # Check for token
    if ! has_token "$platform"; then
        local token_name
        token_name=$(echo "${platform}_TOKEN" | tr '[:lower:]' '[:upper:]')
        echo "  Skipping: No token configured"
        echo "  Set $token_name in .env"
        return 0
    fi

    # Check for bbscope (check common locations)
    local bbscope_cmd="bbscope"
    if ! command -v bbscope &> /dev/null; then
        if [[ -x "$HOME/go/bin/bbscope" ]]; then
            bbscope_cmd="$HOME/go/bin/bbscope"
        else
            echo "  Error: bbscope not installed"
            echo "  Install: go install github.com/sw33tLie/bbscope@latest"
            return 1
        fi
    fi

    if [[ -n "$dry_run" ]]; then
        echo "  [DRY RUN] Would fetch from $platform"
        return 0
    fi

    mkdir -p "$output_dir"

    # Run bbscope based on platform - fetch ALL programs first
    local fetch_success=""
    local fetch_paid_success=""

    case "$platform" in
        hackerone)
            echo "  Fetching all programs from HackerOne..."
            if "$bbscope_cmd" h1 -t "$HACKERONE_TOKEN" -u "${HACKERONE_USERNAME:-}" -o tdu > "$temp_file" 2>&1; then
                fetch_success="1"
            else
                echo "  bbscope error:"
                head -5 "$temp_file" | sed 's/^/    /'
            fi
            # Fetch paid-only programs for bounty status detection
            if [[ -n "$fetch_success" ]]; then
                echo "  Fetching paid programs only..."
                if "$bbscope_cmd" h1 -t "$HACKERONE_TOKEN" -u "${HACKERONE_USERNAME:-}" -b -o u > "$temp_file_paid" 2>&1; then
                    fetch_paid_success="1"
                else
                    echo "  Warning: Could not fetch paid-only list, all programs will be marked as paid=unknown"
                fi
            fi
            ;;
        bugcrowd)
            echo "  Fetching all programs from Bugcrowd..."
            if [[ -n "${BUGCROWD_TOKEN:-}" ]]; then
                # Use session token
                echo "  Using session token auth..."
                if "$bbscope_cmd" bc -t "$BUGCROWD_TOKEN" -o tdu > "$temp_file" 2>&1; then
                    fetch_success="1"
                else
                    echo "  bbscope error:"
                    head -5 "$temp_file" | sed 's/^/    /'
                fi
                # Fetch paid-only programs
                if [[ -n "$fetch_success" ]]; then
                    echo "  Fetching paid programs only..."
                    if "$bbscope_cmd" bc -t "$BUGCROWD_TOKEN" -b -o u > "$temp_file_paid" 2>&1; then
                        fetch_paid_success="1"
                    else
                        echo "  Warning: Could not fetch paid-only list"
                    fi
                fi
            else
                # Use email/password/OTP auth
                echo "  Using email/password auth with OTP..."
                # OTP command - uses 2fa utility if available (check common locations)
                local otp_cmd="${BUGCROWD_OTP_CMD:-}"
                if [[ -z "$otp_cmd" ]]; then
                    if command -v 2fa &> /dev/null; then
                        otp_cmd="2fa bugcrowd"
                    elif [[ -x "$HOME/go/bin/2fa" ]]; then
                        otp_cmd="$HOME/go/bin/2fa bugcrowd"
                    else
                        echo "  Error: 2fa utility not found"
                        echo "  Install: go install rsc.io/2fa@latest && 2fa -add bugcrowd"
                        return 1
                    fi
                fi
                if "$bbscope_cmd" bc -E "$BUGCROWD_USER" -P "$BUGCROWD_PASSWORD" -O "$otp_cmd" -o tdu > "$temp_file" 2>&1; then
                    fetch_success="1"
                else
                    echo "  bbscope error:"
                    head -5 "$temp_file" | sed 's/^/    /'
                fi
                # Fetch paid-only programs
                if [[ -n "$fetch_success" ]]; then
                    echo "  Fetching paid programs only..."
                    if "$bbscope_cmd" bc -E "$BUGCROWD_USER" -P "$BUGCROWD_PASSWORD" -O "$otp_cmd" -b -o u > "$temp_file_paid" 2>&1; then
                        fetch_paid_success="1"
                    else
                        echo "  Warning: Could not fetch paid-only list"
                    fi
                fi
            fi
            ;;
        yeswehack)
            echo "  Fetching all programs from YesWeHack..."
            if "$bbscope_cmd" ywh -t "$YESWEHACK_TOKEN" -o tdu > "$temp_file" 2>&1; then
                fetch_success="1"
            else
                echo "  bbscope error:"
                head -5 "$temp_file" | sed 's/^/    /'
            fi
            # Fetch paid-only programs
            if [[ -n "$fetch_success" ]]; then
                echo "  Fetching paid programs only..."
                if "$bbscope_cmd" ywh -t "$YESWEHACK_TOKEN" -b -o u > "$temp_file_paid" 2>&1; then
                    fetch_paid_success="1"
                else
                    echo "  Warning: Could not fetch paid-only list"
                fi
            fi
            ;;
        intigriti)
            echo "  Fetching all programs from Intigriti..."
            if "$bbscope_cmd" it -t "$INTIGRITI_TOKEN" -o tdu > "$temp_file" 2>&1; then
                fetch_success="1"
            else
                echo "  bbscope error:"
                head -5 "$temp_file" | sed 's/^/    /'
            fi
            # Fetch paid-only programs
            if [[ -n "$fetch_success" ]]; then
                echo "  Fetching paid programs only..."
                if "$bbscope_cmd" it -t "$INTIGRITI_TOKEN" -b -o u > "$temp_file_paid" 2>&1; then
                    fetch_paid_success="1"
                else
                    echo "  Warning: Could not fetch paid-only list"
                fi
            fi
            ;;
        *)
            echo "  Error: Unknown platform '$platform'"
            return 1
            ;;
    esac

    if [[ -z "$fetch_success" ]]; then
        echo "  Failed to fetch from $platform"
        rm -f "$temp_file" "$temp_file_paid"
        return 1
    fi

    # Check if output contains error message
    if grep -q "level=fatal\|level=error" "$temp_file" 2>/dev/null; then
        echo "  Error from bbscope:"
        head -3 "$temp_file" | sed 's/^/    /'
        rm -f "$temp_file" "$temp_file_paid"
        return 1
    fi

    # Build set of paid program URLs for lookup (stored in temp file for grep lookup)
    local temp_file_paid_normalized="${output_file}.paid_urls.tmp"
    local paid_count=0
    local vdp_count=0
    local paid_program_count=0
    if [[ -n "$fetch_paid_success" ]] && [[ -f "$temp_file_paid" ]]; then
        # Filter out error/log lines, normalize URLs, and save to lookup file
        grep -v '^time=' "$temp_file_paid" 2>/dev/null | \
            grep -v '^level=' | \
            grep -v '^$' | \
            sed 's:/*$::' | \
            tr '[:upper:]' '[:lower:]' | \
            sort -u > "$temp_file_paid_normalized"
        paid_program_count=$(wc -l < "$temp_file_paid_normalized" | xargs)
        echo "  Found $paid_program_count paid programs"
    fi

    # Count lines (each line is a scope item)
    local count
    count=$(wc -l < "$temp_file" | xargs)

    # Convert line-based output to JSON
    # bbscope -o tdu outputs: target description program_url (space-separated)
    # We'll parse and create a JSON array
    {
        echo "{"
        echo "  \"platform\": \"$platform\","
        echo "  \"refresh_time\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"scope_count\": $count,"
        echo "  \"scopes\": ["

        local first=true
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            # Skip bbscope log lines that may be mixed into output
            [[ "$line" =~ ^time= ]] && continue
            [[ "$line" =~ ^level= ]] && continue
            [[ "$line" =~ msg=.*Programs ]] && continue
            # Parse the line - format is: target description url
            # The URL is typically at the end starting with http
            local target desc url
            if [[ "$line" =~ ^(.+)[[:space:]](https?://[^[:space:]]+)$ ]]; then
                target="${BASH_REMATCH[1]}"
                url="${BASH_REMATCH[2]}"
                desc=""
            else
                # Just take the whole line as target
                target="$line"
                desc=""
                url=""
            fi

            # Determine if this program is paid
            local is_paid="null"
            if [[ -n "$fetch_paid_success" ]] && [[ -n "$url" ]] && [[ -f "$temp_file_paid_normalized" ]]; then
                # Normalize URL for comparison
                local url_normalized
                url_normalized=$(echo "$url" | sed 's:/*$::' | tr '[:upper:]' '[:lower:]')
                if grep -qxF "$url_normalized" "$temp_file_paid_normalized" 2>/dev/null; then
                    is_paid="true"
                    ((paid_count++))
                else
                    is_paid="false"
                    ((vdp_count++))
                fi
            fi

            # Escape for JSON using jq for proper escaping
            local json_target json_url
            json_target=$(printf '%s' "$target" | jq -Rs '.')
            json_url=$(printf '%s' "$url" | jq -Rs '.')

            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo ","
            fi
            printf '    {"target": %s, "url": %s, "paid": %s}' "$json_target" "$json_url" "$is_paid"
        done < "$temp_file"

        echo ""
        echo "  ]"
        echo "}"
    } > "$output_file"

    rm -f "$temp_file" "$temp_file_paid" "$temp_file_paid_normalized"

    echo "  Fetched: $count scope items"
    if [[ -n "$fetch_paid_success" ]]; then
        echo "  Bounty status: $paid_count paid, $vdp_count VDP"
    fi

    # Show diff if previous version exists in git
    if git -C "$CATALOG_ROOT" show HEAD:"catalog/platforms/$platform.json" &>/dev/null 2>&1; then
        local prev_count
        prev_count=$(git -C "$CATALOG_ROOT" show HEAD:"catalog/platforms/$platform.json" 2>/dev/null | jq '.scope_count // 0' 2>/dev/null || echo "0")

        if [[ "$count" -ne "$prev_count" ]]; then
            local diff_count=$((count - prev_count))
            if [[ "$diff_count" -gt 0 ]]; then
                echo "  Change: +$diff_count scope items since last refresh"
            else
                echo "  Change: $diff_count scope items since last refresh"
            fi
        fi

        # Show new targets if any
        local new_targets
        new_targets=$(diff \
            <(git -C "$CATALOG_ROOT" show HEAD:"catalog/platforms/$platform.json" 2>/dev/null | jq -r '.scopes[]?.target // empty' | sort) \
            <(jq -r '.scopes[]?.target // empty' "$output_file" | sort) \
            2>/dev/null | grep '^>' | head -5 | sed 's/^> /  NEW: /' || true)

        if [[ -n "$new_targets" ]]; then
            echo "$new_targets"
            local new_count
            new_count=$(diff \
                <(git -C "$CATALOG_ROOT" show HEAD:"catalog/platforms/$platform.json" 2>/dev/null | jq -r '.scopes[]?.target // empty' | sort) \
                <(jq -r '.scopes[]?.target // empty' "$output_file" | sort) \
                2>/dev/null | grep -c '^>' || echo "0")
            if [[ "$new_count" -gt 5 ]]; then
                echo "  ... and $((new_count - 5)) more new targets"
            fi
        fi
    fi

    echo ""
}

# Query scopes using DuckDB
query_scopes() {
    local search="$1"
    local platforms_dir="$CATALOG_ROOT/catalog/platforms"

    if ! command -v duckdb &> /dev/null; then
        echo "Error: DuckDB is required for queries"
        echo "Install: brew install duckdb"
        exit 1
    fi

    # Check if any platform files exist
    shopt -s nullglob
    local files=("$platforms_dir"/*.json)
    shopt -u nullglob

    if [[ ${#files[@]} -eq 0 ]]; then
        echo "No platform data found. Run: $0 hackerone"
        exit 1
    fi

    echo "Searching for: $search"
    echo "========================================"

    # Escape single quotes by doubling them for SQL, using sed for reliability
    local escaped_search
    escaped_search=$(printf '%s' "$search" | sed "s/'/''/g")
    local search_lower
    search_lower=$(echo "$escaped_search" | tr '[:upper:]' '[:lower:]')

    duckdb -c "
        SELECT
            unnest.target as target,
            COALESCE(
                NULLIF(regexp_extract(unnest.url, 'hackerone.com/([^/]+)', 1), ''),
                NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/engagements/([^/]+)', 1), ''),
                NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/([^/]+)', 1), ''),
                ''
            ) as program,
            platform,
            CASE
                WHEN unnest.paid = true THEN 'paid'
                WHEN unnest.paid = false THEN 'vdp'
                ELSE '?'
            END as type
        FROM read_json('$platforms_dir/*.json'),
        UNNEST(scopes)
        WHERE lower(unnest.target) LIKE '%$search_lower%'
           OR lower(unnest.url) LIKE '%$search_lower%'
        ORDER BY platform, program, target
        LIMIT 50
    "
}

# Show stats using DuckDB
show_stats() {
    local platforms_dir="$CATALOG_ROOT/catalog/platforms"

    if ! command -v duckdb &> /dev/null; then
        echo "Error: DuckDB is required for stats"
        echo "Install: brew install duckdb"
        exit 1
    fi

    shopt -s nullglob
    local files=("$platforms_dir"/*.json)
    shopt -u nullglob

    if [[ ${#files[@]} -eq 0 ]]; then
        echo "No platform data found. Run: $0 hackerone"
        exit 1
    fi

    echo "Platform Statistics"
    echo "========================================"

    duckdb -c "
        SELECT
            platform,
            scope_count,
            refresh_time
        FROM read_json('$platforms_dir/*.json')
        ORDER BY scope_count DESC
    "

    echo ""
    echo "Bounty Status by Platform:"
    echo "----------------------------------------"

    duckdb -c "
        SELECT
            platform,
            COUNT(*) FILTER (WHERE unnest.paid = true) as paid_scopes,
            COUNT(*) FILTER (WHERE unnest.paid = false) as vdp_scopes,
            COUNT(*) FILTER (WHERE unnest.paid IS NULL) as unknown_scopes,
            COUNT(DISTINCT unnest.url) FILTER (WHERE unnest.paid = true) as paid_programs,
            COUNT(DISTINCT unnest.url) FILTER (WHERE unnest.paid = false) as vdp_programs
        FROM read_json('$platforms_dir/*.json'),
        UNNEST(scopes)
        GROUP BY platform
        ORDER BY paid_scopes DESC
    "

    echo ""
    echo "Top Programs by Scope Count:"
    echo "----------------------------------------"

    duckdb -c "
        SELECT
            COALESCE(
                NULLIF(regexp_extract(unnest.url, 'hackerone.com/([^/]+)', 1), ''),
                NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/engagements/([^/]+)', 1), ''),
                NULLIF(regexp_extract(unnest.url, 'bugcrowd.com/([^/]+)', 1), ''),
                NULLIF(regexp_extract(unnest.url, 'yeswehack.com/programs/([^/]+)', 1), ''),
                NULLIF(regexp_extract(unnest.url, 'intigriti.com/programs/([^/]+)', 1), ''),
                'unknown'
            ) as program,
            platform,
            CASE
                WHEN unnest.paid = true THEN 'paid'
                WHEN unnest.paid = false THEN 'vdp'
                ELSE 'unknown'
            END as type,
            count(*) as scopes
        FROM read_json('$platforms_dir/*.json'),
        UNNEST(scopes)
        WHERE unnest.url <> ''
        GROUP BY program, platform, type
        ORDER BY scopes DESC
        LIMIT 20
    "
}

# Parse arguments
PLATFORM="all"
DRY_RUN=""
LIST_ONLY=""
QUERY_TERM=""
SHOW_STATS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY="1"
            shift
            ;;
        --dry-run)
            DRY_RUN="1"
            shift
            ;;
        --query)
            QUERY_TERM="$2"
            shift 2
            ;;
        --stats)
            SHOW_STATS="1"
            shift
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            ;;
        *)
            PLATFORM="$1"
            shift
            ;;
    esac
done

# Load environment
load_env

# Handle --list
if [[ -n "$LIST_ONLY" ]]; then
    list_platforms
    exit 0
fi

# Handle --query
if [[ -n "$QUERY_TERM" ]]; then
    query_scopes "$QUERY_TERM"
    exit 0
fi

# Handle --stats
if [[ -n "$SHOW_STATS" ]]; then
    show_stats
    exit 0
fi

echo "========================================"
echo "Catalog Refresh: Bug Bounty Platforms"
echo "========================================"
echo ""

if [[ -n "$DRY_RUN" ]]; then
    echo "[DRY RUN MODE]"
    echo ""
fi

# Track success/failure
TOTAL=0
SUCCESS=0
FAILED=0

# Refresh requested platforms
if [[ "$PLATFORM" == "all" ]]; then
    PLATFORMS=(hackerone bugcrowd yeswehack intigriti)
else
    PLATFORMS=("$PLATFORM")
fi

for p in "${PLATFORMS[@]}"; do
    TOTAL=$((TOTAL + 1))
    if refresh_platform "$p" "$DRY_RUN"; then
        SUCCESS=$((SUCCESS + 1))
    else
        FAILED=$((FAILED + 1))
    fi
done

echo "========================================"
echo "Summary"
echo "========================================"
echo "  Platforms: $TOTAL"
echo "  Success:   $SUCCESS"
echo "  Failed:    $FAILED"
echo ""

if [[ -z "$DRY_RUN" && "$SUCCESS" -gt 0 ]]; then
    echo "Review changes:"
    echo "  git diff catalog/platforms/"
    echo ""
    echo "Commit changes:"
    echo "  git add catalog/platforms/"
    echo "  git commit -m 'Refresh platform data'"
    echo ""
fi
