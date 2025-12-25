#!/usr/bin/env bash
set -euo pipefail

# FFUF web fuzzer for endpoint and parameter discovery
#
# Discovers hidden endpoints, parameters, and virtual hosts
# using wordlist-based fuzzing.
#
# Usage: ./scripts/scan-ffuf.sh <org-name> <url> [options]
# Output: findings/<org>/dynamic-results/ffuf/<hash>-<mode>.json

show_help() {
    cat << 'EOF'
Usage: ./scripts/scan-ffuf.sh <org-name> <url> [options]

Fuzz web application for hidden endpoints and parameters.

Modes:
  dirs      Directory and endpoint discovery (default)
  params    Parameter name discovery
  vhost     Virtual host enumeration

Options:
  -m, --mode <mode>       Fuzzing mode: dirs, params, vhost (default: dirs)
  -w, --wordlist <file>   Custom wordlist (auto-selected by mode if not specified)
  -mc, --match-codes      HTTP codes to match (default: 200,204,301,302,307,403)
  -fc, --filter-codes     HTTP codes to filter out
  -fs, --filter-size      Filter by response size
  -rl, --rate-limit <n>   Requests per second (default: 50)
  -o, --output <name>     Custom output name
  -h, --help              Show this help

Examples:
  # Directory fuzzing
  ./scripts/scan-ffuf.sh acme-corp https://acme.com/api/

  # Parameter discovery
  ./scripts/scan-ffuf.sh acme-corp https://acme.com/search -m params

  # Virtual host enumeration
  ./scripts/scan-ffuf.sh acme-corp https://acme.com -m vhost

  # Custom wordlist
  ./scripts/scan-ffuf.sh acme-corp https://acme.com/api/ -w /path/to/wordlist.txt

Default Wordlists (if seclists installed):
  dirs:   /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
  params: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
  vhost:  /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

Install seclists: brew install seclists (macOS) or apt install seclists (Debian)
EOF
    exit 0
}

if [[ $# -lt 2 ]]; then
    show_help
fi

ORG="$1"
URL="$2"
shift 2

# Defaults
MODE="dirs"
WORDLIST=""
MATCH_CODES="200,204,301,302,307,403"
FILTER_CODES=""
FILTER_SIZE=""
RATE_LIMIT="50"
OUTPUT_NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--mode) MODE="$2"; shift 2 ;;
        -w|--wordlist) WORDLIST="$2"; shift 2 ;;
        -mc|--match-codes) MATCH_CODES="$2"; shift 2 ;;
        -fc|--filter-codes) FILTER_CODES="$2"; shift 2 ;;
        -fs|--filter-size) FILTER_SIZE="$2"; shift 2 ;;
        -rl|--rate-limit) RATE_LIMIT="$2"; shift 2 ;;
        -o|--output) OUTPUT_NAME="$2"; shift 2 ;;
        -h|--help) show_help ;;
        *) echo "Unknown option: $1"; show_help ;;
    esac
done

RESULTS_DIR="$(pwd)/findings/$ORG/dynamic-results/ffuf"
mkdir -p "$RESULTS_DIR"

# Generate output filename from URL if not specified
if [[ -z "$OUTPUT_NAME" ]]; then
    URL_HASH=$(echo "$URL" | md5 2>/dev/null || echo "$URL" | md5sum | cut -c1-8)
    # Handle both macOS (md5) and Linux (md5sum)
    URL_HASH=$(echo "$URL_HASH" | cut -c1-8)
    OUTPUT_NAME="${URL_HASH}-${MODE}"
fi

OUTPUT_FILE="$RESULTS_DIR/$OUTPUT_NAME.json"

if ! command -v ffuf &> /dev/null; then
    echo "Error: ffuf is required but not installed."
    echo "Run: ./scripts/setup-dynamic-tools.sh"
    exit 1
fi

# Select default wordlist based on mode
if [[ -z "$WORDLIST" ]]; then
    case "$MODE" in
        dirs)
            # Try common wordlist locations
            for wl in \
                "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
                "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
                "/opt/homebrew/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
                "$(pwd)/wordlists/directories.txt"; do
                if [[ -f "$wl" ]]; then
                    WORDLIST="$wl"
                    break
                fi
            done
            ;;
        params)
            for wl in \
                "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt" \
                "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt" \
                "/opt/homebrew/share/seclists/Discovery/Web-Content/burp-parameter-names.txt" \
                "$(pwd)/wordlists/parameters.txt"; do
                if [[ -f "$wl" ]]; then
                    WORDLIST="$wl"
                    break
                fi
            done
            ;;
        vhost)
            for wl in \
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" \
                "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt" \
                "/opt/homebrew/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" \
                "$(pwd)/wordlists/vhosts.txt"; do
                if [[ -f "$wl" ]]; then
                    WORDLIST="$wl"
                    break
                fi
            done
            ;;
    esac
fi

if [[ -z "$WORDLIST" ]] || [[ ! -f "$WORDLIST" ]]; then
    echo "Error: No wordlist found for mode '$MODE'"
    echo ""
    echo "Install seclists:"
    echo "  macOS: brew install seclists"
    echo "  Debian: sudo apt install seclists"
    echo ""
    echo "Or specify a custom wordlist with -w"
    exit 1
fi

WORDLIST_SIZE=$(wc -l < "$WORDLIST" | xargs)

echo "========================================"
echo "FFUF Fuzzing: $MODE"
echo "========================================"
echo "Target: $URL"
echo "Wordlist: $WORDLIST ($WORDLIST_SIZE words)"
echo "Mode: $MODE"
echo "Rate limit: $RATE_LIMIT req/sec"
echo "Output: $OUTPUT_FILE"
echo "========================================"
echo ""

# Build ffuf command based on mode
FFUF_ARGS=(
    -w "$WORDLIST"
    -mc "$MATCH_CODES"
    -rate "$RATE_LIMIT"
    -o "$OUTPUT_FILE"
    -of json
    -ac  # Auto-calibrate filtering
)

# Add optional filters
[[ -n "$FILTER_CODES" ]] && FFUF_ARGS+=(-fc "$FILTER_CODES")
[[ -n "$FILTER_SIZE" ]] && FFUF_ARGS+=(-fs "$FILTER_SIZE")

case "$MODE" in
    dirs)
        # Ensure URL ends with / for directory fuzzing
        if [[ ! "$URL" =~ /$ ]]; then
            URL="${URL}/"
        fi
        FFUF_ARGS+=(-u "${URL}FUZZ")
        ;;
    params)
        # Add FUZZ as parameter name
        if [[ "$URL" == *"?"* ]]; then
            FFUF_ARGS+=(-u "${URL}&FUZZ=test")
        else
            FFUF_ARGS+=(-u "${URL}?FUZZ=test")
        fi
        ;;
    vhost)
        # Extract host from URL
        HOST=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|')
        FFUF_ARGS+=(-u "$URL" -H "Host: FUZZ.$HOST")
        ;;
    *)
        echo "Error: Unknown mode: $MODE"
        exit 1
        ;;
esac

echo "Starting fuzzing..."
echo ""

# Run ffuf
ffuf "${FFUF_ARGS[@]}" 2>&1

echo ""
echo "========================================"
echo "Results"
echo "========================================"

if [[ -f "$OUTPUT_FILE" ]]; then
    RESULT_COUNT=$(jq '.results | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
    echo "Found: $RESULT_COUNT results"

    if [[ "$RESULT_COUNT" -gt 0 ]]; then
        echo ""
        echo "Top results by status:"
        jq -r '.results[] | "\(.status) \(.url) [\(.length) bytes]"' "$OUTPUT_FILE" 2>/dev/null | head -20 | sed 's/^/  /'
    fi

    echo ""
    echo "Results: $OUTPUT_FILE"
else
    echo "No results file generated"
fi

echo ""
echo "Review findings:"
echo "  ./scripts/extract-ffuf-findings.sh $ORG"
echo ""
