#!/usr/bin/env bash
set -euo pipefail

# Target list management for dynamic scanning
#
# Manages the master target list used by nuclei and other scanners.
# Supports importing from recon results, files, or manual addition.
#
# Usage: ./scripts/recon-targets.sh <org-name> <command> [args]

show_help() {
    cat << 'EOF'
Usage: ./scripts/recon-targets.sh <org-name> <command> [args]

Manage target URLs for dynamic vulnerability scanning.

Commands:
  add-urls <file>      Add URLs from a file (one per line)
  add-url <url>        Add a single URL
  add-domain <domain>  Add a domain as https://<domain>
  from-recon           Import URLs from httpx recon results
  list                 Show current targets
  count                Show target count only
  clear                Remove all targets

Examples:
  # Import from recon results
  ./scripts/recon-targets.sh acme-corp from-recon

  # Add URLs from a file
  ./scripts/recon-targets.sh acme-corp add-urls scope-urls.txt

  # Add a single URL
  ./scripts/recon-targets.sh acme-corp add-url https://api.acme.com

  # Add a domain
  ./scripts/recon-targets.sh acme-corp add-domain acme.com

  # List current targets
  ./scripts/recon-targets.sh acme-corp list

  # Clear all targets
  ./scripts/recon-targets.sh acme-corp clear

Output:
  scans/<org>/dynamic-results/targets.txt
EOF
    exit 0
}

if [[ $# -lt 2 ]]; then
    show_help
fi

ORG="$1"
COMMAND="$2"
shift 2

RESULTS_DIR="$(pwd)/scans/$ORG/dynamic-results"
TARGETS_FILE="$RESULTS_DIR/targets.txt"
RECON_URLS="$RESULTS_DIR/recon/live-urls.txt"

mkdir -p "$RESULTS_DIR"

# Ensure targets file exists
touch "$TARGETS_FILE"

case "$COMMAND" in
    add-urls)
        if [[ $# -lt 1 ]]; then
            echo "Error: Specify a file with URLs"
            echo "Usage: $0 $ORG add-urls <file>"
            exit 1
        fi
        FILE="$1"
        if [[ ! -f "$FILE" ]]; then
            echo "Error: File not found: $FILE"
            exit 1
        fi

        BEFORE=$(wc -l < "$TARGETS_FILE" | xargs)
        cat "$FILE" >> "$TARGETS_FILE"
        sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
        AFTER=$(wc -l < "$TARGETS_FILE" | xargs)
        ADDED=$((AFTER - BEFORE))

        echo "Added $ADDED new URLs from $FILE"
        echo "Total targets: $AFTER"
        ;;

    add-url)
        if [[ $# -lt 1 ]]; then
            echo "Error: Specify a URL"
            echo "Usage: $0 $ORG add-url <url>"
            exit 1
        fi
        URL="$1"

        if grep -qxF "$URL" "$TARGETS_FILE" 2>/dev/null; then
            echo "URL already exists: $URL"
        else
            echo "$URL" >> "$TARGETS_FILE"
            sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
            echo "Added: $URL"
        fi

        TOTAL=$(wc -l < "$TARGETS_FILE" | xargs)
        echo "Total targets: $TOTAL"
        ;;

    add-domain)
        if [[ $# -lt 1 ]]; then
            echo "Error: Specify a domain"
            echo "Usage: $0 $ORG add-domain <domain>"
            exit 1
        fi
        DOMAIN="$1"
        URL="https://$DOMAIN"

        if grep -qxF "$URL" "$TARGETS_FILE" 2>/dev/null; then
            echo "Domain already exists: $URL"
        else
            echo "$URL" >> "$TARGETS_FILE"
            sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
            echo "Added: $URL"
        fi

        TOTAL=$(wc -l < "$TARGETS_FILE" | xargs)
        echo "Total targets: $TOTAL"
        ;;

    from-recon)
        if [[ ! -f "$RECON_URLS" ]]; then
            echo "Error: Recon results not found: $RECON_URLS"
            echo "Run ./scripts/recon-httpx.sh $ORG first"
            exit 1
        fi

        BEFORE=$(wc -l < "$TARGETS_FILE" | xargs)
        cat "$RECON_URLS" >> "$TARGETS_FILE"
        sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
        AFTER=$(wc -l < "$TARGETS_FILE" | xargs)
        ADDED=$((AFTER - BEFORE))

        echo "Imported $ADDED new URLs from recon"
        echo "Total targets: $AFTER"
        ;;

    list)
        if [[ ! -s "$TARGETS_FILE" ]]; then
            echo "No targets configured for $ORG"
            echo ""
            echo "Add targets with:"
            echo "  $0 $ORG add-urls <file>"
            echo "  $0 $ORG add-domain <domain>"
            echo "  $0 $ORG from-recon"
            exit 0
        fi

        TOTAL=$(wc -l < "$TARGETS_FILE" | xargs)
        echo "Targets for $ORG ($TOTAL total):"
        echo ""
        cat "$TARGETS_FILE" | sed 's/^/  /'
        ;;

    count)
        if [[ -f "$TARGETS_FILE" ]]; then
            wc -l < "$TARGETS_FILE" | xargs
        else
            echo "0"
        fi
        ;;

    clear)
        if [[ -f "$TARGETS_FILE" ]]; then
            TOTAL=$(wc -l < "$TARGETS_FILE" | xargs)
            rm -f "$TARGETS_FILE"
            touch "$TARGETS_FILE"
            echo "Cleared $TOTAL targets"
        else
            echo "No targets to clear"
        fi
        ;;

    *)
        echo "Error: Unknown command: $COMMAND"
        echo ""
        show_help
        ;;
esac
