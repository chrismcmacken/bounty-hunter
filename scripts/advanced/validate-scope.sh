#!/usr/bin/env bash
set -euo pipefail

# Validate targets against program scope before scanning
#
# Ensures all targets are within the authorized scope to avoid
# scanning out-of-scope assets.
#
# Usage: ./scripts/validate-scope.sh <org-name> <scope-file>

show_help() {
    cat << 'EOF'
Usage: ./scripts/validate-scope.sh <org-name> <scope-file>

Validate target URLs against authorized scope before scanning.

Arguments:
  org-name     Organization name
  scope-file   File containing allowed domains/patterns (one per line)

Scope File Format:
  - One domain or pattern per line
  - Supports wildcards with *
  - Lines starting with # are comments

Example scope file:
  # Main domains
  example.com
  *.example.com
  api.example.io

  # Subdomains
  app.example.com
  admin.example.com

Examples:
  ./scripts/validate-scope.sh acme-corp scope.txt

  # Create scope file and validate
  echo "acme.com" > scope.txt
  echo "*.acme.com" >> scope.txt
  ./scripts/validate-scope.sh acme-corp scope.txt

What it checks:
  - Each target URL's domain against scope patterns
  - Reports any out-of-scope targets
  - Exits with error if out-of-scope targets found
EOF
    exit 0
}

if [[ $# -lt 2 ]]; then
    show_help
fi

ORG="$1"
SCOPE_FILE="$2"

TARGETS_FILE="findings/$ORG/dynamic-results/targets.txt"

if [[ ! -f "$TARGETS_FILE" ]]; then
    echo "Error: Targets file not found: $TARGETS_FILE"
    echo "Run ./scripts/recon-targets.sh $ORG first"
    exit 1
fi

if [[ ! -f "$SCOPE_FILE" ]]; then
    echo "Error: Scope file not found: $SCOPE_FILE"
    exit 1
fi

TARGET_COUNT=$(wc -l < "$TARGETS_FILE" | xargs)
SCOPE_COUNT=$(grep -v '^#' "$SCOPE_FILE" | grep -v '^$' | wc -l | xargs)

echo "========================================"
echo "Scope Validation: $ORG"
echo "========================================"
echo "Targets: $TARGET_COUNT"
echo "Scope patterns: $SCOPE_COUNT"
echo ""

# Load scope patterns into array
declare -a SCOPE_PATTERNS
while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^#.*$ ]] && continue
    [[ -z "$line" ]] && continue
    SCOPE_PATTERNS+=("$line")
done < "$SCOPE_FILE"

if [[ ${#SCOPE_PATTERNS[@]} -eq 0 ]]; then
    echo "Error: No valid patterns in scope file"
    exit 1
fi

# Function to check if domain matches any scope pattern
matches_scope() {
    local domain="$1"

    for pattern in "${SCOPE_PATTERNS[@]}"; do
        # Convert pattern to regex
        # - Escape dots
        # - Convert * to regex .*
        local regex
        regex=$(echo "$pattern" | sed 's/\./\\./g' | sed 's/\*/.*/g')

        # Check if domain matches pattern
        if [[ "$domain" =~ ^${regex}$ ]]; then
            return 0  # Match found
        fi

        # Also check if domain ends with .pattern (for subdomain matching)
        if [[ "$domain" =~ \.${regex}$ ]]; then
            return 0
        fi

        # Check exact match
        if [[ "$domain" == "$pattern" ]]; then
            return 0
        fi
    done

    return 1  # No match
}

# Check each target
out_of_scope=0
in_scope=0
declare -a OUT_OF_SCOPE_TARGETS

while IFS= read -r url; do
    # Extract domain from URL
    domain=$(echo "$url" | sed -E 's|https?://([^/:]+).*|\1|')

    if matches_scope "$domain"; then
        ((in_scope++))
    else
        ((out_of_scope++))
        OUT_OF_SCOPE_TARGETS+=("$url")
    fi
done < "$TARGETS_FILE"

echo "In scope: $in_scope"
echo "Out of scope: $out_of_scope"
echo ""

if [[ $out_of_scope -gt 0 ]]; then
    echo "========================================"
    echo "OUT OF SCOPE TARGETS"
    echo "========================================"
    for target in "${OUT_OF_SCOPE_TARGETS[@]}"; do
        echo "  $target"
    done
    echo ""
    echo "*** WARNING: $out_of_scope targets are OUT OF SCOPE ***"
    echo ""
    echo "Options:"
    echo "  1. Remove out-of-scope targets from targets.txt"
    echo "  2. Update scope file if targets should be included"
    echo "  3. Verify program scope before scanning"
    echo ""
    exit 1
else
    echo "All targets are within scope"
    echo ""
    echo "Safe to proceed with scanning:"
    echo "  ./scripts/scan-dynamic.sh $ORG --skip-recon"
fi
