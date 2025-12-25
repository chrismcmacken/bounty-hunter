#!/usr/bin/env bash
set -euo pipefail

# Semgrep Security Scanner - Pro Engine with cross-file analysis
#
# Key features:
# - Pro engine: Cross-file and cross-function dataflow/taint analysis
# - Uses p/default (CI-optimized) instead of p/security-audit (audit-style with many FPs)
# - Custom rules enabled by default (0xdea-semgrep-rules, open-semgrep-rules, web-vulns)
# - Excludes test files, examples, vendor code, and generated files
# - Excludes specific rules known to produce false positives
# - Creates .semgrepignore for persistent exclusion configuration
#
# Requires: semgrep login (free for up to 10 contributors)

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <org-name> [--repos-dir <path>] [--output-dir <path>] [--no-custom-rules] [-q|--quiet]"
    echo "Scan all repositories with Semgrep (high-confidence security findings only)."
    echo ""
    echo "Options:"
    echo "  --repos-dir <path>    Directory containing repos to scan"
    echo "  --output-dir <path>   Output directory for results"
    echo "  --no-custom-rules     Disable custom rules from custom-rules/ (enabled by default)"
    echo "  -q, --quiet           Quiet mode: show progress and final summary only"
    exit 1
fi

ORG="$1"
shift

REPOS_DIR=""
OUTPUT_DIR=""
USE_CUSTOM_RULES=true
QUIET_MODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repos-dir)
            REPOS_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-custom-rules)
            USE_CUSTOM_RULES=false
            shift
            ;;
        -q|--quiet)
            QUIET_MODE="1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

export QUIET_MODE

# Default repos dir to org name if not specified
REPOS_DIR="${REPOS_DIR:-$ORG}"
OUTPUT_DIR="${OUTPUT_DIR:-findings/$ORG}"

if [[ ! -d "$REPOS_DIR" ]]; then
    echo "Error: Directory '$REPOS_DIR' not found."
    exit 1
fi

if ! command -v semgrep &> /dev/null; then
    echo "Error: semgrep is required but not installed."
    echo "Install: brew install semgrep"
    exit 1
fi

# Check if logged in for Pro engine access
if [[ ! -f ~/.semgrep/settings.yml ]] || ! grep -q "api_token" ~/.semgrep/settings.yml 2>/dev/null; then
    echo "Warning: Not logged into Semgrep. Pro engine requires authentication."
    echo "Run: semgrep login"
    echo "Continuing with Pro flag (may fall back to OSS if not authenticated)..."
    echo ""
fi

# Handle both relative and absolute paths
if [[ "$OUTPUT_DIR" = /* ]]; then
    RESULTS_DIR="${OUTPUT_DIR}/semgrep-results"
else
    RESULTS_DIR="$(pwd)/$OUTPUT_DIR/semgrep-results"
fi
mkdir -p "$RESULTS_DIR"

# Source utility functions for archived repo detection
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/catalog-utils.sh"

# Create a .semgrepignore if one doesn't exist in the repos directory
SEMGREPIGNORE="$REPOS_DIR/.semgrepignore"
if [[ ! -f "$SEMGREPIGNORE" ]]; then
    cat > "$SEMGREPIGNORE" << 'EOF'
# Semgrepignore - Reduces false positives by excluding non-production code
# Reference: https://semgrep.dev/docs/ignoring-files-folders-code

# Include default gitignore patterns
:include .gitignore

# Test files and fixtures
**/test/**
**/tests/**
**/__tests__/**
**/*_test.go
**/*_test.py
**/test_*.py
**/*.test.js
**/*.test.ts
**/*.spec.js
**/*.spec.ts
**/testdata/**
**/fixtures/**
**/mock/**
**/mocks/**

# Examples and demos
**/examples/**
**/example/**
**/demo/**
**/demos/**
**/samples/**
**/sample/**

# Generated code
**/generated/**
**/*_generated.*
**/*.generated.*
**/uniffi/**
**/*_gen.go
**/*.pb.go

# Vendor and dependencies
**/vendor/**
**/node_modules/**
**/3rdparty/**
**/third_party/**
**/third-party/**
**/external/**

# Build artifacts
**/dist/**
**/build/**
**/target/**
**/out/**
**/*.min.js
**/*.min.css
**/*.bundle.js

# Documentation
**/docs/**
**/*.md

# IDE and config
**/.idea/**
**/.vscode/**
**/.git/**
EOF
    echo "Created $SEMGREPIGNORE"
fi

# Rules known to produce high false positive rates
# Based on analysis of lightsparkdev scan results
EXCLUDE_RULES=(
    # API token auth flagged as basic auth - it's intentional API design
    "yaml.openapi.security.security-basic-auth.security-basic-auth"
    # Test/example private keys - not production credentials
    "generic.secrets.security.detected-private-key.detected-private-key"
    # Go unsafe in FFI bindings - required for C interop
    "go.lang.security.audit.unsafe.use-of-unsafe-block"
    # Dockerfile USER - best practice but not exploitable vulnerability
    "dockerfile.security.missing-user.missing-user"
    "dockerfile.security.missing-user-entrypoint.missing-user-entrypoint"
    # Android exported activity - required for launcher activities
    "java.android.security.android-exported-activity-handling.android-exported-activity-handling"
    # Logger credential leak - often flags non-sensitive log messages
    "python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure"
)

# Build exclude-rule arguments
EXCLUDE_RULE_ARGS=()
for rule in "${EXCLUDE_RULES[@]}"; do
    EXCLUDE_RULE_ARGS+=("--exclude-rule=$rule")
done

# Build custom rules config arguments
CUSTOM_RULE_ARGS=()
CUSTOM_RULES_INFO=""
if [[ "$USE_CUSTOM_RULES" == true ]]; then
    CUSTOM_RULES_DIR="$(pwd)/custom-rules"
    if [[ -d "$CUSTOM_RULES_DIR" ]]; then
        # Add each custom rule directory
        if [[ -d "$CUSTOM_RULES_DIR/0xdea-semgrep-rules/rules" ]]; then
            CUSTOM_RULE_ARGS+=("--config=$CUSTOM_RULES_DIR/0xdea-semgrep-rules/rules")
            CUSTOM_RULES_INFO+="0xdea-semgrep-rules "
        fi
        if [[ -d "$CUSTOM_RULES_DIR/open-semgrep-rules" ]]; then
            CUSTOM_RULE_ARGS+=("--config=$CUSTOM_RULES_DIR/open-semgrep-rules")
            CUSTOM_RULES_INFO+="open-semgrep-rules "
        fi
        if [[ -d "$CUSTOM_RULES_DIR/web-vulns" ]] && [[ -n "$(ls -A "$CUSTOM_RULES_DIR/web-vulns" 2>/dev/null)" ]]; then
            CUSTOM_RULE_ARGS+=("--config=$CUSTOM_RULES_DIR/web-vulns")
            CUSTOM_RULES_INFO+="web-vulns "
        fi
        if [[ -d "$CUSTOM_RULES_DIR/custom" ]] && [[ -n "$(ls -A "$CUSTOM_RULES_DIR/custom" 2>/dev/null)" ]]; then
            CUSTOM_RULE_ARGS+=("--config=$CUSTOM_RULES_DIR/custom")
            CUSTOM_RULES_INFO+="custom "
        fi
        if [[ -d "$CUSTOM_RULES_DIR/patterns" ]] && [[ -n "$(ls -A "$CUSTOM_RULES_DIR/patterns" 2>/dev/null)" ]]; then
            CUSTOM_RULE_ARGS+=("--config=$CUSTOM_RULES_DIR/patterns")
            CUSTOM_RULES_INFO+="patterns "
        fi
    else
        echo "Note: Custom rules directory not found at $CUSTOM_RULES_DIR"
        echo "To add custom rules:"
        echo "  mkdir -p custom-rules"
        echo "  git clone https://github.com/0xdea/semgrep-rules custom-rules/0xdea-semgrep-rules"
        echo "Or disable with: --no-custom-rules"
        echo ""
    fi
fi

# Get only active (non-archived) repos - archived repos are secrets-only
REPOS=$(get_active_repos "$REPOS_DIR")
REPO_COUNT=$(echo "$REPOS" | grep -c . || echo 0)
ARCHIVED_COUNT=$(count_archived_repos "$REPOS_DIR")

log_verbose "Scanning $REPO_COUNT repositories with Semgrep Pro"
[[ "$ARCHIVED_COUNT" -gt 0 ]] && log_verbose "  (skipping $ARCHIVED_COUNT archived repos - secrets-only)"
log_verbose "Config: p/default + p/secrets (high-confidence, CI-optimized)"
if [[ -n "$CUSTOM_RULES_INFO" ]]; then
    log_verbose "Custom: $CUSTOM_RULES_INFO"
fi
log_verbose "Engine: Pro (cross-file dataflow analysis enabled)"
log_verbose "Filters: severity=ERROR,WARNING | excluding tests/examples/vendor"
log_verbose "Excluded rules: ${#EXCLUDE_RULES[@]} known false-positive patterns"
log_verbose "Results: $RESULTS_DIR/"
log_verbose ""

# Convert repos to array for counting
REPOS_ARRAY=()
while IFS= read -r repo; do
    [[ -n "$repo" ]] && REPOS_ARRAY+=("$repo")
done <<< "$REPOS"

current=0
for repo in "${REPOS_ARRAY[@]}"; do
    name=$(basename "$repo")
    current=$((current + 1))

    if [[ -n "$QUIET_MODE" ]]; then
        log_progress "$current" "$REPO_COUNT" "$name"
    else
        echo "[$name] Scanning..."
    fi

    # Create temp file for semgrep output (will be gzipped)
    tmp_output=$(mktemp)

    # Run semgrep with Pro engine for cross-file dataflow analysis
    # - --pro: Enables cross-file, cross-function taint tracking
    # - p/default: CI-optimized ruleset (replaces p/security-audit which has many FPs)
    # - p/secrets: Secret detection
    # - Excludes test/example/vendor paths
    # - Excludes minified files
    # - Excludes known false-positive rules
    semgrep scan \
        --pro \
        --config=p/default \
        --config=p/secrets \
        ${CUSTOM_RULE_ARGS[@]+"${CUSTOM_RULE_ARGS[@]}"} \
        --severity=ERROR \
        --severity=WARNING \
        --exclude='**/test/**' \
        --exclude='**/tests/**' \
        --exclude='**/__tests__/**' \
        --exclude='**/examples/**' \
        --exclude='**/example/**' \
        --exclude='**/vendor/**' \
        --exclude='**/node_modules/**' \
        --exclude='**/3rdparty/**' \
        --exclude='**/*_test.go' \
        --exclude='**/*_test.py' \
        --exclude='**/test_*.py' \
        --exclude='**/*.min.js' \
        --exclude='**/*.min.css' \
        --exclude='**/*.bundle.js' \
        "${EXCLUDE_RULE_ARGS[@]}" \
        --json \
        --output="$tmp_output" \
        "$repo" 2>&1 | grep -v "^Scanning" | grep -v "^Ran" | grep -v "^Some files" || true

    # Gzip the output
    if [[ -f "$tmp_output" && -s "$tmp_output" ]]; then
        gzip -c "$tmp_output" > "$RESULTS_DIR/$name.json.gz"
        count=$(jq '.results | length' "$tmp_output" 2>/dev/null || echo "0")
        if [[ -z "$QUIET_MODE" ]]; then
            echo "[$name] Found $count findings"
        fi
    else
        if [[ -z "$QUIET_MODE" ]]; then
            echo "[$name] No results"
        fi
    fi
    rm -f "$tmp_output"
done

# Clear progress line if in quiet mode
[[ -n "$QUIET_MODE" ]] && clear_progress

log_verbose ""
log_verbose "=== Summary ==="

# Aggregate results with rule breakdown
total=0
declare -A rule_counts 2>/dev/null || true

for f in "$RESULTS_DIR"/*.json.gz; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f" .json.gz)
    count=$(gzip -dc "$f" | jq '.results | length' 2>/dev/null || echo "0")
    if [[ "$count" -gt 0 ]]; then
        log_verbose "$name: $count findings"
        total=$((total + count))
    fi
done

log_verbose ""
echo "Semgrep: $total findings"

# Show top rules if we have findings
if [[ "$total" -gt 0 ]] && [[ -z "$QUIET_MODE" ]]; then
    echo ""
    echo "Top rules by finding count:"
    for f in "$RESULTS_DIR"/*.json.gz; do
        [[ -f "$f" ]] || continue
        gzip -dc "$f" | jq -r '.results[].check_id' 2>/dev/null
    done | sort | uniq -c | sort -rn | head -10 | while read count rule; do
        echo "  $count  $rule"
    done
fi

log_verbose ""
log_verbose "Results saved to: $RESULTS_DIR/"
log_verbose ""
log_verbose "Extract findings:"
log_verbose "  ./scripts/extract-semgrep-findings.sh $ORG              # Summary view"
log_verbose "  ./scripts/extract-semgrep-findings.sh $ORG full         # Full details"
log_verbose "  ./scripts/extract-semgrep-findings.sh $ORG rules        # By rule ID"
log_verbose ""
log_verbose "Review with Claude:"
log_verbose "  /review-semgrep $ORG"
