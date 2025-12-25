#!/usr/bin/env bash
# Catalog System Test Runner
#
# Usage:
#   ./scripts/test-catalog.sh           # Run all tests
#   ./scripts/test-catalog.sh --phase 2 # Run Phase 2 tests only
#   ./scripts/test-catalog.sh --quick   # Run quick smoke tests only

set -u
# Note: We don't use -e or pipefail because tests may intentionally fail
# and grep -q with pipefail causes SIGPIPE issues

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

PHASE="${1:-all}"
PASS=0
FAIL=0
SKIP=0

# Test helper
run_test() {
    local name="$1"
    local cmd="$2"

    local result
    if result=$(eval "$cmd" 2>&1); then
        if echo "$result" | grep -q "PASS"; then
            ((PASS++))
            echo -e "  ${GREEN}PASS${NC}: $name"
        elif echo "$result" | grep -q "SKIP"; then
            ((SKIP++))
            echo -e "  ${YELLOW}SKIP${NC}: $name"
        else
            ((PASS++))
            echo -e "  ${GREEN}PASS${NC}: $name"
        fi
    else
        if echo "$result" | grep -q "SKIP"; then
            ((SKIP++))
            echo -e "  ${YELLOW}SKIP${NC}: $name"
        else
            ((FAIL++))
            echo -e "  ${RED}FAIL${NC}: $name"
            echo "       $result" | head -3
        fi
    fi
}

# Phase 1: Infrastructure
test_phase_1() {
    echo ""
    echo "Phase 1: Infrastructure"
    echo "----------------------------------------"

    run_test "catalog/platforms exists" \
        '[[ -d catalog/platforms ]] && echo PASS'

    run_test "catalog/tracked exists" \
        '[[ -d catalog/tracked ]] && echo PASS'

    run_test "catalog/index.json exists" \
        '[[ -f catalog/index.json ]] && echo PASS'

    run_test "index.json valid structure" \
        'jq -e ".tracked_orgs | type == \"array\"" catalog/index.json > /dev/null && echo PASS'

    run_test "repos/ in .gitignore" \
        'grep -q "^repos/" .gitignore && echo PASS'

    run_test ".env in .gitignore" \
        'grep -q "^\.env$" .gitignore && echo PASS'

    run_test ".env.example exists" \
        '[[ -f .env.example ]] && echo PASS'
}

# Phase 2: Library Functions
test_phase_2() {
    echo ""
    echo "Phase 2: Library Functions"
    echo "----------------------------------------"

    run_test "catalog-utils.sh sources cleanly" \
        'source scripts/lib/catalog-utils.sh && echo PASS'

    run_test "get_scan_timestamp format" \
        'source scripts/lib/catalog-utils.sh; ts=$(get_scan_timestamp); [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}$ ]] && echo PASS'

    run_test "get_iso_timestamp format" \
        'source scripts/lib/catalog-utils.sh; ts=$(get_iso_timestamp); [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] && echo PASS'

    run_test "get_org_catalog_dir returns path" \
        'source scripts/lib/catalog-utils.sh; [[ "$(get_org_catalog_dir testorg)" == *"catalog/tracked/testorg"* ]] && echo PASS'

    run_test "validate_org_name rejects spaces" \
        'source scripts/lib/catalog-utils.sh; validate_org_name "bad name" 2>/dev/null && echo FAIL || echo PASS'

    run_test "validate_org_name accepts valid" \
        'source scripts/lib/catalog-utils.sh; validate_org_name "valid-org_123" && echo PASS'
}

# Phase 3-6: DuckDB Extract Scripts
test_phase_3_6() {
    echo ""
    echo "Phase 3-6: DuckDB Extract Scripts"
    echo "----------------------------------------"

    # Scripts show usage when called with no args (not --help)
    run_test "extract-semgrep-findings.sh shows usage" \
        './scripts/extract-semgrep-findings.sh 2>&1 | grep -q Usage && echo PASS'

    run_test "extract-trufflehog-findings.sh shows usage" \
        './scripts/extract-trufflehog-findings.sh 2>&1 | grep -q Usage && echo PASS'

    run_test "extract-kics-findings.sh shows usage" \
        './scripts/extract-kics-findings.sh 2>&1 | grep -q Usage && echo PASS'

    run_test "extract-artifact-findings.sh shows usage" \
        './scripts/extract-artifact-findings.sh 2>&1 | grep -q Usage && echo PASS'

    run_test "extract-semgrep missing org error" \
        './scripts/extract-semgrep-findings.sh nonexistent 2>&1 | grep -qi "not found\|error" && echo PASS'

    run_test "extract-trufflehog missing org error" \
        './scripts/extract-trufflehog-findings.sh nonexistent 2>&1 | grep -qi "not found\|error" && echo PASS'

    # Test formats if we have data (use actual supported formats)
    local ORG
    ORG=$(ls -1 findings 2>/dev/null | head -1 || echo "")
    if [[ -n "$ORG" && -d "findings/$ORG/semgrep-results" ]]; then
        for fmt in summary full count jsonl rules; do
            run_test "semgrep format: $fmt" \
                "./scripts/extract-semgrep-findings.sh '$ORG' '$fmt' > /dev/null 2>&1 && echo PASS"
        done
    else
        echo -e "  ${YELLOW}SKIP${NC}: No findings data for format tests"
        ((SKIP++))
    fi
}

# Phase 7-8: Modified Scripts
test_phase_7_8() {
    echo ""
    echo "Phase 7-8: Modified Scripts"
    echo "----------------------------------------"

    run_test "clone-org-repos.sh --help shows --standalone" \
        './scripts/clone-org-repos.sh --help 2>&1 | grep -q standalone && echo PASS'

    run_test "catalog-scan.sh --help shows --no-catalog" \
        './scripts/catalog-scan.sh --help 2>&1 | grep -q no-catalog && echo PASS'

    run_test "catalog-scan.sh --help shows --repos-dir" \
        './scripts/catalog-scan.sh --help 2>&1 | grep -q repos-dir && echo PASS'

    run_test "hunt.sh --help shows platform argument" \
        './scripts/hunt.sh --help 2>&1 | grep -q platform && echo PASS'
}

# Phase 9-14: Catalog Scripts
test_phase_9_14() {
    echo ""
    echo "Phase 9-14: Catalog Scripts"
    echo "----------------------------------------"

    run_test "catalog-track.sh --help" \
        './scripts/catalog-track.sh --help 2>&1 | grep -q Usage && echo PASS'

    run_test "catalog-track.sh rejects invalid platform" \
        './scripts/catalog-track.sh test invalidplatform 2>&1 | grep -qi "invalid\|error" && echo PASS'

    run_test "catalog-scan.sh --help" \
        './scripts/catalog-scan.sh --help 2>&1 | grep -q Usage && echo PASS'

    run_test "catalog-scan.sh rejects untracked org" \
        './scripts/catalog-scan.sh nonexistent 2>&1 | grep -qi "not tracked" && echo PASS'

    run_test "catalog-status.sh runs" \
        './scripts/catalog-status.sh > /dev/null 2>&1 && echo PASS'

    run_test "catalog-status.sh shows columns" \
        './scripts/catalog-status.sh 2>&1 | grep -q "ORG\|PLATFORM" && echo PASS'

    run_test "catalog-diff.sh --help" \
        './scripts/catalog-diff.sh --help 2>&1 | grep -q Usage && echo PASS'

    run_test "catalog-diff.sh handles missing org" \
        './scripts/catalog-diff.sh nonexistent 2>&1 | grep -qi "error\|not found" && echo PASS'

    run_test "catalog-refresh.sh --help" \
        './scripts/catalog-refresh.sh --help 2>&1 | grep -q Usage && echo PASS'

    run_test "catalog-refresh.sh --list" \
        './scripts/catalog-refresh.sh --list 2>&1 | grep -qi "hackerone\|bugcrowd" && echo PASS'

    run_test "catalog-untrack.sh --help" \
        './scripts/catalog-untrack.sh --help 2>&1 | grep -q Usage && echo PASS'

    run_test "catalog-untrack.sh handles missing org" \
        './scripts/catalog-untrack.sh nonexistent 2>&1 | grep -qi "not tracked" && echo PASS'

    run_test "catalog-query.sh --help" \
        './scripts/catalog-query.sh --help 2>&1 | grep -q Usage && echo PASS'

    run_test "catalog-query.sh search" \
        './scripts/catalog-query.sh stripe --limit 5 2>&1 | grep -qi stripe && echo PASS'

    run_test "catalog-query.sh --type github" \
        './scripts/catalog-query.sh --type github --format programs --limit 5 2>&1 | grep -qi "hackerone\|bugcrowd" && echo PASS'

    run_test "catalog-query.sh --format orgs" \
        './scripts/catalog-query.sh --type github --format orgs --limit 5 2>&1 | grep -q "[A-Za-z]" && echo PASS'
}

# Integration Tests
test_integration() {
    echo ""
    echo "Integration Tests"
    echo "----------------------------------------"

    # Full workflow test with temp org
    local TEST_ORG="__test_org_$$"

    run_test "Track temp org" \
        "./scripts/catalog-track.sh '$TEST_ORG' other --program-url 'https://example.com' > /dev/null 2>&1 && echo PASS"

    run_test "Status shows temp org" \
        "./scripts/catalog-status.sh 2>&1 | grep -q '$TEST_ORG' && echo PASS"

    run_test "Untrack temp org" \
        "./scripts/catalog-untrack.sh '$TEST_ORG' --delete-all --force > /dev/null 2>&1 && echo PASS"

    run_test "Temp org removed from index" \
        "! ./scripts/catalog-status.sh 2>&1 | grep -q '$TEST_ORG' && echo PASS"
}

# Edge Case Tests
test_edge_cases() {
    echo ""
    echo "Edge Case Tests"
    echo "----------------------------------------"

    run_test "Reject org name with spaces" \
        './scripts/catalog-track.sh "bad name" hackerone 2>&1 | grep -qi "invalid\|error" && echo PASS'

    run_test "Reject org name with slashes" \
        './scripts/catalog-track.sh "bad/name" hackerone 2>&1 | grep -qi "invalid\|error" && echo PASS'

    # Test DuckDB is available
    run_test "DuckDB installed" \
        'command -v duckdb && echo PASS'

    run_test "jq installed" \
        'command -v jq && echo PASS'
}

# Quick smoke test
test_quick() {
    echo ""
    echo "Quick Smoke Tests"
    echo "----------------------------------------"

    run_test "catalog-utils.sh loads" \
        'source scripts/lib/catalog-utils.sh && echo PASS'

    run_test "catalog-status.sh runs" \
        './scripts/catalog-status.sh > /dev/null 2>&1 && echo PASS'

    run_test "catalog-refresh.sh --list" \
        './scripts/catalog-refresh.sh --list > /dev/null 2>&1 && echo PASS'

    run_test "extract scripts have help" \
        './scripts/extract-semgrep-findings.sh --help 2>&1 | grep -q Usage && echo PASS'
}

# Main
echo "========================================"
echo "Catalog System Test Suite"
echo "========================================"

case "$PHASE" in
    --quick)
        test_quick
        ;;
    --phase)
        case "${2:-}" in
            1) test_phase_1 ;;
            2) test_phase_2 ;;
            3|4|5|6|3-6) test_phase_3_6 ;;
            7|8|7-8) test_phase_7_8 ;;
            9|10|11|12|13|14|9-14) test_phase_9_14 ;;
            integration) test_integration ;;
            edge) test_edge_cases ;;
            *) echo "Unknown phase: ${2:-}"; exit 1 ;;
        esac
        ;;
    all|*)
        test_phase_1
        test_phase_2
        test_phase_3_6
        test_phase_7_8
        test_phase_9_14
        test_integration
        test_edge_cases
        ;;
esac

# Summary
echo ""
echo "========================================"
echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
echo "========================================"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
