# Catalog System Test Suite

This document defines tests for the Bug Bounty Target Catalog System. Run these tests after making changes to verify functionality.

## Quick Test Runner

```bash
# Run all tests
./scripts/test-catalog.sh

# Run specific phase tests
./scripts/test-catalog.sh --phase 2
./scripts/test-catalog.sh --phase 3-6
```

---

## Phase 1: Infrastructure Tests

### Test 1.1: Directory Structure
```bash
# Verify required directories exist
test -d catalog/platforms && echo "PASS: catalog/platforms exists" || echo "FAIL: catalog/platforms missing"
test -d catalog/tracked && echo "PASS: catalog/tracked exists" || echo "FAIL: catalog/tracked missing"
test -f catalog/index.json && echo "PASS: catalog/index.json exists" || echo "FAIL: catalog/index.json missing"
```

### Test 1.2: Index JSON Valid
```bash
# Verify index.json is valid JSON with correct structure
jq -e '.tracked_orgs | type == "array"' catalog/index.json > /dev/null && \
    echo "PASS: index.json has tracked_orgs array" || \
    echo "FAIL: index.json structure invalid"
```

### Test 1.3: .gitignore Configured
```bash
# Verify critical patterns in .gitignore
grep -q "^repos/" .gitignore && echo "PASS: repos/ in .gitignore" || echo "FAIL: repos/ not in .gitignore"
grep -q "^\.env$" .gitignore && echo "PASS: .env in .gitignore" || echo "FAIL: .env not in .gitignore"
```

### Test 1.4: .env.example Exists
```bash
test -f .env.example && echo "PASS: .env.example exists" || echo "FAIL: .env.example missing"
grep -q "HACKERONE_TOKEN" .env.example && echo "PASS: HackerOne token in .env.example" || echo "FAIL"
grep -q "BUGCROWD_TOKEN" .env.example && echo "PASS: Bugcrowd token in .env.example" || echo "FAIL"
```

---

## Phase 2: Library Functions Tests

### Test 2.1: Source Without Error
```bash
source scripts/lib/catalog-utils.sh && echo "PASS: catalog-utils.sh sources cleanly" || echo "FAIL"
```

### Test 2.2: Timestamp Functions
```bash
source scripts/lib/catalog-utils.sh
ts=$(get_scan_timestamp)
[[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}$ ]] && \
    echo "PASS: get_scan_timestamp format correct ($ts)" || \
    echo "FAIL: get_scan_timestamp format wrong ($ts)"

iso=$(get_iso_timestamp)
[[ "$iso" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] && \
    echo "PASS: get_iso_timestamp format correct ($iso)" || \
    echo "FAIL: get_iso_timestamp format wrong ($iso)"
```

### Test 2.3: Path Helpers
```bash
source scripts/lib/catalog-utils.sh
[[ "$(get_org_catalog_dir testorg)" == *"catalog/tracked/testorg"* ]] && \
    echo "PASS: get_org_catalog_dir correct" || echo "FAIL"
[[ "$(get_org_repos_dir testorg)" == *"repos/testorg"* ]] && \
    echo "PASS: get_org_repos_dir correct" || echo "FAIL"
```

### Test 2.4: Index Management (Isolated Test)
```bash
# Create temp index for testing
source scripts/lib/catalog-utils.sh
TEST_INDEX=$(mktemp)
echo '{"tracked_orgs":[]}' > "$TEST_INDEX"
CATALOG_INDEX="$TEST_INDEX"

# Test add
add_to_index "test-org" "hackerone" "https://hackerone.com/test"
jq -e '.tracked_orgs[] | select(.name == "test-org")' "$TEST_INDEX" > /dev/null && \
    echo "PASS: add_to_index works" || echo "FAIL: add_to_index"

# Test is_org_tracked
is_org_tracked "test-org" && echo "PASS: is_org_tracked finds org" || echo "FAIL"
is_org_tracked "nonexistent" && echo "FAIL: found nonexistent" || echo "PASS: is_org_tracked rejects missing"

# Test remove
remove_from_index "test-org"
is_org_tracked "test-org" && echo "FAIL: org still exists" || echo "PASS: remove_from_index works"

rm "$TEST_INDEX"
```

### Test 2.5: JSON Normalization - Semgrep
```bash
source scripts/lib/catalog-utils.sh
TEST_FILE=$(mktemp --suffix=.json)

# Create unsorted semgrep JSON
cat > "$TEST_FILE" << 'EOF'
{
  "results": [
    {"path": "b.py", "start": {"line": 10}, "check_id": "rule1"},
    {"path": "a.py", "start": {"line": 5}, "check_id": "rule2"},
    {"path": "a.py", "start": {"line": 1}, "check_id": "rule1"}
  ]
}
EOF

normalize_semgrep_json "$TEST_FILE"

# Verify sorted: a.py:1, a.py:5, b.py:10
first_path=$(jq -r '.results[0].path' "$TEST_FILE")
[[ "$first_path" == "a.py" ]] && echo "PASS: semgrep normalization sorts correctly" || echo "FAIL: $first_path"

rm "$TEST_FILE"
```

### Test 2.6: JSON Normalization - Trufflehog NDJSON
```bash
source scripts/lib/catalog-utils.sh
TEST_FILE=$(mktemp --suffix=.json)

# Create unsorted NDJSON
cat > "$TEST_FILE" << 'EOF'
{"DetectorName":"AWS","SourceMetadata":{"Data":{"Filesystem":{"file":"z.txt"}}}}
{"DetectorName":"GitHub","SourceMetadata":{"Data":{"Filesystem":{"file":"a.txt"}}}}
EOF

normalize_trufflehog_json "$TEST_FILE"

# Verify sorted by file: a.txt first
first_file=$(head -1 "$TEST_FILE" | jq -r '.SourceMetadata.Data.Filesystem.file')
[[ "$first_file" == "a.txt" ]] && echo "PASS: trufflehog normalization sorts correctly" || echo "FAIL: $first_file"

rm "$TEST_FILE"
```

---

## Phase 3-6: DuckDB Extract Scripts Tests

### Test 3.1: extract-semgrep-findings.sh Help
```bash
./scripts/extract-semgrep-findings.sh --help 2>&1 | grep -q "Usage" && \
    echo "PASS: semgrep extract has help" || echo "FAIL"
```

### Test 3.2: extract-semgrep-findings.sh Missing Org
```bash
./scripts/extract-semgrep-findings.sh nonexistent-org 2>&1 | grep -qi "not found\|error" && \
    echo "PASS: semgrep extract handles missing org" || echo "FAIL"
```

### Test 3.3: extract-semgrep-findings.sh All Formats
```bash
# Only run if we have findings data
ORG=$(ls -1 findings 2>/dev/null | head -1)
if [[ -n "$ORG" && -d "findings/$ORG/semgrep-results" ]]; then
    for fmt in summary full count jsonl rules; do
        ./scripts/extract-semgrep-findings.sh "$ORG" "$fmt" > /dev/null 2>&1 && \
            echo "PASS: semgrep format '$fmt'" || echo "FAIL: semgrep format '$fmt'"
    done
else
    echo "SKIP: No semgrep findings to test formats"
fi
```

### Test 4.1: extract-trufflehog-findings.sh Help
```bash
./scripts/extract-trufflehog-findings.sh --help 2>&1 | grep -q "Usage" && \
    echo "PASS: trufflehog extract has help" || echo "FAIL"
```

### Test 4.2: extract-trufflehog-findings.sh All Formats
```bash
ORG=$(ls -1 findings 2>/dev/null | head -1)
if [[ -n "$ORG" && -d "findings/$ORG/trufflehog-results" ]]; then
    for fmt in summary table json verified detectors repos; do
        ./scripts/extract-trufflehog-findings.sh "$ORG" "$fmt" > /dev/null 2>&1 && \
            echo "PASS: trufflehog format '$fmt'" || echo "FAIL: trufflehog format '$fmt'"
    done
else
    echo "SKIP: No trufflehog findings to test formats"
fi
```

### Test 5.1: extract-kics-findings.sh Help
```bash
./scripts/extract-kics-findings.sh --help 2>&1 | grep -q "Usage" && \
    echo "PASS: kics extract has help" || echo "FAIL"
```

### Test 5.2: extract-kics-findings.sh All Formats
```bash
ORG=$(ls -1 findings 2>/dev/null | head -1)
if [[ -n "$ORG" && -d "findings/$ORG/kics-results" ]]; then
    for fmt in summary table json resources queries repos; do
        ./scripts/extract-kics-findings.sh "$ORG" "$fmt" > /dev/null 2>&1 && \
            echo "PASS: kics format '$fmt'" || echo "FAIL: kics format '$fmt'"
    done
else
    echo "SKIP: No kics findings to test formats"
fi
```

### Test 6.1: extract-artifact-findings.sh Help
```bash
./scripts/extract-artifact-findings.sh --help 2>&1 | grep -q "Usage" && \
    echo "PASS: artifact extract has help" || echo "FAIL"
```

### Test 6.2: extract-artifact-findings.sh All Formats
```bash
ORG=$(ls -1 findings 2>/dev/null | head -1)
if [[ -n "$ORG" && -d "findings/$ORG/artifact-results" ]]; then
    for fmt in summary table json archives databases sql sources repos; do
        ./scripts/extract-artifact-findings.sh "$ORG" "$fmt" > /dev/null 2>&1 && \
            echo "PASS: artifact format '$fmt'" || echo "FAIL: artifact format '$fmt'"
    done
else
    echo "SKIP: No artifact findings to test formats"
fi
```

---

## Phase 7: clone-org-repos.sh Tests

### Test 7.1: Help Text
```bash
./scripts/clone-org-repos.sh --help 2>&1 | grep -q "catalog" && \
    echo "PASS: clone-org-repos.sh documents --catalog flag" || echo "FAIL"
```

### Test 7.2: Catalog Flag Recognition
```bash
# Should not error on flag parsing (may error on missing org which is OK)
./scripts/clone-org-repos.sh --catalog 2>&1 | grep -qi "unknown.*catalog" && \
    echo "FAIL: --catalog flag not recognized" || echo "PASS: --catalog flag recognized"
```

---

## Phase 8: scan-all.sh Tests

### Test 8.1: Help Text
```bash
./scripts/scan-all.sh --help 2>&1 | grep -q "output-dir\|repos-dir" && \
    echo "PASS: scan-all.sh documents new flags" || echo "FAIL"
```

### Test 8.2: Flag Recognition
```bash
# Should not error on flag parsing
./scripts/scan-all.sh --output-dir /tmp/test --repos-dir /tmp/repos 2>&1 | grep -qi "unknown" && \
    echo "FAIL: flags not recognized" || echo "PASS: flags recognized"
```

---

## Phase 9: catalog-track.sh Tests

### Test 9.1: Help Text
```bash
./scripts/catalog-track.sh --help 2>&1 | grep -q "Usage" && \
    echo "PASS: catalog-track.sh has help" || echo "FAIL"
```

### Test 9.2: Invalid Platform Rejection
```bash
./scripts/catalog-track.sh test-org invalidplatform 2>&1 | grep -qi "invalid\|error" && \
    echo "PASS: rejects invalid platform" || echo "FAIL"
```

### Test 9.3: Duplicate Detection
```bash
# Track an org, then try to track again
source scripts/lib/catalog-utils.sh
if is_org_tracked "Dynatrace"; then
    ./scripts/catalog-track.sh Dynatrace hackerone 2>&1 | grep -qi "already tracked" && \
        echo "PASS: detects duplicate org" || echo "FAIL: should detect duplicate"
else
    echo "SKIP: No existing tracked org to test duplicate detection"
fi
```

---

## Phase 10: catalog-scan.sh Tests

### Test 10.1: Help Text
```bash
./scripts/catalog-scan.sh --help 2>&1 | grep -q "Usage" && \
    echo "PASS: catalog-scan.sh has help" || echo "FAIL"
```

### Test 10.2: Untracked Org Rejection
```bash
./scripts/catalog-scan.sh nonexistent-random-org 2>&1 | grep -qi "not tracked" && \
    echo "PASS: rejects untracked org" || echo "FAIL"
```

### Test 10.3: Missing Repos Detection
```bash
# Use a tracked org that has no repos cloned
source scripts/lib/catalog-utils.sh
TRACKED_ORG=$(jq -r '.tracked_orgs[0].name // empty' catalog/index.json)
if [[ -n "$TRACKED_ORG" && ! -d "repos/$TRACKED_ORG" ]]; then
    ./scripts/catalog-scan.sh "$TRACKED_ORG" 2>&1 | grep -qi "not found\|clone first" && \
        echo "PASS: detects missing repos" || echo "FAIL: should detect missing repos"
else
    echo "SKIP: No tracked org without repos to test"
fi
```

---

## Phase 11: catalog-status.sh Tests

### Test 11.1: Basic Execution
```bash
./scripts/catalog-status.sh > /dev/null 2>&1 && \
    echo "PASS: catalog-status.sh runs" || echo "FAIL"
```

### Test 11.2: Output Format
```bash
./scripts/catalog-status.sh 2>&1 | grep -q "ORG\|PLATFORM\|SCANS" && \
    echo "PASS: catalog-status.sh shows expected columns" || echo "FAIL"
```

### Test 11.3: Stale Days Flag
```bash
./scripts/catalog-status.sh --stale-days 1 > /dev/null 2>&1 && \
    echo "PASS: --stale-days flag works" || echo "FAIL"
```

### Test 11.4: Org Detail View
```bash
TRACKED_ORG=$(jq -r '.tracked_orgs[0].name // empty' catalog/index.json)
if [[ -n "$TRACKED_ORG" ]]; then
    ./scripts/catalog-status.sh "$TRACKED_ORG" 2>&1 | grep -qi "$TRACKED_ORG" && \
        echo "PASS: org detail view works" || echo "FAIL"
else
    echo "SKIP: No tracked org for detail view test"
fi
```

---

## Phase 12: catalog-diff.sh Tests

### Test 12.1: Help Text
```bash
./scripts/catalog-diff.sh --help 2>&1 | grep -q "Usage" && \
    echo "PASS: catalog-diff.sh has help" || echo "FAIL"
```

### Test 12.2: Missing Org Handling
```bash
./scripts/catalog-diff.sh nonexistent-org 2>&1 | grep -qi "error\|not found" && \
    echo "PASS: handles missing org" || echo "FAIL"
```

### Test 12.3: Single Scan Warning
```bash
# Find org with scans
TRACKED_ORG=$(jq -r '.tracked_orgs[0].name // empty' catalog/index.json)
if [[ -n "$TRACKED_ORG" ]]; then
    SCAN_COUNT=$(ls -1 "catalog/tracked/$TRACKED_ORG/scans" 2>/dev/null | wc -l | xargs)
    if [[ "$SCAN_COUNT" -lt 2 ]]; then
        ./scripts/catalog-diff.sh "$TRACKED_ORG" 2>&1 | grep -qi "need.*2\|at least" && \
            echo "PASS: warns about single scan" || echo "FAIL: should warn"
    else
        echo "SKIP: Org has multiple scans, can't test single-scan warning"
    fi
else
    echo "SKIP: No tracked org to test"
fi
```

---

## Phase 13: catalog-refresh.sh Tests

### Test 13.1: Help Text
```bash
./scripts/catalog-refresh.sh --help 2>&1 | grep -q "Usage" && \
    echo "PASS: catalog-refresh.sh has help" || echo "FAIL"
```

### Test 13.2: List Platforms
```bash
./scripts/catalog-refresh.sh --list 2>&1 | grep -qi "hackerone\|bugcrowd" && \
    echo "PASS: --list shows platforms" || echo "FAIL"
```

### Test 13.3: Query Function
```bash
# Test query with a known program
./scripts/catalog-refresh.sh --query github 2>&1 | head -20 | grep -qi "github\|scope\|results" && \
    echo "PASS: --query returns results" || echo "FAIL: --query may have no data"
```

### Test 13.4: Stats Function
```bash
./scripts/catalog-refresh.sh --stats 2>&1 | grep -qi "program\|scopes\|platform" && \
    echo "PASS: --stats shows data" || echo "FAIL"
```

### Test 13.5: Missing Token Handling
```bash
# Temporarily unset token and test
(
    unset YESWEHACK_TOKEN
    ./scripts/catalog-refresh.sh yeswehack 2>&1 | grep -qi "not set\|skipping\|not configured" && \
        echo "PASS: handles missing token" || echo "FAIL"
)
```

---

## Phase 14: catalog-untrack.sh Tests

### Test 14.1: Help Text
```bash
./scripts/catalog-untrack.sh --help 2>&1 | grep -q "Usage" && \
    echo "PASS: catalog-untrack.sh has help" || echo "FAIL"
```

### Test 14.2: Missing Org Handling
```bash
./scripts/catalog-untrack.sh nonexistent-random-org 2>&1 | grep -qi "not tracked" && \
    echo "PASS: handles untracked org" || echo "FAIL"
```

### Test 14.3: Flags Recognition
```bash
# Test that flags are recognized (will fail on org lookup, but shouldn't fail on flags)
./scripts/catalog-untrack.sh test --delete-scans --delete-repos --force 2>&1 | grep -qi "unknown.*option" && \
    echo "FAIL: flags not recognized" || echo "PASS: flags recognized"
```

---

## Integration Tests

### Integration Test 1: Full Workflow (Dry Run)
```bash
echo "=== Integration Test: Full Workflow ==="

TEST_ORG="__test_org_$$"

# Track
./scripts/catalog-track.sh "$TEST_ORG" other --program-url "https://example.com" > /dev/null 2>&1
source scripts/lib/catalog-utils.sh
is_org_tracked "$TEST_ORG" && echo "PASS: Track created org" || echo "FAIL: Track"

# Status shows it
./scripts/catalog-status.sh 2>&1 | grep -q "$TEST_ORG" && \
    echo "PASS: Status shows org" || echo "FAIL: Status"

# Untrack
./scripts/catalog-untrack.sh "$TEST_ORG" --delete-all --force > /dev/null 2>&1
is_org_tracked "$TEST_ORG" && echo "FAIL: Untrack" || echo "PASS: Untrack removed org"

echo "=== Integration Test Complete ==="
```

### Integration Test 2: DuckDB Cross-Org Query
```bash
echo "=== Integration Test: DuckDB Cross-Org Query ==="

# Query across all orgs (if any have findings)
if ls findings/*/semgrep-results/*.json 2>/dev/null | head -1 | grep -q json; then
    duckdb -c "
        SELECT count(*) as total_findings
        FROM read_json('findings/*/semgrep-results/*.json')
        CROSS JOIN UNNEST(results)
    " 2>/dev/null && echo "PASS: Cross-org DuckDB query works" || echo "FAIL"
else
    echo "SKIP: No findings for cross-org query test"
fi
```

---

## Edge Case Tests

### Edge Case 1: Empty Results Handling
```bash
# Create empty results directory and test extraction
TEST_DIR=$(mktemp -d)
mkdir -p "$TEST_DIR/semgrep-results"
echo '{"results":[]}' > "$TEST_DIR/semgrep-results/empty.json"

# Should not crash on empty
FINDINGS_DIR="$TEST_DIR" ./scripts/extract-semgrep-findings.sh test summary 2>&1 | \
    grep -qi "error\|crash" && echo "FAIL: crashes on empty" || echo "PASS: handles empty results"

rm -rf "$TEST_DIR"
```

### Edge Case 2: Special Characters in Org Name
```bash
# Should reject invalid org names
./scripts/catalog-track.sh "org with spaces" hackerone 2>&1 | grep -qi "invalid\|error" && \
    echo "PASS: rejects spaces in org name" || echo "FAIL"

./scripts/catalog-track.sh "org/slash" hackerone 2>&1 | grep -qi "invalid\|error" && \
    echo "PASS: rejects slashes in org name" || echo "FAIL"
```

### Edge Case 3: Large JSON Handling
```bash
echo "=== Edge Case: Large JSON Performance ==="
# Check if we have platform data to test
if [[ -f catalog/platforms/hackerone.json ]]; then
    time (
        duckdb -c "SELECT count(*) FROM read_json('catalog/platforms/hackerone.json'), UNNEST(scopes)" 2>/dev/null
    ) && echo "PASS: Large JSON query completes" || echo "FAIL"
else
    echo "SKIP: No platform data for large JSON test"
fi
```

---

## Running All Tests

Save this as a runnable script:

```bash
#!/usr/bin/env bash
# scripts/test-catalog.sh - Run catalog system tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

PHASE="${1:-all}"

echo "========================================"
echo "Catalog System Test Suite"
echo "========================================"
echo ""

PASS=0
FAIL=0
SKIP=0

run_test() {
    local result
    result=$(eval "$1" 2>&1)
    if echo "$result" | grep -q "^PASS"; then
        ((PASS++))
        echo "$result"
    elif echo "$result" | grep -q "^FAIL"; then
        ((FAIL++))
        echo "$result"
    elif echo "$result" | grep -q "^SKIP"; then
        ((SKIP++))
        echo "$result"
    fi
}

# Run tests based on phase selection
# (Add test calls here)

echo ""
echo "========================================"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "========================================"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

---

## Known Issues and Workarounds

### Issue: DuckDB NDJSON Format
- **Problem**: `regexp_extract` returns empty string instead of NULL
- **Solution**: Use `NULLIF(regexp_extract(...), '')` to convert to NULL for COALESCE

### Issue: Bugcrowd URL Parsing
- **Problem**: Bugcrowd uses `/engagements/<program>` URL format
- **Solution**: Include both patterns in regex: `bugcrowd.com/engagements/([^/]+)` and `bugcrowd.com/([^/]+)`

### Issue: Shell != Operator in DuckDB
- **Problem**: `!=` can cause parse errors in shell-embedded DuckDB queries
- **Solution**: Use `<>` instead of `!=`

### Issue: bbscope Bugcrowd Email/Password Auth
- **Problem**: Email/password auth fails with "redirect_to not found" error
- **Solution**: Use session token method (extract `_crowdcontrol_session_key` cookie from browser)

### Issue: 2fa Utility Not in PATH
- **Problem**: Go binaries install to ~/go/bin which may not be in PATH
- **Solution**: Check both `command -v 2fa` and `$HOME/go/bin/2fa`

### Issue: grep -q with pipefail Causes SIGPIPE
- **Problem**: `cmd | grep -q pattern && echo PASS` with `set -o pipefail` fails with exit 141
- **Cause**: `grep -q` closes the pipe immediately after finding a match, causing SIGPIPE to the writing process
- **Solution**: Don't use pipefail in test scripts, or use `grep pattern > /dev/null` instead of `grep -q`
