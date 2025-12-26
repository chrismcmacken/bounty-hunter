# Extraction Script Test Plan

Verification tests to ensure extraction scripts display all findings without truncation.

## Root Cause

DuckDB's default terminal display truncates output to ~40 rows. Combined with sorting by repo name (alphabetically), findings in repos starting with later letters were being hidden.

## Fixes Applied

1. **Sort by severity first** - All scripts now sort by severity before repo name
2. **No row truncation** - Added `run_duckdb()` function with `.maxrows -1`
3. **Review skill updates** - Added count verification steps to all review skills

## Test Cases

### Test 1: Count Verification

For each script, verify that the total in summary output matches the sum of individual repo counts.

```bash
# Semgrep
count_sum=$(./scripts/extract-semgrep-findings.sh <org> count 2>/dev/null | tail -n +3 | awk '{sum += $NF} END {print sum}')
summary_total=$(./scripts/extract-semgrep-findings.sh <org> 2>/dev/null | grep "^Total:" | awk '{print $2}')
[[ "$count_sum" == "$summary_total" ]] && echo "PASS" || echo "FAIL: count=$count_sum, summary=$summary_total"

# Trufflehog
count_sum=$(./scripts/extract-trufflehog-findings.sh <org> count 2>/dev/null | tail -n +3 | awk '{sum += $3} END {print sum}')
summary_total=$(./scripts/extract-trufflehog-findings.sh <org> 2>/dev/null | grep "^Total:" | awk '{print $2}')
[[ "$count_sum" == "$summary_total" ]] && echo "PASS" || echo "FAIL: count=$count_sum, summary=$summary_total"

# KICS (count total column)
count_sum=$(./scripts/extract-kics-findings.sh <org> count 2>/dev/null | tail -n +3 | awk '{sum += $3} END {print sum}')
summary_total=$(./scripts/extract-kics-findings.sh <org> 2>/dev/null | grep "^Total:" | awk '{print $2}')
[[ "$count_sum" == "$summary_total" ]] && echo "PASS" || echo "FAIL: count=$count_sum, summary=$summary_total"

# Artifacts (more complex - 4 categories)
./scripts/extract-artifact-findings.sh <org> count
# Manually verify the totals line matches sum of columns
```

### Test 2: Severity Sort Order

Verify ERROR/HIGH findings appear before WARNING/MEDIUM/LOW.

```bash
# Semgrep - first non-header line should be ERROR (if any exist)
./scripts/extract-semgrep-findings.sh <org> 2>/dev/null | head -10
# Verify: First data rows show "ERROR" in severity column

# KICS - first non-header line should be HIGH (if any exist)
./scripts/extract-kics-findings.sh <org> 2>/dev/null | head -10
# Verify: First data rows show "HIGH" in severity column

# Trufflehog - verified secrets should appear first
./scripts/extract-trufflehog-findings.sh <org> 2>/dev/null | head -10
# Verify: First data rows show "[VERIFIED]" if any verified secrets exist
```

### Test 3: All Rows Displayed

For an org with known finding counts, verify no "(N shown)" truncation message.

```bash
# Check for truncation message
./scripts/extract-semgrep-findings.sh <org> 2>/dev/null | grep "shown)"
# Should return nothing (no truncation)

./scripts/extract-kics-findings.sh <org> 2>/dev/null | grep "shown)"
# Should return nothing
```

### Test 4: Specific Repo Filter

Verify single-repo queries work correctly.

```bash
# Get one repo name from count output
repo=$(./scripts/extract-semgrep-findings.sh <org> count 2>/dev/null | tail -n +3 | head -1 | awk '{print $1}')

# Query that specific repo
./scripts/extract-semgrep-findings.sh <org> summary "$repo"
# Should show only findings from that repo
```

### Test 5: GitHub Actions Findings Visible

Specific test for the issue that triggered this fix.

```bash
# Semgrep should show GitHub Actions shell injection findings
./scripts/extract-semgrep-findings.sh wise 2>/dev/null | grep -i "shell-injection\|run-shell"
# Should show sanitize-branch-name and download-repo-artifact findings

# These should appear in the first 30 lines (ERROR severity)
./scripts/extract-semgrep-findings.sh wise 2>/dev/null | head -30 | grep -i "shell-injection"
# Should find at least one match
```

## Automated Test Script

Create `scripts/test-extraction.sh`:

```bash
#!/usr/bin/env bash
# Test extraction scripts for truncation and sort order issues

set -euo pipefail

ORG="${1:-wise}"
PASS=0
FAIL=0

echo "Testing extraction scripts for org: $ORG"
echo ""

# Test 1: Semgrep count matches summary
echo -n "Test 1: Semgrep count verification... "
count_sum=$(./scripts/extract-semgrep-findings.sh "$ORG" count 2>/dev/null | grep -E "^\│" | awk -F'│' '{sum += $3} END {print sum+0}')
summary_total=$(./scripts/extract-semgrep-findings.sh "$ORG" 2>/dev/null | grep "^Total:" | awk '{print $2}')
if [[ "$count_sum" == "$summary_total" ]]; then
    echo "PASS ($count_sum findings)"
    ((PASS++))
else
    echo "FAIL (count=$count_sum, summary=$summary_total)"
    ((FAIL++))
fi

# Test 2: Semgrep severity sort order
echo -n "Test 2: Semgrep ERROR findings first... "
first_severity=$(./scripts/extract-semgrep-findings.sh "$ORG" 2>/dev/null | grep -E "^\│" | head -1 | awk -F'│' '{print $3}' | xargs)
if [[ "$first_severity" == "ERROR" ]] || [[ -z "$first_severity" ]]; then
    echo "PASS"
    ((PASS++))
else
    echo "FAIL (first severity: $first_severity)"
    ((FAIL++))
fi

# Test 3: No truncation message
echo -n "Test 3: No row truncation... "
if ./scripts/extract-semgrep-findings.sh "$ORG" 2>/dev/null | grep -q "shown)"; then
    echo "FAIL (found truncation message)"
    ((FAIL++))
else
    echo "PASS"
    ((PASS++))
fi

# Test 4: GitHub Actions findings visible (if wise org)
if [[ "$ORG" == "wise" ]]; then
    echo -n "Test 4: GitHub Actions shell injection visible... "
    if ./scripts/extract-semgrep-findings.sh wise 2>/dev/null | grep -qi "shell-injection"; then
        echo "PASS"
        ((PASS++))
    else
        echo "FAIL (shell injection not found)"
        ((FAIL++))
    fi
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
exit $FAIL
```

## Known Issues

1. **extract-inventory.sh** - Standalone script, doesn't use run_duckdb(). Lower priority as it's not security-critical.

2. **Catalog mode** - Some extraction scripts behave differently in `--catalog` mode. Test both modes.

3. **Empty repos** - Scripts should handle repos with 0 findings gracefully.

## Regression Prevention

When modifying extraction scripts:

1. Always use `run_duckdb()` function for display queries
2. Sort by severity/priority BEFORE repo name
3. Run the test script on a known org before committing
4. Verify count verification still works in review skills
