# Test Semgrep Rule Skill

Evaluate Semgrep rules against known-vulnerable repositories to measure true/false positive rates.

## When to Use This Skill

Use `/test-semgrep-rule` when:
- You've created a new CVE rule and want to validate it
- You need to measure a rule's false positive rate
- You want to test a rule against standardized benchmarks
- You need to verify a rule catches known vulnerabilities

## Skill Workflow

### Phase 1: Identify Test Target

Based on the rule's language and vulnerability type, select appropriate test repositories:

| Language | Repository | Vulnerability Types |
|----------|-----------|---------------------|
| Java | OWASP WebGoat | SQLi, XSS, XXE, Auth |
| Java | OWASP Benchmark | Standardized metrics |
| PHP | DVWA | SQLi, XSS, LFI, CSRF |
| Node.js | OWASP Juice Shop | Modern JS vulns |
| Python | Damn Vulnerable Python | Python-specific |
| Ruby | RailsGoat | Rails vulns |

See `resources/test-repositories.md` for full catalog and setup instructions.

### Phase 2: Setup Test Environment

**Option A: Docker (Recommended)**
```bash
# Quick start - no build required
docker run -d -p 8080:8080 webgoat/webgoat
docker run -d -p 80:80 vulnerables/web-dvwa
docker run -d -p 3000:3000 bkimminich/juice-shop
```

**Option B: Clone Repository**
```bash
git clone https://github.com/OWASP/WebGoat.git
cd WebGoat
git checkout <specific-version>  # For reproducibility
```

### Phase 3: Run Rule Against Vulnerable Code

```bash
# Test rule against vulnerable repo
semgrep --config custom-rules/cve/CVE-YYYY-NNNNN.yaml \
        /path/to/vulnerable-repo/ \
        --json > findings.json

# Count findings
jq '.results | length' findings.json

# View findings summary
jq -r '.results[] | "\(.path):\(.start.line) - \(.check_id)"' findings.json
```

### Phase 4: Evaluate Results

**True Positive (TP):** Rule correctly identified a real vulnerability
**False Positive (FP):** Rule flagged safe code as vulnerable
**False Negative (FN):** Rule missed a real vulnerability

**Evaluation Process:**
1. For each finding, determine if it's a real vulnerability
2. Check known vulnerable locations to verify detection
3. Calculate metrics:
   - Precision = TP / (TP + FP)
   - Recall = TP / (TP + FN)
   - FP Rate = FP / (FP + TN)

**Target Metrics:**
| Rule Confidence | Target FP Rate | Target Recall |
|-----------------|---------------|---------------|
| HIGH | < 5% | > 80% |
| MEDIUM | < 20% | > 60% |
| LOW | < 40% | > 40% |

### Phase 5: Test Against Fixed Version

If testing a CVE rule:

```bash
# 1. Test against vulnerable version
git checkout <commit-before-fix>
semgrep --config rule.yaml . --json | jq '.results | length'
# Expected: >= 1 finding

# 2. Test against fixed version
git checkout <commit-after-fix>
semgrep --config rule.yaml . --json | jq '.results | length'
# Expected: 0 findings (or fewer than before)
```

### Phase 6: Generate Evaluation Report

Create a markdown report summarizing the evaluation:

```markdown
# Rule Evaluation: cve-YYYY-NNNNN-vuln-type

## Test Environment
- Repository: OWASP WebGoat
- Version: 8.2.2
- Rule file: custom-rules/cve/CVE-YYYY-NNNNN.yaml

## Results

### Findings Summary
- Total findings: 15
- True positives: 12
- False positives: 3
- Known vulnerabilities missed: 1

### Metrics
- Precision: 80% (12/15)
- FP Rate: 20% (3/15)

### False Positive Analysis
1. `src/test/java/...` - Test fixture, exclude test paths
2. `src/main/.../SafeQuery.java` - Custom sanitizer not recognized

### Recommendations
1. Add test path exclusions
2. Add `SafeQuery.build()` as sanitizer
3. Confidence should be MEDIUM until FP rate < 10%
```

## Resource Files

| File | Purpose |
|------|---------|
| `resources/test-repositories.md` | Catalog of vulnerable repos |
| `resources/evaluation-criteria.md` | TP/FP definitions |
| `resources/docker-commands.md` | Quick start Docker commands |

## OWASP Benchmark Integration

For standardized metrics, use OWASP Benchmark:

```bash
# Clone and build
git clone https://github.com/OWASP/Benchmark.git
cd Benchmark
./mvnw compile

# Run Semgrep
semgrep --config custom-rules/ src/main/java/ --json > semgrep-results.json

# Compare against ground truth (Benchmark provides expected results)
# See: https://owasp.org/www-project-benchmark/
```

## Example Usage

```
User: Test my new SQL injection rule against known vulnerable apps

Claude: I'll evaluate your rule against OWASP WebGoat and Benchmark.

[Sets up WebGoat via Docker]
[Runs rule: semgrep --config rule.yaml /webgoat/]
[Analyzes 25 findings]
[Verifies 20 are in known vulnerable locations]
[Identifies 5 false positives in test code]

Results:
- True Positives: 20
- False Positives: 5
- FP Rate: 20%

Recommendations:
1. Add path exclusion for src/test/
2. Add sanitizer for PreparedStatement usage
3. Current confidence: MEDIUM
```

## Integration with pattern-to-rule

After creating a rule with `/pattern-to-rule`, use `/test-semgrep-rule` to:

1. Validate the rule catches the specific CVE
2. Measure false positive rate
3. Refine sanitizers based on FP analysis
4. Set appropriate confidence level
