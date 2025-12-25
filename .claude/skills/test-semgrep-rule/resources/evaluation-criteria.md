# Rule Evaluation Criteria

Standards for evaluating Semgrep rule effectiveness.

---

## Classification Definitions

### True Positive (TP)
A finding that correctly identifies a real vulnerability.

**Criteria:**
- The flagged code IS actually vulnerable
- The vulnerability type matches what the rule claims to detect
- An attacker COULD exploit this in a realistic scenario

### False Positive (FP)
A finding that incorrectly flags safe code as vulnerable.

**Common causes:**
- Test/fixture code flagged
- Custom sanitizers not recognized
- Framework-provided safety not recognized
- Dead code flagged
- Hardcoded safe values flagged

### False Negative (FN)
A real vulnerability that the rule failed to detect.

**Common causes:**
- Unusual code pattern not covered
- Cross-file data flow
- Dynamic dispatch
- Obfuscated patterns
- Framework-specific patterns not covered

### True Negative (TN)
Safe code correctly NOT flagged.

---

## Metrics Calculations

### Precision (Positive Predictive Value)
```
Precision = TP / (TP + FP)
```
*"Of the things flagged, how many were real?"*

### Recall (Sensitivity)
```
Recall = TP / (TP + FN)
```
*"Of the real vulns, how many did we find?"*

### False Positive Rate
```
FPR = FP / (FP + TN)
```
*"Of the safe code, how much did we incorrectly flag?"*

### F1 Score
```
F1 = 2 * (Precision * Recall) / (Precision + Recall)
```
*"Balanced measure of precision and recall"*

---

## Target Metrics by Confidence Level

### HIGH Confidence Rules
Used for: Blocking in CI/CD, automated remediation

| Metric | Target |
|--------|--------|
| Precision | > 95% |
| FP Rate | < 5% |
| Recall | > 80% |

### MEDIUM Confidence Rules
Used for: PR comments, security review queue

| Metric | Target |
|--------|--------|
| Precision | > 80% |
| FP Rate | < 20% |
| Recall | > 60% |

### LOW Confidence Rules
Used for: Security audits, manual triage

| Metric | Target |
|--------|--------|
| Precision | > 60% |
| FP Rate | < 40% |
| Recall | > 40% |

---

## Evaluation Process

### Step 1: Run Rule
```bash
semgrep --config rule.yaml target/ --json > findings.json
```

### Step 2: Extract Findings
```bash
jq -r '.results[] | "\(.path):\(.start.line) - \(.extra.message)"' findings.json
```

### Step 3: Classify Each Finding

For each finding, determine:
1. Is this code actually reachable?
2. Does user input reach this point?
3. Is there sanitization the rule missed?
4. Would exploitation be possible?

### Step 4: Check Known Vulnerabilities

If testing against intentionally vulnerable apps:
1. List known vulnerable locations (from documentation)
2. Verify rule detects each one
3. Note any missed (false negatives)

### Step 5: Calculate Metrics

```python
TP = 12  # Real vulns detected
FP = 3   # Safe code flagged
FN = 2   # Real vulns missed
TN = 100 # Safe code not flagged (estimate)

precision = TP / (TP + FP)        # 0.80
recall = TP / (TP + FN)           # 0.857
fpr = FP / (FP + TN)              # 0.029
f1 = 2 * precision * recall / (precision + recall)  # 0.828
```

---

## False Positive Categories

When analyzing FPs, categorize them:

### Category 1: Test Code
```
Finding in: test/fixtures/vulnerable_sample.py
Reason: Intentionally vulnerable test fixture
Action: Add path exclusion
```

### Category 2: Unrecognized Sanitizer
```
Finding in: src/api/users.py:45
Reason: Custom sanitizer `company_validate()` not recognized
Action: Add as pattern-sanitizer
```

### Category 3: Framework Safety
```
Finding in: src/views/list.py:23
Reason: Django ORM query flagged, but ORM is parameterized
Action: Add ORM pattern as sanitizer
```

### Category 4: Dead Code
```
Finding in: src/legacy/old_handler.py:100
Reason: Function never called, behind feature flag
Action: Likely acceptable FP, note in rule
```

### Category 5: Hardcoded Values
```
Finding in: src/config/defaults.py:15
Reason: Hardcoded string constant flagged as tainted
Action: Add pattern-not for string literals
```

---

## False Negative Categories

When analyzing FNs, categorize them:

### Category 1: Cross-File Flow
```
Missed: User input in views.py reaches sink in models.py
Reason: Requires interfile analysis
Action: Enable `interfile: true` (requires --pro)
```

### Category 2: Indirect Flow
```
Missed: Input assigned to object attribute, later used in sink
Reason: Taint lost through object assignment
Action: Add propagator pattern
```

### Category 3: Unusual Pattern
```
Missed: SQL built with string.Template instead of f-string
Reason: Pattern not in sink list
Action: Add variant sink pattern
```

### Category 4: Framework-Specific
```
Missed: FastAPI request body via Pydantic model
Reason: Source pattern doesn't cover Pydantic
Action: Add FastAPI/Pydantic sources
```

---

## Evaluation Report Template

```markdown
# Rule Evaluation Report

## Rule Information
- Rule ID: cve-2024-12345-sql-injection
- Language: Python
- Vulnerability Type: SQL Injection (CWE-89)

## Test Environment
- Repository: OWASP WebGoat / PyGoat / Custom
- Version: X.Y.Z
- Commit: abc123

## Quantitative Results

| Metric | Value |
|--------|-------|
| Total Findings | 25 |
| True Positives | 20 |
| False Positives | 5 |
| Known Vulns Missed | 2 |
| Precision | 80% |
| Recall | 91% |
| FP Rate | 20% |

## False Positive Analysis

| Location | Category | Recommended Fix |
|----------|----------|-----------------|
| test/fixtures/sql.py:10 | Test code | Path exclusion |
| src/utils/query.py:45 | Custom sanitizer | Add sanitizer |
| ... | ... | ... |

## False Negative Analysis

| Known Vuln Location | Category | Recommended Fix |
|---------------------|----------|-----------------|
| src/api/admin.py:100 | Cross-file | Enable interfile |
| ... | ... | ... |

## Recommendations

1. [Specific fix for FP #1]
2. [Specific fix for FP #2]
3. [How to address FNs]
4. [Recommended confidence level]

## Conclusion

- Current confidence: MEDIUM
- After fixes: HIGH expected
- Ready for production: YES / NO
```

---

## Quick Evaluation Checklist

Before deploying a rule:

- [ ] Tested against intentionally vulnerable repo
- [ ] All known vuln locations detected (recall check)
- [ ] FP rate measured and acceptable
- [ ] FPs categorized and fixes identified
- [ ] Confidence level set appropriately
- [ ] Test file with ruleid/ok annotations created
- [ ] `semgrep --test` passes
