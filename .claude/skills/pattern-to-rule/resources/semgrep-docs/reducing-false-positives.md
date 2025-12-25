# Reducing False Positives in Semgrep Rules

> Sources:
> - https://semgrep.dev/docs/kb/semgrep-code/reduce-false-positives
> - https://semgrep.dev/docs/writing-rules/data-flow/constant-propagation

## Overview

False positives erode developer trust and waste triage time. A single noisy rule can undermine weeks of security team goodwill. This guide covers techniques to minimize FPs while maintaining detection coverage.

---

## Strategy 1: Pattern Refinement

### Add Exclusion Patterns

Use `pattern-not` and `pattern-not-inside` to exclude safe code:

```yaml
patterns:
  - pattern: eval($X)
  # Exclude hardcoded strings
  - pattern-not: eval("...")
  # Exclude known safe wrappers
  - pattern-not: safe_eval(...)
  # Exclude test contexts
  - pattern-not-inside: |
      def test_...(...):
          ...
```

### Use Typed Metavariables

Constrain matches to specific types:

```yaml
# Instead of matching any variable
pattern: $FUNC($X)

# Match only string type (language-dependent)
pattern: $FUNC((String $X))
```

### Constrain Variable Names

Use `metavariable-regex` to target suspicious names:

```yaml
patterns:
  - pattern: $VAR = "..."
  - metavariable-regex:
      metavariable: $VAR
      regex: "(?i)(password|secret|api_key|token|credential)"
```

### Require Dangerous Context

Use `pattern-inside` to only match in risky contexts:

```yaml
patterns:
  - pattern: $CURSOR.execute($QUERY)
  - pattern-inside: |
      def $FUNC(..., $REQUEST, ...):
          ...
```

---

## Strategy 2: Taint Mode Optimization

### Use focus-metavariable

Narrow findings to the specific tainted expression:

```yaml
pattern-sinks:
  - pattern: cursor.execute($QUERY, $PARAMS)
    focus-metavariable: $QUERY  # Report at $QUERY, not whole statement
```

### Add Comprehensive Sanitizers

Cover all legitimate sanitization methods:

```yaml
pattern-sanitizers:
  # Type conversions
  - pattern: int(...)
  - pattern: float(...)
  - pattern: bool(...)
  - pattern: str(...)

  # Framework sanitizers
  - pattern: escape(...)
  - pattern: html.escape(...)
  - pattern: markupsafe.escape(...)
  - pattern: bleach.clean(...)
  - pattern: quote(...)

  # Validation functions
  - pattern: validate(...)
  - pattern: sanitize(...)
  - pattern: clean(...)

  # Parameterized query syntax
  - pattern: $CURSOR.execute("...", (...))

  # ORM methods (inherently safe)
  - pattern: $MODEL.objects.filter(...)
  - pattern: $MODEL.objects.get(...)
  - pattern: $MODEL.objects.create(...)
```

### Tune Source Precision

Use `exact: true` when subexpressions shouldn't be sources:

```yaml
pattern-sources:
  - pattern: request.args.get(...)
    exact: true  # Only this call, not nested expressions
```

---

## Strategy 3: Context Exclusions

### Exclude Test Files

```yaml
paths:
  exclude:
    - "**/test/**"
    - "**/tests/**"
    - "**/*_test.py"
    - "**/*.test.js"
    - "**/spec/**"
    - "**/fixtures/**"
```

Or use pattern-based exclusion:

```yaml
patterns:
  - pattern: dangerous($X)
  - pattern-not-inside: |
      def test_...(...):
          ...
  - pattern-not-inside: |
      class Test...:
          ...
```

### Exclude Example/Demo Code

```yaml
paths:
  exclude:
    - "**/examples/**"
    - "**/demo/**"
    - "**/sample/**"
    - "**/docs/**"
```

### Exclude Vendored/Third-Party Code

```yaml
paths:
  exclude:
    - "**/vendor/**"
    - "**/node_modules/**"
    - "**/third_party/**"
    - "**/external/**"
```

### Exclude Generated Code

```yaml
paths:
  exclude:
    - "**/*.generated.*"
    - "**/*.pb.go"
    - "**/generated/**"
```

---

## Strategy 4: Constant Propagation Awareness

### How It Works

Semgrep tracks constant values through assignments:

```python
password = "hunter2"
connect(password)  # Semgrep knows password = "hunter2"
```

### When to Disable

Disable if causing false positives with mutable values:

```yaml
options:
  constant_propagation: false
```

### Immutability Assumptions

Semgrep assumes constants are immutable. Consider:

```java
// Private + single assignment = immutable
private static final String REGEX = "^[a-z]+$";

// Public = potentially mutable (may cause FPs)
public String query = "SELECT *";
```

---

## Strategy 5: Cross-Function/File Analysis

### Enable Pro Analysis

Use Semgrep Pro for advanced dataflow:

```bash
# Cross-function analysis
semgrep --pro

# Cross-file analysis
semgrep --pro  # with interfile: true in rule
```

### Rule-Level Configuration

```yaml
options:
  interfile: true  # Enable cross-file taint tracking
```

### Trade-offs

| Analysis Level | FP Rate | FN Rate | Performance |
|---------------|---------|---------|-------------|
| Intraprocedural | Higher | Higher | Fast |
| Interprocedural | Lower | Lower | Medium |
| Interfile | Lowest | Lowest | Slow |

---

## Strategy 6: Severity and Confidence Metadata

### Use Appropriate Confidence Levels

```yaml
metadata:
  confidence: HIGH    # Very few FPs expected
  confidence: MEDIUM  # Some FPs possible
  confidence: LOW     # Manual review recommended
```

### Severity Guidelines

| Severity | Confidence Required | Use For |
|----------|--------------------| --------|
| CRITICAL | HIGH | Verified exploitable, immediate risk |
| HIGH | HIGH/MEDIUM | Likely exploitable security issues |
| MEDIUM | Any | Potential issues, need verification |
| LOW | Any | Informational, code quality |

---

## Strategy 7: Iterative Testing

### Test Against Real Codebases

```bash
# Run rule against target before adding to pipeline
semgrep --config my-rule.yaml repos/target-org/

# Check finding count
semgrep --config my-rule.yaml repos/target-org/ --json | jq '.results | length'

# Review first 10 findings manually
semgrep --config my-rule.yaml repos/target-org/ --json | jq '.results[:10]'
```

### Use Code Search (Semgrep Cloud)

Test patterns across many repositories before deploying:
- Rapid feedback loop (seconds vs hours)
- See real-world match distribution
- Identify FP patterns before rollout

---

## Common False Positive Sources

### 1. Hardcoded/Literal Values

```yaml
# Problem: Flags hardcoded strings as injection
pattern: execute($QUERY)

# Fix: Exclude literals
patterns:
  - pattern: execute($QUERY)
  - pattern-not: execute("...")
```

### 2. Test Fixtures

```yaml
# Problem: Test data looks like secrets
pattern: password = "..."

# Fix: Exclude test paths
paths:
  exclude:
    - "**/test/**"
    - "**/fixtures/**"
```

### 3. Already-Sanitized Input

```yaml
# Problem: Doesn't recognize custom sanitizers
pattern-sinks:
  - pattern: execute($Q)

# Fix: Add sanitizers
pattern-sanitizers:
  - pattern: company_sanitize(...)
  - pattern: SafeQuery.build(...)
```

### 4. Framework Auto-Escaping

```yaml
# Problem: Framework handles escaping
pattern: $TEMPLATE.render($DATA)

# Fix: Exclude framework-safe patterns
patterns:
  - pattern: $TEMPLATE.render($DATA)
  - pattern-not-inside: |
      @app.route(...)
      def ...():
          ...
          return render_template(...)  # Flask auto-escapes
```

### 5. Admin/Internal Code

```yaml
# Problem: Admin functions aren't user-accessible
pattern: dangerous($INPUT)

# Fix: Exclude admin decorators
patterns:
  - pattern: dangerous($INPUT)
  - pattern-not-inside: |
      @admin_required
      def ...():
          ...
```

---

## False Positive Checklist

Before adding a rule to production, verify:

- [ ] Rule excludes hardcoded/literal values
- [ ] Rule excludes test/example directories
- [ ] Rule excludes vendored/third-party code
- [ ] Sanitizers cover framework-specific methods
- [ ] Sanitizers cover project-specific wrappers
- [ ] Tested against target codebase with acceptable FP rate
- [ ] Confidence level matches expected FP rate
- [ ] `todook` annotations document known FPs being addressed

---

## Measuring False Positive Rate

### Manual Sampling

```bash
# Get sample of findings
semgrep --config rule.yaml target/ --json > findings.json

# Review random sample
jq -r '.results | .[] | "\(.path):\(.start.line) - \(.extra.message)"' findings.json | shuf | head -20
```

### Target FP Rates

| Rule Type | Target FP Rate |
|-----------|---------------|
| CRITICAL severity | < 5% |
| HIGH severity | < 10% |
| MEDIUM severity | < 20% |
| LOW/Audit | < 40% |

### When to Disable vs Fix

- **FP rate > 50%**: Consider disabling until fixed
- **FP rate 20-50%**: Add to monitoring, fix before blocking
- **FP rate < 20%**: Acceptable for comment/monitor mode
- **FP rate < 5%**: Ready for blocking mode
