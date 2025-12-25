# Bad Rule Examples (Anti-Patterns)

Common mistakes in Semgrep rules and how to fix them. Learn from these anti-patterns.

---

## Anti-Pattern 1: Over-Broad Pattern Matching

### Bad Rule ❌

```yaml
# BAD: Matches ANY call to execute()
rules:
  - id: bad-sql-injection
    pattern: $X.execute($Y)
    languages: [python]
    severity: ERROR
    message: Possible SQL injection
```

**Problems:**
- Matches ORM methods that are safe (Django, SQLAlchemy)
- Matches non-SQL execute methods
- Massive false positive rate (often > 90%)

### Good Rule ✓

```yaml
# GOOD: Taint mode with specific sinks and sanitizers
rules:
  - id: good-sql-injection
    mode: taint
    languages: [python]
    severity: ERROR
    message: SQL injection via string concatenation

    pattern-sources:
      - pattern: request.args.get(...)

    pattern-sinks:
      - pattern: $CURSOR.execute($Q)
        focus-metavariable: $Q

    pattern-sanitizers:
      - pattern: $CURSOR.execute("...", (...))  # Parameterized
      - pattern: $MODEL.objects.filter(...)      # ORM
      - pattern: int(...)                        # Type cast
```

---

## Anti-Pattern 2: Missing Sanitizers

### Bad Rule ❌

```yaml
# BAD: No sanitizers, flags parameterized queries as vulnerable
rules:
  - id: bad-no-sanitizers
    mode: taint
    languages: [python]

    pattern-sources:
      - pattern: request.args.get(...)

    pattern-sinks:
      - pattern: cursor.execute($Q)
```

**Problems:**
- Flags `cursor.execute("SELECT ?", (param,))` as vulnerable
- Flags ORM queries as vulnerable
- Flags type-cast values as vulnerable

### Good Rule ✓

```yaml
# GOOD: Comprehensive sanitizers
rules:
  - id: good-with-sanitizers
    mode: taint
    languages: [python]

    pattern-sources:
      - pattern: request.args.get(...)

    pattern-sinks:
      - pattern: cursor.execute($Q)

    pattern-sanitizers:
      # Parameterized queries
      - pattern: cursor.execute("...", (...))
      - pattern: cursor.execute($Q, $PARAMS)

      # Type conversions
      - pattern: int(...)
      - pattern: str(...)
      - pattern: uuid.UUID(...)

      # ORM methods
      - pattern: $MODEL.objects.filter(...)
      - pattern: $MODEL.objects.get(...)
```

---

## Anti-Pattern 3: Ignoring Framework Differences

### Bad Rule ❌

```yaml
# BAD: Single source pattern for all frameworks
rules:
  - id: bad-single-source
    mode: taint
    languages: [python]

    pattern-sources:
      - pattern: request.args.get(...)  # Flask only!

    pattern-sinks:
      - pattern: cursor.execute($Q)
```

**Problems:**
- Only detects Flask applications
- Misses Django, FastAPI, aiohttp, etc.
- False negatives in multi-framework codebases

### Good Rule ✓

```yaml
# GOOD: Framework-comprehensive sources
rules:
  - id: good-multi-framework
    mode: taint
    languages: [python]

    pattern-sources:
      # Flask
      - pattern: request.args.get(...)
      - pattern: request.args[...]
      - pattern: request.form.get(...)
      - pattern: request.json

      # Django
      - pattern: request.GET.get(...)
      - pattern: request.GET[...]
      - pattern: request.POST.get(...)
      - pattern: request.POST[...]

      # FastAPI
      - pattern: $QUERY
      - pattern: $BODY

    pattern-sinks:
      - pattern: cursor.execute($Q)
```

---

## Anti-Pattern 4: No Test Path Exclusions

### Bad Rule ❌

```yaml
# BAD: Will flag test files
rules:
  - id: bad-no-exclusions
    pattern: pickle.loads($X)
    languages: [python]
    severity: ERROR
    message: Insecure deserialization
```

**Problems:**
- Flags intentionally vulnerable test fixtures
- Flags unit tests for deserialization handling
- Noise drowns out real findings

### Good Rule ✓

```yaml
# GOOD: Excludes test directories
rules:
  - id: good-with-exclusions
    pattern: pickle.loads($X)
    languages: [python]
    severity: ERROR
    message: Insecure deserialization

    paths:
      exclude:
        - "**/test/**"
        - "**/tests/**"
        - "**/test_*.py"
        - "**/*_test.py"
        - "**/fixtures/**"
        - "**/testdata/**"
```

---

## Anti-Pattern 5: Vague or Missing Message

### Bad Rule ❌

```yaml
# BAD: Unhelpful message
rules:
  - id: bad-message
    pattern: eval($X)
    languages: [python]
    severity: ERROR
    message: eval is bad  # Not helpful!
```

**Problems:**
- Developer doesn't know WHY it's bad
- No guidance on how to fix
- No references for learning more

### Good Rule ✓

```yaml
# GOOD: Actionable message with remediation
rules:
  - id: good-message
    pattern: eval($X)
    languages: [python]
    severity: CRITICAL
    message: |
      eval() executes arbitrary Python code. If $X contains user input,
      attackers can execute arbitrary system commands.

      Impact: Remote Code Execution (RCE)

      Remediation:
      - Use ast.literal_eval() for safe literal evaluation
      - Use json.loads() for JSON parsing
      - Avoid eval() entirely when possible

    metadata:
      cwe: "CWE-94"
      owasp: "A03:2021 - Injection"
      references:
        - https://cwe.mitre.org/data/definitions/94.html
```

---

## Anti-Pattern 6: Missing focus-metavariable

### Bad Rule ❌

```yaml
# BAD: Reports entire statement, hard to understand
rules:
  - id: bad-no-focus
    mode: taint
    languages: [python]

    pattern-sources:
      - pattern: request.args.get(...)

    pattern-sinks:
      - pattern: cursor.execute($QUERY, $PARAMS)
      # Reports the whole execute() call
```

**Problems:**
- Finding highlights entire statement
- Unclear which parameter is tainted
- Harder for developers to understand

### Good Rule ✓

```yaml
# GOOD: Focus on the vulnerable parameter
rules:
  - id: good-with-focus
    mode: taint
    languages: [python]

    pattern-sources:
      - pattern: request.args.get(...)

    pattern-sinks:
      - pattern: cursor.execute($QUERY, $PARAMS)
        focus-metavariable: $QUERY  # Highlights just $QUERY
```

---

## Anti-Pattern 7: Using Pattern Mode for Data Flow

### Bad Rule ❌

```yaml
# BAD: Pattern mode can't track data flow
rules:
  - id: bad-pattern-for-flow
    languages: [python]
    patterns:
      - pattern: |
          $X = request.args.get(...)
          ...
          cursor.execute($X)
```

**Problems:**
- Semgrep's `...` is limited in how many statements it spans
- Misses transformations (concat, format, etc.)
- Misses cross-function flow

### Good Rule ✓

```yaml
# GOOD: Taint mode for data flow
rules:
  - id: good-taint-for-flow
    mode: taint
    languages: [python]

    pattern-sources:
      - pattern: request.args.get(...)

    pattern-sinks:
      - pattern: cursor.execute($Q)
```

---

## Anti-Pattern 8: Overly Specific Pattern

### Bad Rule ❌

```yaml
# BAD: Only catches exact code from CVE report
rules:
  - id: bad-too-specific
    languages: [python]
    pattern: |
      yaml.load(request.form['data'], Loader=yaml.UnsafeLoader)
```

**Problems:**
- Only catches exact match
- Misses `request.args`, `request.json`, etc.
- Misses `yaml.load()` without Loader (also unsafe)
- Misses variable intermediates

### Good Rule ✓

```yaml
# GOOD: Generalizes to catch variants
rules:
  - id: good-generalized
    mode: taint
    languages: [python]

    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
      - pattern: request.json

    pattern-sinks:
      - pattern: yaml.load($DATA)  # No Loader
      - pattern: yaml.load($DATA, Loader=yaml.Loader)
      - pattern: yaml.load($DATA, Loader=yaml.UnsafeLoader)
      - pattern: yaml.unsafe_load($DATA)

    pattern-sanitizers:
      - pattern: yaml.safe_load(...)
      - pattern: yaml.load($DATA, Loader=yaml.SafeLoader)
```

---

## Anti-Pattern 9: Wrong Severity

### Bad Rule ❌

```yaml
# BAD: Overstating severity
rules:
  - id: bad-severity
    pattern: MD5(...)
    languages: [python]
    severity: CRITICAL  # Not critical for all uses!
    message: MD5 detected
```

**Problems:**
- MD5 is weak for passwords but fine for checksums
- Crying wolf with CRITICAL reduces trust
- Security team fatigue from false urgency

### Good Rule ✓

```yaml
# GOOD: Appropriate severity with context
rules:
  # CRITICAL: MD5 for password hashing
  - id: md5-password-hashing
    patterns:
      - pattern: hashlib.md5($PASSWORD)
      - metavariable-regex:
          metavariable: $PASSWORD
          regex: "(?i)password|passwd|pwd|secret"
    languages: [python]
    severity: ERROR
    message: |
      MD5 used for password hashing. MD5 is cryptographically broken.
      Use bcrypt, scrypt, or argon2 for password hashing.

  # WARNING: General MD5 use (might be OK)
  - id: md5-general-audit
    pattern: hashlib.md5(...)
    languages: [python]
    severity: WARNING
    message: |
      MD5 detected. Verify this is not used for security-sensitive purposes.
      MD5 is acceptable for checksums but NOT for passwords or signatures.
```

---

## Anti-Pattern 10: No Metadata

### Bad Rule ❌

```yaml
# BAD: No metadata
rules:
  - id: some-vulnerability
    pattern: dangerous($X)
    languages: [python]
    severity: ERROR
    message: This is dangerous
```

**Problems:**
- Can't filter by CWE/OWASP
- No confidence level for prioritization
- No references for investigation

### Good Rule ✓

```yaml
# GOOD: Complete metadata
rules:
  - id: cve-2024-12345-vulnerability
    pattern: dangerous($X)
    languages: [python]
    severity: ERROR
    message: |
      Vulnerability similar to CVE-2024-12345. [details]

    metadata:
      cve: "CVE-2024-12345"
      cwe: "CWE-XX"
      cvss: "7.5"
      owasp: "A03:2021 - Injection"
      confidence: HIGH
      category: security
      technology:
        - flask
        - django
      references:
        - https://nvd.nist.gov/vuln/detail/CVE-2024-12345
        - https://github.com/owner/repo/commit/abc123
```

---

## Summary Checklist

Before finalizing a rule, verify:

- [ ] Uses taint mode for injection/data flow vulnerabilities
- [ ] Has comprehensive sanitizers to reduce FPs
- [ ] Covers multiple frameworks (not just Flask or Express)
- [ ] Excludes test directories
- [ ] Has actionable message with remediation
- [ ] Uses focus-metavariable for sink parameters
- [ ] Generalizes pattern to catch variants
- [ ] Has appropriate severity (not always CRITICAL)
- [ ] Includes complete metadata (CWE, confidence, references)
- [ ] Has accompanying test file with ruleid/ok annotations
