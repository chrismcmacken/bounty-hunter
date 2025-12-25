# Semgrep Quick Reference

Quick reference for writing CVE-derived Semgrep rules. For detailed documentation, see the full docs in `semgrep-docs/`.

## Full Documentation

| Document | Description |
|----------|-------------|
| [rule-syntax.md](semgrep-docs/rule-syntax.md) | Complete rule structure, all operators |
| [pattern-syntax.md](semgrep-docs/pattern-syntax.md) | Pattern matching, metavariables, ellipsis |
| [taint-mode.md](semgrep-docs/taint-mode.md) | Sources, sinks, sanitizers, propagators |
| [testing-rules.md](semgrep-docs/testing-rules.md) | Test annotations, validation protocol |
| [reducing-false-positives.md](semgrep-docs/reducing-false-positives.md) | FP reduction techniques |

## Official Semgrep Resources

- [Semgrep Docs](https://semgrep.dev/docs/) - Official documentation
- [Semgrep Registry](https://semgrep.dev/r) - Existing rules for reference
- [Semgrep Playground](https://semgrep.dev/playground) - Interactive rule testing

---

## Rule Template

```yaml
rules:
  - id: cve-YYYY-NNNNN-vulnerability-type
    message: |
      Brief description of what was detected.

      CVE: https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN

      Remediation: How to fix this.
    severity: ERROR  # CRITICAL, HIGH, MEDIUM, LOW
    languages:
      - python
    # Choose ONE: pattern, patterns, pattern-either, or mode: taint
    pattern: dangerous_function(...)
    metadata:
      cve: "CVE-YYYY-NNNNN"
      cwe: "CWE-XX"
      confidence: HIGH  # HIGH, MEDIUM, LOW
      category: security
```

---

## Pattern Operators Cheat Sheet

### Basic Matching

| Operator | Purpose | Example |
|----------|---------|---------|
| `pattern` | Exact match | `eval($X)` |
| `patterns` | AND logic | Multiple conditions |
| `pattern-either` | OR logic | Multiple alternatives |
| `pattern-regex` | Regex match | `"password\s*="` |

### Exclusions

| Operator | Purpose | Example |
|----------|---------|---------|
| `pattern-not` | Exclude pattern | `pattern-not: eval("...")` |
| `pattern-not-inside` | Exclude context | Not inside try/except |
| `pattern-not-regex` | Exclude by regex | Filter variable names |

### Context

| Operator | Purpose | Example |
|----------|---------|---------|
| `pattern-inside` | Require context | Inside specific function |
| `focus-metavariable` | Narrow match | Report specific variable |

### Metavariable Constraints

| Operator | Purpose | Example |
|----------|---------|---------|
| `metavariable-regex` | Regex on captured var | Match function names |
| `metavariable-pattern` | Pattern on captured var | Check if user input |
| `metavariable-comparison` | Numeric comparison | `$X > 1000` |
| `metavariable-analysis` | Semantic analysis | Entropy detection |

---

## Metavariable Syntax

| Syntax | Meaning |
|--------|---------|
| `$VAR` | Capture any expression |
| `$_` | Match anything (no capture) |
| `$...ARGS` | Capture multiple arguments |
| `<... $X ...>` | Match $X at any nesting depth |
| `...` | Match any statements |

---

## Taint Mode Quick Reference

```yaml
rules:
  - id: injection-taint
    mode: taint
    languages: [python]

    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]

    pattern-sinks:
      - pattern: cursor.execute($Q)
        focus-metavariable: $Q

    pattern-sanitizers:
      - pattern: int(...)
      - pattern: escape(...)
```

### Common Sources by Framework

**Flask:**
```yaml
- pattern: request.args.get(...)
- pattern: request.form[...]
- pattern: request.json
```

**Django:**
```yaml
- pattern: request.GET.get(...)
- pattern: request.POST.get(...)
```

**Express.js:**
```yaml
- pattern: req.query.$PARAM
- pattern: req.body.$FIELD
- pattern: req.params.$PARAM
```

### Common Sinks by Vulnerability

**SQL Injection:**
```yaml
- pattern: $CURSOR.execute($Q)
- pattern: $DB.raw($Q)
```

**Command Injection:**
```yaml
- pattern: os.system($CMD)
- pattern: subprocess.call($CMD, shell=True, ...)
```

**Path Traversal:**
```yaml
- pattern: open($PATH, ...)
- pattern: os.path.join(..., $PATH)
```

---

## Testing Quick Reference

### Annotations

```python
# ruleid: my-rule-id       # Should match (true positive)
# ok: my-rule-id           # Should NOT match (true negative)
# todoruleid: my-rule-id   # Known false negative
# todook: my-rule-id       # Known false positive
```

### Commands

```bash
# Validate syntax
semgrep --validate --config rule.yaml

# Run tests
semgrep --test custom-rules/

# Test against code
semgrep --config rule.yaml target-dir/
```

### CVE Validation Protocol

1. Test against vulnerable commit → MUST detect
2. Test against fixed commit → MUST NOT detect
3. Test file with ruleid/ok annotations → All pass

---

## False Positive Reduction Checklist

- [ ] Exclude hardcoded literals: `pattern-not: func("...")`
- [ ] Exclude test files in `paths.exclude`
- [ ] Add framework-specific sanitizers
- [ ] Add project-specific safe wrappers
- [ ] Use `focus-metavariable` in taint rules
- [ ] Set appropriate `confidence` in metadata
- [ ] Test against real codebase before deployment

---

## CVE Rule Naming Convention

```
cve-YYYY-NNNNN-<vulnerability-type>[-<variant>]
```

Examples:
- `cve-2024-12345-sql-injection`
- `cve-2024-12345-path-traversal-variant`
- `cve-2024-12345-deserialization-pickle`

---

## Severity Guidelines

| Severity | When to Use |
|----------|-------------|
| `CRITICAL` | RCE, auth bypass, data breach |
| `HIGH` | SQLi, command injection, SSRF |
| `MEDIUM` | XSS, path traversal, info disclosure |
| `LOW` | Weak crypto, missing headers |

---

## Quick Commands

```bash
# Validate rule
semgrep --validate --config custom-rules/cve/CVE-2024-1234.yaml

# Test rule
semgrep --test custom-rules/cve/

# Scan with rule
semgrep --config custom-rules/cve/CVE-2024-1234.yaml repos/target/

# Count findings
semgrep --config rule.yaml target/ --json | jq '.results | length'

# Debug matching
semgrep --config rule.yaml target/ --debug

# Interactive pattern test
semgrep --pattern 'eval($X)' target/
```
