# Semgrep Rule Syntax Reference

> Source: https://semgrep.dev/docs/writing-rules/rule-syntax

## Core Rule Structure

Semgrep rules are YAML-based configurations that define code patterns to detect. Every rule requires specific mandatory fields at the top level under the `rules` key.

```yaml
rules:
  - id: rule-id-here
    message: |
      Description of what was matched and how to fix it.
    severity: ERROR
    languages:
      - python
    pattern: dangerous_function(...)
```

## Required Fields

### id
A unique identifier string. Use kebab-case: `no-unused-variable`, `sql-injection-taint`

### message
Explains what was matched and how to fix it. Supports metavariable interpolation:
```yaml
message: |
  Found dangerous use of $FUNC with user input $INPUT.
  Use parameterized queries instead.
```

### severity
One of:
- `CRITICAL` - Exploitable vulnerabilities with severe impact
- `HIGH` - Security issues requiring immediate attention
- `MEDIUM` - Security concerns that should be addressed
- `LOW` - Minor issues or informational findings

Legacy values `ERROR`, `WARNING`, `INFO` remain supported.

### languages
Array of target languages:
```yaml
languages:
  - python
  - javascript
  - typescript
```

Supported languages include: python, javascript, typescript, java, go, ruby, php, c, cpp, csharp, rust, kotlin, scala, swift, solidity, terraform, dockerfile, yaml, json, and 30+ more.

### Pattern Definition
Must include exactly ONE of:
- `pattern` - Single expression matching
- `patterns` - Logical AND of multiple patterns
- `pattern-either` - Logical OR of multiple patterns
- `pattern-regex` - PCRE2-compatible regex

## Pattern Operators

### Basic Operators

#### pattern
Matches code expressions directly:
```yaml
pattern: hashlib.md5(...)
```

#### patterns
Combines multiple conditions with AND logic:
```yaml
patterns:
  - pattern: $FUNC($INPUT)
  - metavariable-regex:
      metavariable: $FUNC
      regex: (system|exec|popen)
```

Evaluation order:
1. Positive patterns intersect
2. Negative patterns filter results
3. Conditionals examine bound metavariables

#### pattern-either
Combines patterns with OR logic:
```yaml
pattern-either:
  - pattern: os.system(...)
  - pattern: os.popen(...)
  - pattern: subprocess.call(..., shell=True, ...)
```

#### pattern-regex
PCRE2-compatible regular expressions in multiline mode:
```yaml
pattern-regex: "password\\s*=\\s*['\"][^'\"]+['\"]"
```

Named capturing groups become metavariables:
```yaml
pattern-regex: "(?P<PASSWORD>password\\s*=\\s*['\"][^'\"]+['\"])"
```

### Negation Operators

#### pattern-not
Excludes matches meeting certain criteria:
```yaml
patterns:
  - pattern: eval($X)
  - pattern-not: eval("...")  # Exclude hardcoded strings
```

#### pattern-not-regex
Filters findings with regex patterns:
```yaml
patterns:
  - pattern: $VAR = "..."
  - pattern-not-regex: "^(test|example|placeholder)$"
```

#### pattern-not-inside
Keeps findings outside specified code contexts:
```yaml
patterns:
  - pattern: $CURSOR.execute($QUERY)
  - pattern-not-inside: |
      try:
          ...
      except Exception:
          ...
```

### Contextual Operators

#### pattern-inside
Restricts matches to code within specified patterns:
```yaml
patterns:
  - pattern-inside: |
      def $FUNC(...):
          ...
  - pattern: eval($X)
```

Useful for finding code in specific functions, classes, or contexts.

#### focus-metavariable
Narrows matched region to specific metavariable bindings:
```yaml
patterns:
  - pattern: $CURSOR.execute($QUERY, $PARAMS)
  - focus-metavariable: $QUERY
```

Supports multiple metavariables (intersection semantics).

## Metavariable Operators

### metavariable-regex
Filters metavariables against regex patterns (left-anchored):
```yaml
patterns:
  - pattern: $FUNC(...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: "(eval|exec|compile)"
```

### metavariable-pattern
Matches metavariables using pattern formulas:
```yaml
patterns:
  - pattern: $FUNC($ARG)
  - metavariable-pattern:
      metavariable: $ARG
      pattern-either:
        - pattern: request.args[...]
        - pattern: request.form[...]
```

Supports language specification for string content analysis:
```yaml
metavariable-pattern:
  metavariable: $CODE
  language: python
  pattern: eval(...)
```

### metavariable-comparison
Compares metavariable numeric values:
```yaml
patterns:
  - pattern: set_timeout($DURATION)
  - metavariable-comparison:
      metavariable: $DURATION
      comparison: $DURATION > 30000
```

Available functions: `int()`, `float()`, `str()`, `today()`, `re.match()`

### metavariable-analysis
Performs semantic analysis on metavariables:
```yaml
patterns:
  - pattern: $KEY = "..."
  - metavariable-analysis:
      analyzer: entropy
      metavariable: $KEY
```

Available analyzers: `entropy` (detect high-entropy secrets)

## Optional Configuration

### fix
Provides simple search-and-replace autofixes:
```yaml
rules:
  - id: use-safe-yaml
    pattern: yaml.load($X)
    fix: yaml.safe_load($X)
```

Applied with `semgrep --autofix`

### metadata
Arbitrary user data (doesn't affect matching):
```yaml
metadata:
  cwe: "CWE-89"
  owasp:
    - "A03:2021-Injection"
  category: security
  confidence: HIGH
  likelihood: HIGH
  impact: HIGH
  author: "Security Team"
  references:
    - https://cwe.mitre.org/data/definitions/89.html
```

### paths
Controls file inclusion/exclusion:
```yaml
paths:
  include:
    - "src/**"
  exclude:
    - "**/test/**"
    - "**/vendor/**"
```

Exclusions take precedence over inclusions.

### options
Matching behavior configuration:
```yaml
options:
  constant_propagation: true    # Default: true
  ac_matching: true             # Associativity/commutativity
  symmetric_eq: false           # Treat a==b as b==a
  implicit_return: true         # Match implicit returns
  vardef_assign: true           # Match var declarations
```

### min-version / max-version
Semgrep version constraints:
```yaml
min-version: "1.38.0"
max-version: "2.0.0"
```

## Metavariable Matching Behavior

### In AND operations (patterns)
Metavariables must bind identically across sub-patterns:
```yaml
patterns:
  - pattern: $X = user_input()
  - pattern: dangerous($X)  # Must be same $X
```

### In OR operations (pattern-either)
No matching constraints between alternatives:
```yaml
pattern-either:
  - pattern: func1($X)  # $X here
  - pattern: func2($Y)  # $Y independent
```

## Complete Example

```yaml
rules:
  - id: python-sql-injection
    message: |
      SQL injection vulnerability. User input from $SOURCE flows to
      $CURSOR.execute() without parameterization.

      Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    severity: CRITICAL
    languages:
      - python
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
    pattern-sinks:
      - pattern: $CURSOR.execute($QUERY, ...)
        focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern: int(...)
      - pattern: escape(...)
    metadata:
      cwe: "CWE-89"
      owasp:
        - "A03:2021-Injection"
      category: security
      confidence: HIGH
      references:
        - https://owasp.org/www-community/attacks/SQL_Injection
```
