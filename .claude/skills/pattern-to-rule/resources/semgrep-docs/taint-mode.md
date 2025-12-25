# Semgrep Taint Mode Reference

> Source: https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview

## Overview

Taint analysis tracks untrusted (user-controlled) data as it flows through code. When tainted data reaches a dangerous function (sink) without sanitization, Semgrep reports a finding.

Enable taint mode by adding `mode: taint` to your rule.

```yaml
rules:
  - id: sql-injection-taint
    mode: taint
    languages:
      - python
    message: |
      SQL injection: user input flows to database query.
    severity: CRITICAL
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      - pattern: cursor.execute($QUERY)
```

---

## Core Components

### pattern-sources

Define where tainted data originates. Supports all pattern operators.

```yaml
pattern-sources:
  # Flask
  - pattern: request.args.get(...)
  - pattern: request.args[...]
  - pattern: request.form[...]
  - pattern: request.json
  - pattern: request.data

  # Django
  - pattern: request.GET.get(...)
  - pattern: request.POST.get(...)

  # Express.js
  - pattern: req.query.$PARAM
  - pattern: req.body.$FIELD
  - pattern: req.params.$PARAM
```

**Options:**

```yaml
pattern-sources:
  - pattern: get_input()
    exact: true      # Only this expression, not subexpressions (default: false)
    by-side-effect: true  # Taints via side effect, not return value
```

### pattern-sinks

Specify vulnerable functions where taint causes harm. By default, sinks are "exact" (subexpressions not considered).

```yaml
pattern-sinks:
  # SQL Injection
  - pattern: $CURSOR.execute($QUERY)
  - pattern: $CURSOR.executemany($QUERY, ...)
  - pattern: $DB.raw($QUERY)

  # Command Injection
  - pattern: os.system($CMD)
  - pattern: subprocess.call($CMD, shell=True, ...)
  - pattern: subprocess.Popen($CMD, shell=True, ...)

  # XSS
  - pattern: $ELEM.innerHTML = $DATA
  - pattern: document.write($DATA)
```

**Options:**

```yaml
pattern-sinks:
  - pattern: dangerous($INPUT)
    exact: false     # Subexpressions also considered sinks (default: true)
```

### pattern-sanitizers

Mark functions that clean/validate data, removing taint status.

```yaml
pattern-sanitizers:
  # Type conversion (safe for SQLi when expecting int)
  - pattern: int(...)
  - pattern: float(...)
  - pattern: bool(...)

  # Escaping functions
  - pattern: escape(...)
  - pattern: html.escape(...)
  - pattern: markupsafe.escape(...)
  - pattern: bleach.clean(...)

  # Parameterized queries (the tuple syntax)
  - pattern: $CURSOR.execute("...", (...))

  # Validation
  - pattern: validate(...)
  - pattern: sanitize(...)
```

**Options:**

```yaml
pattern-sanitizers:
  - pattern: sanitize($X)
    exact: false          # Sanitize subexpressions too (default: false)
    by-side-effect: true  # Sanitizes via side effect
```

### pattern-propagators

Define custom taint flow paths beyond default assignments and function calls.

```yaml
pattern-propagators:
  # String copy propagates taint
  - pattern: strcpy($DST, $SRC)
    from: $SRC
    to: $DST

  # Append propagates taint
  - pattern: $LIST.append($ITEM)
    from: $ITEM
    to: $LIST

  # Dictionary assignment
  - pattern: $DICT[$KEY] = $VALUE
    from: $VALUE
    to: $DICT
```

---

## focus-metavariable

Narrow the finding to a specific part of the match:

```yaml
pattern-sinks:
  - pattern: $CURSOR.execute($QUERY, $PARAMS)
    focus-metavariable: $QUERY
```

This reports the finding at `$QUERY`'s location, not the entire statement.

---

## Analysis Modes

### Intraprocedural (Default)

Tracks taint within single functions. Run with:
```bash
semgrep --pro-intrafile
```

### Interprocedural (Cross-Function)

Follows taint through function calls. Run with:
```bash
semgrep --pro
```

### Interfile (Cross-File)

Tracks taint across file imports. Enable in rule:
```yaml
options:
  interfile: true
```

Run with:
```bash
semgrep --pro
```

Memory recommendation: 8 GB per core or more.

---

## Taint Labels (Pro Feature)

Track different types of tainted data separately:

```yaml
pattern-sources:
  - pattern: user_input()
    label: USER
  - pattern: file_read()
    label: FILE

pattern-sinks:
  - pattern: execute_query($X)
    requires: USER  # Only fires for USER-labeled taint
  - pattern: write_file($X)
    requires: FILE  # Only fires for FILE-labeled taint
```

### Label Operations

```yaml
pattern-sinks:
  # Require both labels
  - pattern: dangerous($X)
    requires: USER and FILE

  # Require either label
  - pattern: risky($X)
    requires: USER or FILE

  # Require one but not other
  - pattern: special($X)
    requires: USER and not SANITIZED
```

---

## Complete Taint Rule Example

```yaml
rules:
  - id: python-sql-injection
    mode: taint
    languages:
      - python
    message: |
      SQL injection vulnerability detected. User input from $SOURCE
      flows to database query without proper sanitization.

      Use parameterized queries instead:
      cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    severity: CRITICAL
    metadata:
      cwe: "CWE-89"
      owasp:
        - "A03:2021-Injection"
      category: security
      confidence: HIGH

    pattern-sources:
      # Flask sources
      - pattern: request.args.get(...)
      - pattern: request.args[...]
      - pattern: request.form.get(...)
      - pattern: request.form[...]
      - pattern: request.json
      - pattern: request.data
      - pattern: request.values.get(...)

    pattern-sinks:
      - pattern: $CURSOR.execute($QUERY, ...)
        focus-metavariable: $QUERY
      - pattern: $CURSOR.executemany($QUERY, ...)
        focus-metavariable: $QUERY
      - pattern: $ENGINE.execute($QUERY)
        focus-metavariable: $QUERY
      - pattern: text($QUERY)
        focus-metavariable: $QUERY

    pattern-sanitizers:
      # Type conversions
      - pattern: int(...)
      - pattern: float(...)
      - pattern: uuid.UUID(...)

      # Parameterized queries
      - pattern: $CURSOR.execute("...", (...))

      # ORM methods (safe by default)
      - pattern: $MODEL.objects.filter(...)
      - pattern: $MODEL.objects.get(...)
```

---

## Common Taint Patterns by Vulnerability

### SQL Injection

```yaml
pattern-sources:
  - pattern: request.$METHOD[...]
  - pattern: request.$METHOD.get(...)
pattern-sinks:
  - pattern: $CURSOR.execute($Q)
  - pattern: $CURSOR.executemany($Q, ...)
pattern-sanitizers:
  - pattern: $CURSOR.execute("...", (...))  # Parameterized
```

### Command Injection

```yaml
pattern-sources:
  - pattern: request.$METHOD[...]
pattern-sinks:
  - pattern: os.system($CMD)
  - pattern: os.popen($CMD)
  - pattern: subprocess.call($CMD, shell=True, ...)
  - pattern: subprocess.Popen($CMD, shell=True, ...)
  - pattern: subprocess.run($CMD, shell=True, ...)
pattern-sanitizers:
  - pattern: shlex.quote(...)
  - pattern: shlex.split(...)
```

### Path Traversal

```yaml
pattern-sources:
  - pattern: request.args.get(...)
pattern-sinks:
  - pattern: open($PATH, ...)
  - pattern: os.path.join(..., $PATH)
pattern-sanitizers:
  - pattern: os.path.basename(...)
  - pattern: secure_filename(...)
  - pattern: os.path.realpath(...)
```

### XSS (Cross-Site Scripting)

```yaml
pattern-sources:
  - pattern: request.args.get(...)
pattern-sinks:
  - pattern: Markup($HTML)
  - pattern: render_template_string($TPL)
  - pattern: make_response($BODY)
pattern-sanitizers:
  - pattern: escape(...)
  - pattern: bleach.clean(...)
  - pattern: markupsafe.escape(...)
```

### SSRF (Server-Side Request Forgery)

```yaml
pattern-sources:
  - pattern: request.args.get(...)
pattern-sinks:
  - pattern: requests.get($URL, ...)
  - pattern: requests.post($URL, ...)
  - pattern: urllib.request.urlopen($URL)
  - pattern: httpx.get($URL, ...)
pattern-sanitizers:
  - pattern: validate_url(...)
  - pattern: urlparse(...)  # If followed by validation
```

---

## Debugging Taint Rules

### Check Taint Traces

Findings include explanations of source-to-sink flow. Look for:
- Source location
- Propagation steps
- Sink location

### Common Issues

**Rule doesn't match:**
- Verify source pattern matches input points
- Check if sanitizer is too broad
- Try `--pro` for cross-function tracking

**Too many false positives:**
- Add more sanitizers for safe wrappers
- Use `pattern-not-inside` to exclude safe contexts
- Add `exact: true` to sources if subexpressions cause noise

**Missing findings:**
- Propagators may be needed for custom data flow
- Enable interfile analysis for cross-module flows
- Check if taint is lost through unrecognized transformations

---

## Performance Considerations

### Intraprocedural
- Fast, low memory
- Default mode

### Interprocedural
- Slower, more memory
- Catches more real bugs
- Use `--pro`

### Interfile
- Slowest, highest memory (8GB+ per core)
- Most comprehensive
- Use `--pro` with `interfile: true`

For large codebases, start with intraprocedural and selectively enable interprocedural for critical rules.
