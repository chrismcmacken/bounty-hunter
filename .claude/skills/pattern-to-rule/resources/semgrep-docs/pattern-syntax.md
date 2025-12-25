# Semgrep Pattern Syntax Reference

> Source: https://semgrep.dev/docs/writing-rules/pattern-syntax

## Core Concept

Semgrep searches code for patterns, matching them as full expressions or nested within larger structures. The expression pattern `1 + func(42)` can match a full expression or be part of a subexpression.

---

## Ellipsis Operator (`...`)

The ellipsis represents zero or more sequential items depending on context.

### Function Arguments

```yaml
# Match any arguments
pattern: insecure_function(...)

# Match with specific argument at start
pattern: func(1, ...)

# Match with specific argument at end
pattern: func(..., 1)

# Match specific args with anything between
pattern: func($X, ..., $Y)
```

### Method Chains

```yaml
# Match intermediate method calls
pattern: $O.foo(). ... .bar()
```

Matches: `obj.foo().something().else().bar()`

### Function Definitions

```yaml
# Match function with any parameters and body
pattern: |
  def $FUNC(...):
      ...

# Match anonymous functions
pattern: function ...($X) { ... }
```

### Class Definitions

```yaml
# Match class inheriting from specific base
pattern: |
  class $CLASS(InsecureBaseClass):
      ...
```

### String Content

```yaml
# Match function called with any string
pattern: crypto.set_secret_key("...")
```

### Containers

```yaml
# List with specific element
pattern: user_list = [..., 10, ...]

# Dictionary with key-value pair
pattern: user_dict = {..., $KEY: $VALUE, ...}
```

### Conditionals and Loops

```yaml
# Match if statement with any body
pattern: |
  if $CONDITION:
      ...

# Match for loop
pattern: |
  for $X in $ITER:
      ...
```

### Scope Limitation

The ellipsis only matches within its defined scope—it cannot jump across nested block boundaries.

---

## Metavariables

Metavariables capture code elements. Format: `$NAME` (e.g., `$X`, `$FUNC`, `$USER_INPUT`)

### Expression Metavariables

```yaml
# Capture arithmetic operands
pattern: $X + $Y

# Capture function and argument
pattern: $FUNC($ARG)
```

### Import Metavariables

```yaml
pattern: import $MODULE
```

### Reoccurring Metavariables

Same metavariable name enforces identical code matching:

```yaml
# Detect useless reassignment (same var assigned twice)
pattern: |
  $X = $Y
  ...
  $X = $Z
```

### Literal Metavariables

```yaml
# Match string literals
pattern: print("$MESSAGE")

# Match regex literals
pattern: /$REGEX/

# Match atoms (Ruby)
pattern: :$ATOM
```

### Typed Metavariables

Constrain matches to specific types (language-dependent):

```yaml
# Java - match Logger type
pattern: (java.util.logging.Logger $LOGGER).log(...)

# C - match char pointer
pattern: $X == (char *$Y)

# Go - match zip.Reader pointer
pattern: ($READER : *zip.Reader).Open($INPUT)

# TypeScript - match DomSanitizer
pattern: ($X: DomSanitizer).sanitize(...)
```

### Ellipsis Metavariables

Capture sequences of arguments:

```yaml
# Capture args before and after literal 3
pattern: foo($...ARGS, 3, $...ARGS)
```

### Anonymous Metavariables

Use `$_` as placeholder without binding:

```yaml
# Match function with exactly 3 parameters (don't care about names)
pattern: def $FUNC($_, $_, $_)
```

### Metavariable Display in Messages

```yaml
message: |
  Dangerous use of $FUNC with input $ARG.
  Found in function $CONTAINING_FUNC.
```

The actual captured values appear in the output.

---

## Metavariable Unification

### In `patterns` (AND)

Same-named metavariables must match identical code:

```yaml
patterns:
  - pattern: $X = user_input()
  - pattern: dangerous($X)  # Must be same variable
```

### In `pattern-either` (OR)

Metavariables are independent between alternatives:

```yaml
pattern-either:
  - pattern: func1($X)
  - pattern: func2($Y)  # $Y is separate from $X
```

### In Taint Mode

Enable cross-pattern unification with:

```yaml
options:
  taint_unify_mvars: true
```

---

## Deep Expression Operator

Pattern `<... [expression] ...>` matches deeply nested occurrences:

```yaml
# Find method call anywhere in condition
pattern: |
  if <... $USER.is_admin() ...>:
      ...
```

Matches the method call within:
- Nested function calls
- Binary operations
- Complex expressions

---

## Equivalences (Automatic)

Semgrep automatically handles semantic equivalents:

### Import Aliases

```yaml
pattern: subprocess.Popen(...)
```

Matches even with aliased imports:
```python
import subprocess as sp
sp.Popen(cmd)  # Still matches
```

### Constant Propagation

```yaml
pattern: dangerous($SECRET)
```

Matches:
```python
password = "hunter2"
dangerous(password)  # Matches via constant propagation
```

Disable per-rule:
```yaml
options:
  constant_propagation: false
```

### Associative-Commutative Operators

Operators `&&`, `||`, and `|` match reordered operands:

```yaml
pattern: $X && $Y
```

Matches both `a && b` and `b && a`

---

## Metavariable Operators

### metavariable-regex

Filter by regex (left-anchored):

```yaml
patterns:
  - pattern: $FUNC(...)
  - metavariable-regex:
      metavariable: $FUNC
      regex: "(eval|exec|compile)"
```

### metavariable-pattern

Match metavariable content with patterns:

```yaml
patterns:
  - pattern: dangerous($INPUT)
  - metavariable-pattern:
      metavariable: $INPUT
      pattern-either:
        - pattern: request.args[...]
        - pattern: request.form[...]
```

With language specification (for strings containing code):

```yaml
metavariable-pattern:
  metavariable: $CODE_STRING
  language: javascript
  pattern: eval(...)
```

### metavariable-comparison

Numeric/string comparisons:

```yaml
patterns:
  - pattern: set_timeout($MS)
  - metavariable-comparison:
      metavariable: $MS
      comparison: $MS > 30000
```

Available operators: `<`, `>`, `<=`, `>=`, `==`, `!=`
Available functions: `int()`, `float()`, `str()`, `len()`, `today()`, `re.match()`

### metavariable-analysis

Semantic analysis:

```yaml
patterns:
  - pattern: $KEY = "..."
  - metavariable-analysis:
      analyzer: entropy
      metavariable: $KEY
```

Analyzers: `entropy` (detect high-entropy strings like secrets)

---

## Generic Pattern Matching

For unsupported languages or config files, use `generic` language:

```yaml
rules:
  - id: find-config-issue
    languages:
      - generic
    pattern: |
      password = ...
```

### Generic Mode Features

- `...` skips up to 10 lines
- `$X` matches single words `[A-Za-z0-9_]+`
- `$...X` captures word sequences
- Indentation determines nesting

### Generic Mode Options

```yaml
options:
  # Restrict to single-line matching
  generic_ellipsis_max_span: 0

  # Handle C-style comments
  generic_comment_style: c
```

---

## Common Patterns by Use Case

### Dangerous Function Calls

```yaml
pattern-either:
  - pattern: eval($X)
  - pattern: exec($X)
  - pattern: os.system($X)
```

### Hardcoded Credentials

```yaml
patterns:
  - pattern: $VAR = "..."
  - metavariable-regex:
      metavariable: $VAR
      regex: "(?i)(password|secret|api_key|token)"
  - metavariable-analysis:
      analyzer: entropy
      metavariable: $VAR
```

### Missing Security Check

```yaml
patterns:
  - pattern: |
      def $FUNC(...):
          ...
          $DB.query(...)
          ...
  - pattern-not: |
      def $FUNC(...):
          ...
          if not $USER.is_authenticated():
              ...
          ...
          $DB.query(...)
          ...
```

### Deprecated API Usage

```yaml
patterns:
  - pattern: $OBJ.deprecated_method(...)
  - pattern-not-inside: |
      # LEGACY: ...
      ...
```

---

## Limitations

### Statements vs Expressions

Import statements require full syntax:
```yaml
# Wrong
pattern: foo

# Correct
pattern: import foo
```

### Partial Expressions

Incomplete expressions are invalid:
```yaml
# Invalid
pattern: 1+
```

### Block Boundaries

Ellipses cannot cross scope boundaries:
```yaml
# This won't match across function definitions
pattern: |
  $X = 1
  ...
  $Y = $X  # Won't match if def/class between
```
