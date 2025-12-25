# Semgrep Rule Testing Reference

> Source: https://semgrep.dev/docs/writing-rules/testing-rules

## Overview

Semgrep provides a built-in testing framework to validate rules against known good and bad code samples. Tests protect against both false positives and false negatives.

---

## Test File Structure

Place test files alongside rules with matching names:

```
custom-rules/cve/
├── CVE-2024-1234.yaml       # Rule file
├── CVE-2024-1234.py         # Python test cases
├── CVE-2024-1234.js         # JavaScript test cases (if multi-language)
└── CVE-2024-1234.java       # Java test cases
```

Semgrep discovers test files based on:
1. Rule filename
2. Languages specified in the rule

---

## Test Annotations

Add annotations as comments immediately before the code line being tested.

### ruleid - Expected Match (True Positive)

Protects against false negatives:

```python
# ruleid: sql-injection-taint
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# ruleid: sql-injection-taint
query = f"DELETE FROM users WHERE id = {request.args.get('id')}"
cursor.execute(query)
```

### ok - Expected Non-Match (True Negative)

Protects against false positives:

```python
# ok: sql-injection-taint
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# ok: sql-injection-taint
cursor.execute("SELECT * FROM users WHERE id = %s", (int(user_id),))

# ok: sql-injection-taint
cursor.execute("SELECT COUNT(*) FROM users")  # No user input
```

### todoruleid - Future True Positive

Mark cases that SHOULD match but currently don't (known false negatives):

```python
# todoruleid: sql-injection-taint
# Complex data flow not yet detected
def get_query():
    return request.args.get('q')
cursor.execute(get_query())
```

### todook - Future True Negative

Mark cases that SHOULD NOT match but currently do (known false positives):

```python
# todook: sql-injection-taint
# This is actually safe but rule doesn't recognize it
cursor.execute(validated_query_builder(user_id))
```

---

## Running Tests

### Basic Test Run

```bash
# Test all rules in directory
semgrep --test custom-rules/cve/

# Test specific rule
semgrep --test custom-rules/cve/CVE-2024-1234.yaml
```

### Validate Rule Syntax

```bash
# Check for configuration errors
semgrep --validate --config custom-rules/cve/CVE-2024-1234.yaml
```

### Test Against Target Code

```bash
# Run rule against actual repository
semgrep --config custom-rules/cve/CVE-2024-1234.yaml repos/target-org/

# Count findings
semgrep --config custom-rules/cve/CVE-2024-1234.yaml repos/target-org/ --json | jq '.results | length'
```

---

## Test File Examples

### Python Test File

```python
# test_sql_injection.py

import sqlite3
from flask import request

# === TRUE POSITIVES (should match) ===

# ruleid: sql-injection-taint
def bad_query_concat():
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# ruleid: sql-injection-taint
def bad_query_fstring():
    user_id = request.args.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ruleid: sql-injection-taint
def bad_query_format():
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))

# === TRUE NEGATIVES (should NOT match) ===

# ok: sql-injection-taint
def good_parameterized():
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# ok: sql-injection-taint
def good_cast_to_int():
    user_id = int(request.args.get('id'))
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ok: sql-injection-taint
def good_hardcoded():
    cursor.execute("SELECT * FROM users WHERE id = 1")

# ok: sql-injection-taint
def good_constant():
    QUERY = "SELECT * FROM users"
    cursor.execute(QUERY)

# === KNOWN ISSUES ===

# todoruleid: sql-injection-taint
# Cross-function flow not detected without --pro
def get_user_id():
    return request.args.get('id')

def bad_cross_function():
    cursor.execute(f"SELECT * FROM users WHERE id = {get_user_id()}")
```

### JavaScript Test File

```javascript
// test_command_injection.js

const { exec } = require('child_process');
const express = require('express');

// === TRUE POSITIVES ===

// ruleid: command-injection-node
app.get('/run', (req, res) => {
    exec(req.query.cmd);
});

// ruleid: command-injection-node
app.post('/execute', (req, res) => {
    exec('ls ' + req.body.dir);
});

// === TRUE NEGATIVES ===

// ok: command-injection-node
app.get('/list', (req, res) => {
    exec('ls -la');  // Hardcoded command
});

// ok: command-injection-node
app.get('/safe', (req, res) => {
    const sanitized = shellEscape([req.query.input]);
    exec('echo ' + sanitized);
});
```

### Java Test File

```java
// TestSqlInjection.java

import java.sql.*;
import javax.servlet.http.*;

public class TestSqlInjection {

    // ruleid: java-sql-injection
    public void badConcatenation(HttpServletRequest req, Connection conn) {
        String id = req.getParameter("id");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    // ok: java-sql-injection
    public void goodPreparedStatement(HttpServletRequest req, Connection conn) {
        String id = req.getParameter("id");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, id);
        pstmt.executeQuery();
    }

    // ok: java-sql-injection
    public void goodHardcoded(Connection conn) {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = 1");
    }
}
```

---

## Autofix Testing

Test that autofixes produce correct output:

### Rule with Fix

```yaml
rules:
  - id: use-safe-yaml
    pattern: yaml.load($X)
    fix: yaml.safe_load($X)
    message: Use yaml.safe_load() instead
    severity: ERROR
    languages: [python]
```

### Create Expected Output File

```
custom-rules/
├── use-safe-yaml.yaml
├── use-safe-yaml.py          # Input test file
└── use-safe-yaml.fixed.py    # Expected output after fix
```

**use-safe-yaml.py:**
```python
# ruleid: use-safe-yaml
data = yaml.load(content)
```

**use-safe-yaml.fixed.py:**
```python
# ruleid: use-safe-yaml
data = yaml.safe_load(content)
```

### Run Autofix Test

```bash
semgrep --test --config custom-rules/use-safe-yaml.yaml custom-rules/
```

---

## CVE Rule Testing Protocol

For CVE-derived rules, follow this validation sequence:

### 1. Test Against Original Vulnerable Code

```bash
# Clone vulnerable version
git clone https://github.com/owner/repo
cd repo && git checkout COMMIT_BEFORE_FIX

# Verify rule catches the vulnerability
semgrep --config ../custom-rules/cve/CVE-2024-1234.yaml .
# Expected: 1+ findings
```

### 2. Test Against Fixed Code

```bash
# Checkout patched version
git checkout COMMIT_AFTER_FIX

# Verify rule doesn't fire on fix
semgrep --config ../custom-rules/cve/CVE-2024-1234.yaml .
# Expected: 0 findings (or fewer than before)
```

### 3. Test for Variants

```bash
# Scan your test file for patterns
semgrep --config custom-rules/cve/CVE-2024-1234.yaml \
        custom-rules/cve/CVE-2024-1234.py
# Should match all 'ruleid' lines, skip all 'ok' lines
```

---

## Organizing Tests

### Separate Test Directories

For large rule sets, separate rules from tests:

```
custom-rules/
├── cve/
│   ├── CVE-2024-1234.yaml
│   └── CVE-2024-5678.yaml
└── tests/
    └── cve/
        ├── CVE-2024-1234.py
        └── CVE-2024-5678.py
```

Run with:
```bash
semgrep --test --config custom-rules/cve/ custom-rules/tests/cve/
```

### Test Naming Conventions

- Match rule filename exactly (minus extension)
- Use appropriate language extension
- Include comment header describing test purpose

```python
# CVE-2024-1234.py
# Tests for path traversal variant detection
# Based on: https://nvd.nist.gov/vuln/detail/CVE-2024-1234
#
# True positives: Lines 10-25
# True negatives: Lines 30-50
# Known issues: Lines 55-60
```

---

## Best Practices

### Minimum Test Coverage

Every CVE rule should have:
- At least 3 true positive cases (variations of vulnerable pattern)
- At least 3 true negative cases (safe patterns that shouldn't match)
- Edge cases specific to the vulnerability

### Test Both Patterns and Taint

For taint rules, test:
- Different source types
- Different sink variations
- Sanitizer effectiveness
- Propagation paths

### Document Known Limitations

Use `todoruleid` and `todook` to document:
- Patterns the rule should catch but doesn't
- False positives that need fixing
- Semgrep limitations (cross-file, complex flows)

### Continuous Testing

```bash
# Add to CI/CD
semgrep --validate --config custom-rules/
semgrep --test custom-rules/
```
