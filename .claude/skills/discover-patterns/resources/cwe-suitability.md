# CWE Suitability for Behavioral Pattern Rules

Which CWE vulnerability types yield **behavioral patterns** that developers recreate - NOT library-specific bugs.

## Key Distinction: Behavioral Patterns vs Library Bugs

### Behavioral Patterns (GOOD - Create Rules)

CVEs where the vulnerability is a **coding practice** that developers might recreate in custom code:

| Pattern Type | Example | Why Developers Recreate It |
|--------------|---------|---------------------------|
| Input→SQL | `"SELECT * FROM users WHERE id=" + user_id` | Custom query builders, raw SQL |
| Input→Shell | `os.system("ls " + user_dir)` | Custom scripts, automation |
| Input→Template | `Template(user_input).render()` | Custom template wrappers |
| Input→URL | `requests.get(user_url)` | Custom API clients |
| Input→Path | `open(base + "/" + user_file)` | Custom file handlers |

**Key characteristic:** The pattern exists in the USER'S CODE, not just in library internals.

### Library-Internal Bugs (SKIP - Use SCA Instead)

CVEs where the vulnerability is **inside the library's implementation**:

| Bug Type | Example | Why NOT Pattern-Matchable |
|----------|---------|--------------------------|
| Parser bugs | "Regex catastrophic backtracking in validator" | Internal implementation detail |
| Memory bugs | "Buffer overflow in C extension" | Not visible in user code |
| Logic bugs | "State machine error in protocol parser" | Complex internal logic |
| Default bugs | "Insecure default changed in v2.3" | Same user code, different behavior |

**Key characteristic:** User code looks **identical** before and after the fix. Only the library version matters.

### The Litmus Test

Ask: **"If I look at code using this library, can I tell if it's vulnerable without checking the version?"**

- **YES** → Behavioral pattern, create a rule
- **NO** → Library bug, skip (let SCA tools handle it)

## Excellent Candidates (Behavioral Patterns)

These vulnerability types have clear code patterns that Semgrep can detect with high accuracy.

### CWE-89: SQL Injection

**Suitability:** Excellent (+3 points)

**Pattern:** User input concatenated/formatted into SQL query strings.

```python
# Detectable pattern
cursor.execute("SELECT * FROM users WHERE id=" + user_id)
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
```

**Semgrep approach:** Taint mode with SQL execution sinks.

---

### CWE-78: OS Command Injection

**Suitability:** Excellent (+3 points)

**Pattern:** User input passed to shell execution functions.

```python
# Detectable pattern
os.system("ls " + user_input)
subprocess.call(user_input, shell=True)
```

**Semgrep approach:** Taint mode with subprocess/os sinks.

---

### CWE-94: Code Injection

**Suitability:** Excellent (+3 points)

**Pattern:** User input passed to code evaluation functions.

```python
# Detectable pattern
eval(user_input)
exec(user_code)
```

**Semgrep approach:** Taint mode with eval/exec sinks.

---

### CWE-79: Cross-Site Scripting (XSS)

**Suitability:** Excellent (+3 points)

**Pattern:** User input rendered in HTML without escaping.

```javascript
// Detectable pattern
element.innerHTML = userInput;
document.write(userInput);
```

**Semgrep approach:** Taint mode with DOM sinks.

---

### CWE-22: Path Traversal

**Suitability:** Excellent (+3 points)

**Pattern:** User input used in file paths without sanitization.

```python
# Detectable pattern
open(os.path.join(base_dir, user_input))
```

**Semgrep approach:** Taint mode with file operation sinks.

---

### CWE-611: XML External Entity (XXE)

**Suitability:** Excellent (+3 points)

**Pattern:** XML parser with external entities enabled.

```python
# Detectable pattern
etree.parse(user_input)  # Without disabling external entities
```

**Semgrep approach:** Pattern match for unsafe XML parser configurations.

---

### CWE-918: Server-Side Request Forgery (SSRF)

**Suitability:** Excellent (+3 points)

**Pattern:** User input used as URL in server-side HTTP request.

```python
# Detectable pattern
requests.get(user_url)
urllib.request.urlopen(user_input)
```

**Semgrep approach:** Taint mode with HTTP client sinks.

---

### CWE-502: Deserialization of Untrusted Data

**Suitability:** Excellent (+3 points)

**Pattern:** Deserializing user-controlled data with unsafe deserializers.

```python
# Detectable pattern
pickle.loads(user_data)
yaml.load(user_input)  # Without safe loader
```

**Semgrep approach:** Pattern match for unsafe deserializers.

---

### CWE-1321: Prototype Pollution (JavaScript)

**Suitability:** Excellent (+3 points)

**Pattern:** User input used to set object properties via bracket notation.

```javascript
// Detectable pattern
obj[userKey] = userValue;
Object.assign(target, userObject);
```

**Semgrep approach:** Taint mode tracking property assignments.

---

### CWE-1336: Server-Side Template Injection (SSTI)

**Suitability:** Excellent (+3 points)

**Pattern:** User input used as template string.

```python
# Detectable pattern
Template(user_input).render()
jinja2.Template(user_string).render()
```

**Semgrep approach:** Taint mode with template engine sinks.

---

## Good Candidates

These are detectable but may have higher false positive rates.

### CWE-287: Improper Authentication

**Suitability:** Good (+2 points)

**Detectable patterns:**
- Missing authentication decorators
- Hardcoded credentials
- Weak authentication checks

**Challenge:** Logic-dependent; may need context.

---

### CWE-306: Missing Authentication for Critical Function

**Suitability:** Good (+2 points)

**Detectable patterns:**
- Admin endpoints without auth decorators
- Direct object references

---

### CWE-732: Incorrect Permission Assignment

**Suitability:** Good (+2 points)

**Detectable patterns:**
- `chmod 777`
- World-readable file creation

---

### CWE-327: Use of Broken Crypto

**Suitability:** Moderate (+1 point)

**Detectable patterns:**
- MD5/SHA1 for passwords
- DES/RC4 usage
- ECB mode

**Challenge:** Context matters (hashing for checksums vs passwords).

---

## Poor Candidates

These vulnerability types are difficult or impossible to detect statically.

### CWE-362: Race Condition

**Suitability:** Poor (0 points)

**Why:** Requires understanding of execution timing and concurrency.

---

### CWE-119/120/125: Buffer Overflow/Memory Corruption

**Suitability:** Poor (0 points)

**Why:** Requires memory layout analysis. Use CodeQL or address sanitizers instead.

---

### CWE-330: Insufficient Randomness

**Suitability:** Poor (0 points)

**Why:** Detecting weak RNG usage is possible, but determining if it's security-critical requires context.

---

### CWE-284: Improper Access Control

**Suitability:** Poor (0 points)

**Why:** Logic bugs requiring understanding of authorization model.

---

### CWE-352: Cross-Site Request Forgery (CSRF)

**Suitability:** Poor (0 points)

**Why:** Requires understanding of state-changing operations and token validation flow.

---

### CWE-400: Resource Exhaustion (DoS)

**Suitability:** Poor (0 points)

**Why:** Requires understanding of resource usage patterns.

---

## Summary Table

| CWE | Name | Score | Notes |
|-----|------|-------|-------|
| CWE-89 | SQL Injection | +3 | Excellent - taint tracking |
| CWE-78 | Command Injection | +3 | Excellent - taint tracking |
| CWE-94 | Code Injection | +3 | Excellent - taint tracking |
| CWE-79 | XSS | +3 | Excellent - taint tracking |
| CWE-22 | Path Traversal | +3 | Excellent - taint tracking |
| CWE-611 | XXE | +3 | Excellent - config patterns |
| CWE-918 | SSRF | +3 | Excellent - taint tracking |
| CWE-502 | Deserialization | +3 | Excellent - sink patterns |
| CWE-1321 | Prototype Pollution | +3 | Excellent - JS specific |
| CWE-1336 | SSTI | +3 | Excellent - taint tracking |
| CWE-287 | Improper Auth | +2 | Good - missing decorators |
| CWE-306 | Missing Auth | +2 | Good - pattern-based |
| CWE-732 | Bad Permissions | +2 | Good - literal patterns |
| CWE-327 | Broken Crypto | +1 | Moderate - context needed |
| CWE-362 | Race Condition | 0 | Poor - runtime analysis needed |
| CWE-119 | Buffer Overflow | 0 | Poor - use CodeQL |
| CWE-330 | Weak Random | 0 | Poor - context dependent |
| CWE-284 | Access Control | 0 | Poor - logic bugs |
| CWE-352 | CSRF | 0 | Poor - framework dependent |

## Using CWE in Pattern Discovery

When filtering CVEs, check the CWE field:

```bash
# Extract CWE from OSV response
jq '.database_specific.cwe_ids[]' cve.json

# Or from GitHub Advisory
jq '.cwes[]' advisory.json
```

Only score +3 points for CWEs in the "Excellent" category.

## Important: CWE Doesn't Guarantee a Pattern

Even with an "Excellent" CWE, the specific CVE might still be a library-internal bug.

### Example: CWE-89 (SQL Injection)

**Good CVE (behavioral pattern):**
```
CVE-XXXX-1111: "SQL injection in User.find() when using raw interpolation"
Fix: Added parameter escaping to User.find()
```
→ The PATTERN is "raw interpolation in queries" - developers recreate this.

**Bad CVE (library bug):**
```
CVE-XXXX-2222: "SQL injection due to incorrect escaping in pg-escape library"
Fix: Fixed regex in internal escape function
```
→ No pattern - user code looks identical, only library internals changed.

### Always Check the Fix

1. Find the fix commit
2. Ask: "Does the fix change how USERS write code, or just internal implementation?"
3. If internal-only → Skip, regardless of CWE

## CVE Evaluation Checklist

For any CVE, regardless of CWE:

```
[ ] Fix adds validation/sanitization at API boundary → GOOD
[ ] Fix restricts what user input can contain → GOOD
[ ] Fix changes internal parsing/processing → SKIP
[ ] Fix changes defaults without API change → SKIP
[ ] Same user code works differently after fix → SKIP
```
