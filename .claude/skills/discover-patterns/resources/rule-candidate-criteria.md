# Pattern Candidate Scoring Criteria

Scoring system for determining which CVEs yield **extractable behavioral patterns** for Semgrep rule creation.

## Core Principle

We're scoring for **pattern extractability**, not CVE severity. A high-severity CVE with a library-internal bug is useless for pattern detection. A medium-severity CVE with a clear behavioral pattern is valuable.

## Scoring System

| Factor | Points | Criteria |
|--------|--------|----------|
| Clear source→sink flow | +3 | Taint-trackable from user input to dangerous sink |
| Fix is validation/sanitization | +3 | Behavioral fix at API boundary |
| Developers would recreate | +3 | Pattern exists in custom code, not just this library |
| Pattern-matchable CWE | +2 | Injection, deserialization, path traversal, etc. |
| Supported language | +1 | Python, Java, JS/TS, Go, PHP, Ruby |
| Fix is internal restructure | -3 | Library-internal bug, not pattern-matchable |
| Requires version check | -3 | SCA territory, same user code before/after |
| Complex state/timing | -3 | Not statically detectable |

**Maximum score:** 12 points
**Pattern candidate threshold:** Score >= 6

## Positive Factors (Pattern Indicators)

### Clear Source→Sink Flow (+3 points)

**Why it matters:** If there's a clear data flow from user input to dangerous sink, we can detect it with taint tracking.

**Qualifies:**
- User input → SQL query construction
- Request body → shell command execution
- User URL → HTTP request parameter
- User path → file operation

**How to check:**
1. Find the fix commit
2. Identify what input was being passed unsafely
3. Identify what sink received that input
4. Verify the flow is trackable

### Fix is Validation/Sanitization (+3 points)

**Why it matters:** If the fix adds input validation, the vulnerability was unsafe input handling - a pattern developers recreate.

**Qualifies:**
- Fix adds input escaping/encoding
- Fix adds allowlist/blocklist
- Fix restricts what user can control
- Fix sanitizes before passing to sink

**Doesn't qualify:**
- Fix rewrites internal parsing logic
- Fix changes how library processes data internally
- Fix changes default configuration values

### Developers Would Recreate (+3 points)

**Why it matters:** This is the key question. If developers would make the same mistake in custom code, the pattern is valuable.

**Qualifies (custom code scenarios):**
- Custom query builders that concatenate user input
- Wrapper functions that pass user objects to libraries
- Template helpers that forward user input
- Config mergers that spread user objects
- Custom file handlers with user paths

**Doesn't qualify:**
- Bugs in library-internal parsing logic
- Memory corruption in C extensions
- Complex state machine errors
- Protocol-specific edge cases

**Litmus test:** "If I look at code using this library, can I tell if it's vulnerable without checking the library version?"
- YES → Developers would recreate (+3)
- NO → Skip (library bug)

### Pattern-Matchable CWE (+2 points)

**Qualifies (see `cwe-suitability.md` for full list):**
- CWE-89: SQL Injection
- CWE-78: Command Injection
- CWE-94: Code Injection
- CWE-79: XSS
- CWE-22: Path Traversal
- CWE-611: XXE
- CWE-918: SSRF
- CWE-502: Deserialization
- CWE-1321: Prototype Pollution
- CWE-1336: SSTI

**Doesn't qualify:**
- CWE-362: Race Conditions
- CWE-119/120/125: Memory Corruption
- CWE-330: Insufficient Randomness
- CWE-284: Improper Access Control

### Supported Language (+1 point)

**Tier 1 - Full support (+1 point):**
- Python, Java, JavaScript/TypeScript, Go, Ruby, PHP, C#

**Tier 2/3 - Limited support (+0 points):**
- Kotlin, Scala, Swift, Rust, C/C++

## Negative Factors (Library Bug Indicators)

### Fix is Internal Restructure (-3 points)

**Why it matters:** If the fix only changes internal library code, there's no external pattern to detect.

**Red flags:**
- Fix only modifies private/internal functions
- Fix changes parsing algorithm
- Fix restructures data handling pipeline
- Fix touches no public API surface

**How to check:**
```
1. Look at the fix diff
2. Ask: "Did the fix change how users write code, or just internal implementation?"
3. If internal-only → -3 points
```

### Requires Version Check (-3 points)

**Why it matters:** If you need to know the library version to determine vulnerability, that's SCA, not pattern detection.

**Red flags:**
- Same user code works differently after fix
- Fix changes default behavior, not API
- Vulnerability is "version X.Y.Z introduced a bug"
- No code change in user's application needed

### Complex State/Timing (-3 points)

**Why it matters:** Some bugs require runtime analysis and can't be detected statically.

**Red flags:**
- Race conditions
- Time-of-check to time-of-use (TOCTOU)
- State-dependent behavior
- Concurrent access patterns

## Score Interpretation

| Score | Interpretation | Action |
|-------|----------------|--------|
| 10-12 | Excellent pattern | High priority, clear behavioral pattern |
| 7-9 | Good pattern | Worth creating a rule |
| 6 | Threshold | Consider if relevant to targets |
| 3-5 | Marginal | Likely has pattern issues |
| 0-2 | Poor | Library bug or not pattern-matchable |
| Negative | Skip | Definitely not suitable |

## Example Scoring

### Good Pattern Example: CVE-2022-29078 (Template Options Injection)

| Factor | Score | Reason |
|--------|-------|--------|
| Source→sink flow | +3 | req.query → res.render() options |
| Fix is sanitization | +3 | Added validation of options keys |
| Devs would recreate | +3 | Developers pass user objects to render() |
| Pattern-matchable CWE | +2 | CWE-94 (Code Injection) |
| Language | +1 | JavaScript - fully supported |
| **Total** | **12/12** | **Excellent pattern candidate** |

**Abstracted pattern:** "User-controlled objects passed to function options where object keys influence execution"

### Library Bug Example: CVE-XXXX-YYYY (Internal Parser Bug)

| Factor | Score | Reason |
|--------|-------|--------|
| Source→sink flow | +0 | Flow is internal to library |
| Fix is sanitization | +0 | Fix rewrites parsing logic |
| Devs would recreate | +0 | Bug is in library internals |
| Pattern-matchable CWE | +2 | CWE-94 |
| Language | +1 | Python |
| Fix is internal | -3 | Only internal functions changed |
| Requires version | -3 | Same user code, different behavior |
| **Total** | **-3** | **Skip - library-internal bug** |

## Pattern Abstraction Output

When a CVE passes scoring, document the abstracted pattern:

```
=== Pattern Candidate ===
CVE: CVE-2022-29078
Score: 12/12

Abstracted Pattern:
  Class: injection/template-options
  Behavior: User-controlled objects passed to function options
            where object keys can influence code execution

Source: User input (req.query, req.body with nested keys)
Sink: Template render functions with options parameter

Applies to:
  - EJS, Pug, Handlebars, Nunjucks (template engines)
  - Express res.render() with any template engine
  - Custom template wrappers
  - Any function interpreting object keys as config

Would developers recreate? YES
  - Custom template helpers
  - Wrapper functions passing user data
  - Spread operators on user objects

Rule output: custom-rules/patterns/injection/template-options-injection.yaml
```
