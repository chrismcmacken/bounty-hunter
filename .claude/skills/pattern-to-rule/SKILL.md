# Pattern-to-Rule Skill

Extract behavioral patterns from CVE patches and create generalized Semgrep rules that detect dangerous coding practices - NOT library-specific vulnerabilities.

## Core Principle: Extract the Pattern, Not the Library

**The goal is NOT to detect usage of a vulnerable library version.** SCA tools (Dependabot, Snyk) do that better.

**The goal IS to extract the behavioral pattern** from a CVE and detect it in ANY codebase - including custom code that makes the same mistake the library made.

### The Mental Model

```
CVE-2022-29078 (EJS vulnerability)
         ↓
    Pattern Extraction
         ↓
"User-controlled objects passed to template engine options"
         ↓
    Generalized Rule
         ↓
Detects this pattern in EJS, Pug, Handlebars, custom template wrappers, etc.
```

The CVE is research input. The output is a behavioral pattern rule.

## When to Use This Skill

Use `/pattern-to-rule` when:
- You have identified a CVE with an extractable behavioral pattern (via `/discover-patterns`)
- You have a GitHub commit URL with a security fix
- You want to create a rule from a known vulnerability pattern

**Do NOT use this skill when:**
- The CVE is a library-internal bug (parser rewrite, memory handling)
- The pattern only matches the specific library (that's SCA)
- You haven't verified the CVE has an extractable pattern

## Skill Workflow

### Phase 1: Information Gathering

1. **Parse Input**
   - If CVE ID: Fetch from OSV.dev
   - If commit URL: Fetch diff and extract context
   - Identify: affected package, versions, CWE, CVSS

2. **Fetch CVE Details**
   ```bash
   # OSV.dev (preferred for open source)
   curl -s "https://api.osv.dev/v1/vulns/CVE-YYYY-NNNNN"

   # GitHub Advisory search
   gh api /advisories?cve_id=CVE-YYYY-NNNNN
   ```

3. **Locate the Patch**
   - Find fix commit in GitHub
   - Download the diff
   - Identify vulnerable vs fixed code

### Phase 2: Mandatory Pattern Abstraction Gate

**STOP. Before writing any rule, you MUST complete this gate.**

#### Gate Question 1: What is the behavioral pattern?

Remove the library name from the vulnerability. What dangerous behavior remains?

| CVE Description | Abstracted Pattern |
|-----------------|-------------------|
| "EJS allows RCE via settings[view options]" | "User objects passed to function options with special key handling" |
| "SQL injection in Django ORM extra()" | "Unsafe string interpolation in query construction" |
| "SSRF in requests library" | "User-controlled URLs passed to HTTP client" |

**If you can't describe the pattern without the library name → STOP. This CVE is not suitable.**

#### Gate Question 2: Would developers recreate this in custom code?

- **YES examples:**
  - Custom query builders that concatenate strings
  - Wrapper functions that pass user objects to libraries
  - Template helpers that forward user input
  - Config mergers that spread user objects

- **NO examples:**
  - Internal parser state machine bugs
  - Memory corruption in C extensions
  - Complex timing/race conditions
  - Version-specific default changes

**If the answer is NO → STOP. This CVE is not suitable.**

#### Gate Question 3: Is the pattern too broad or sink-focused better?

| Pattern | Assessment |
|---------|-----------|
| `req.query → res.render()` | Specific enough, use pattern-focused |
| `obj[key] = value` | Too broad, use sink-focused instead |
| `user_input → subprocess.run()` | Specific enough |
| Any object assignment | Too broad |

**If the pattern is too broad:**
- Consider sink-focused detection (detect at exploitation point)
- Or mark as audit-level (high FP rate expected)

#### Gate Output

Document your answers before proceeding:

```
=== Pattern Abstraction Gate ===
CVE: CVE-YYYY-NNNNN
Library: <package name>

Q1: Behavioral pattern (library-independent):
    <your answer - if blank, STOP>

Q2: Would devs recreate this?
    YES/NO - <reasoning>
    (if NO, STOP)

Q3: Pattern scope:
    Pattern-focused / Sink-focused / Too broad to detect

GATE PASSED: YES/NO
```

### Phase 3: Root Cause Analysis

Follow the checklist in `resources/cve-analysis-checklist.md`:

1. **Identify the SOURCE** (user input entry point)
   - Request params, body, headers
   - File contents, environment variables
   - Database values, external APIs

2. **Identify the SINK** (dangerous function)
   - What function receives the tainted data?
   - What makes it dangerous at this point?

3. **Understand the FIX**
   - What validation/sanitization was added?
   - What input patterns are now blocked?

4. **Determine Pattern Class**
   - `injection/template-options`
   - `injection/command`
   - `injection/sql`
   - `ssrf/user-controlled-url`
   - `traversal/path-concatenation`
   - `deserialization/unsafe-loader`

### Phase 4: Check Existing Coverage

Search for existing rules that might cover this pattern:

```bash
# Search by CWE
grep -rn "CWE-94" custom-rules/

# Search by pattern class
ls custom-rules/patterns/injection/

# Search by sink function
grep -rn "render(" custom-rules/
```

If a rule exists, consider:
- Adding variants to existing rule
- Creating specialized sub-rule
- Skipping if already covered

### Phase 5: Generate Rule

#### Rule Location and Naming

Rules go in pattern-based directories, NOT CVE-based:

```
custom-rules/patterns/
  injection/
    template-options-injection.yaml     # NOT CVE-2022-29078.yaml
    command-injection-subprocess.yaml
  ssrf/
    user-controlled-url.yaml
  traversal/
    path-concatenation.yaml
```

The CVE becomes metadata, not identity.

#### Rule Template

```yaml
rules:
  - id: <pattern-class>-<specific-pattern>
    # Example: injection-template-options, ssrf-user-controlled-url
    mode: taint
    metadata:
      category: security
      subcategory: [vuln]
      confidence: HIGH  # or MEDIUM if FP-prone

      # Pattern information (primary)
      pattern_class: injection/template-options
      behavior: "User-controlled objects passed to template engine options"

      # CVE as reference only
      pattern_source: CVE-2022-29078

      cwe: "CWE-94: Code Injection"
      owasp: "A03:2021 - Injection"

      # Languages this pattern applies to
      languages_applicable: [javascript, typescript]

      references:
        - https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY
        - <fix commit URL>

    message: >-
      User-controlled input is passed to template engine options.
      This pattern can enable code injection via special object keys
      (e.g., outputFunctionName in some engines).
      Fix: Only pass explicitly allowed properties to render options.

    languages: [javascript, typescript]
    severity: ERROR

    pattern-sources:
      # Generic sources - not library-specific
      - pattern: req.query
      - pattern: req.body
      - pattern: req.params

    pattern-sinks:
      # Generic sinks - any template engine
      - pattern: res.render($TEMPLATE, $OPTS)
        focus-metavariable: $OPTS
      - pattern: $ENGINE.render($TEMPLATE, $OPTS)
        focus-metavariable: $OPTS

    pattern-sanitizers:
      # Patterns that break the dangerous flow
      - pattern: JSON.parse(JSON.stringify(...))
      - pattern: "{ $KEY: $SOURCE }"
```

#### Key Differences from SCA-Style Rules

| SCA-Style (WRONG) | Behavioral (CORRECT) |
|-------------------|---------------------|
| `id: cve-2022-29078` | `id: injection-template-options` |
| `require("ejs")` | Generic sinks, any template engine |
| `ejs.render(...)` | `res.render($T, $OPTS)` |
| "If using EJS < 3.1.7..." | "User input to template options..." |
| `sca_required: true` | `pattern_class: injection/template-options` |

### Phase 6: Validate Rule

```bash
# Syntax validation
semgrep --validate --config custom-rules/patterns/<class>/<name>.yaml

# Test against vulnerable code pattern (not specific library)
# Create a test file with the PATTERN, not library-specific code

# Run against real codebases for FP check
semgrep --config custom-rules/patterns/<class>/<name>.yaml repos/<org>/
```

### Phase 7: Create Test File

Test files go alongside rules:

```
custom-rules/patterns/injection/
  template-options-injection.yaml
  template-options-injection.test.js
```

Test file format:

```javascript
// template-options-injection.test.js
// Tests for the behavioral pattern, not specific library

// === TRUE POSITIVES ===

// ruleid: injection-template-options
app.get('/page', (req, res) => {
  res.render('template', req.query);  // Direct pass-through
});

// ruleid: injection-template-options
router.post('/view', (req, res) => {
  res.render('view', {...req.body});  // Spread operator
});

// ruleid: injection-template-options
function renderWithData(template, data) {
  engine.render(template, data);  // Generic engine
}
renderWithData('page', req.body);

// === TRUE NEGATIVES ===

// ok: injection-template-options
app.get('/safe', (req, res) => {
  res.render('template', { title: req.query.title });  // Explicit keys
});

// ok: injection-template-options
app.get('/sanitized', (req, res) => {
  const clean = JSON.parse(JSON.stringify(req.query));
  res.render('template', clean);
});
```

Run tests:
```bash
semgrep --test custom-rules/patterns/
```

## Quality Gates (Required)

Before finalizing any rule:

- [ ] **Pattern abstraction gate passed** - Can describe pattern without library name
- [ ] **Developers would recreate** - Pattern exists in custom code
- [ ] **Syntactic validity** - `semgrep --validate` passes
- [ ] **Pattern-named** - Rule ID describes pattern, not CVE
- [ ] **Test coverage** - At least 3 true positives + 3 true negatives
- [ ] **FP check** - Run against real codebase, < 20% FP rate

## Common Mistakes to Avoid

1. **Creating SCA rules instead of behavioral rules**
   - Wrong: Rule ID is `cve-2022-29078`
   - Right: Rule ID is `injection-template-options`

2. **Library-specific sinks**
   - Wrong: `ejs.render($T, $O)`
   - Right: `res.render($T, $O)` or `$ENGINE.render($T, $O)`

3. **Mentioning versions in messages**
   - Wrong: "If using EJS < 3.1.7..."
   - Right: "User input to template options enables code injection..."

4. **Skipping the abstraction gate**
   - If you can't describe the pattern without the library name, STOP

5. **CVE-centric file organization**
   - Wrong: `custom-rules/cve/CVE-2022-29078.yaml`
   - Right: `custom-rules/patterns/injection/template-options.yaml`

## Resource Files

| File | Purpose |
|------|---------|
| `resources/semgrep-reference.md` | Quick reference for rule syntax |
| `resources/cve-analysis-checklist.md` | Root cause analysis template |
| `resources/false-positive-patterns.md` | How to reduce FPs |
| `resources/pattern-classes.md` | Pattern taxonomy |
| `templates/pattern-rule-template.yaml` | Starting template |

## Example Usage

```
User: /pattern-to-rule CVE-2022-29078

Claude: I'll analyze CVE-2022-29078 and extract the behavioral pattern.

[Fetches CVE details from OSV.dev]
[Identifies: EJS template injection, CWE-94]

=== Pattern Abstraction Gate ===
Q1: Behavioral pattern: "User-controlled objects passed to function
    options where object keys influence code execution"
Q2: Would devs recreate? YES - developers write template wrappers,
    pass user objects to render functions, use spread operators
Q3: Pattern scope: Pattern-focused (req.query → render() is specific)

GATE PASSED: YES

[Analyzes fix commit]
[Determines pattern class: injection/template-options]

Creating rule: custom-rules/patterns/injection/template-options-injection.yaml

[Generates rule with generic sinks, behavioral message]
[Creates test file]
[Validates syntax]

Output: Rule created at custom-rules/patterns/injection/template-options-injection.yaml
```

## Integration with Hunt Workflow

After creating pattern rules, scan targets:

```bash
# Scan with all pattern rules
semgrep --config custom-rules/patterns/ repos/<org>/

# Or use the scan script (includes pattern rules automatically)
./scripts/scan-semgrep.sh <org>
```
