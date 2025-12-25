# Discover Patterns Skill

Discover dangerous behavioral patterns that developers recreate in their code. Uses CVEs as research input to identify generalizable anti-patterns.

## Core Principle: Patterns, Not Libraries

**We are NOT building an SCA tool.** Dependabot and Snyk already detect vulnerable library versions.

**We ARE finding behavioral anti-patterns** - dangerous coding practices that developers recreate in custom code, independent of any specific library.

### The Key Question

For every potential pattern, ask: **"Would a developer recreate this mistake in custom code?"**

- **Yes** → Good pattern candidate (custom query builders, template wrappers, config mergers)
- **No** → Skip (library-internal parsing bugs, memory corruption, complex state machines)

## When to Use This Skill

Use `/discover-patterns` when:
- You want to find new behavioral patterns worth detecting
- You're researching dangerous coding practices in a language/framework
- You want to use CVEs as research input to discover generalizable patterns
- You're looking for patterns by vulnerability type (CWE)

## Skill Usage

```bash
# Discover patterns by CWE (recommended - most pattern-focused)
/discover-patterns CWE-94              # Code injection patterns
/discover-patterns CWE-78              # Command injection patterns
/discover-patterns CWE-918             # SSRF patterns
/discover-patterns CWE-1321            # Prototype pollution patterns

# Discover patterns from recent CVEs in an ecosystem
/discover-patterns pypi                # Extract patterns from Python CVEs
/discover-patterns npm                 # Extract patterns from Node.js CVEs
/discover-patterns go                  # Extract patterns from Go CVEs

# Analyze a specific CVE for pattern extraction
/discover-patterns CVE-2022-29078      # Extract the behavioral pattern

# Discover patterns affecting an org's tech stack
/discover-patterns --org acme-corp     # Patterns relevant to their languages

# Options
/discover-patterns npm --days 90       # Look back 90 days
/discover-patterns pypi --critical     # Only CVSS >= 9.0
```

## Skill Workflow

### Phase 1: Determine Discovery Mode

1. **CWE-based discovery** (`/discover-patterns CWE-94`):
   - Most pattern-focused approach
   - Query recent CVEs with this CWE
   - Filter to those with extractable behavioral patterns

2. **Ecosystem discovery** (`/discover-patterns npm`):
   - Query OSV.dev for recent vulnerabilities
   - Apply pattern extraction filter (see Phase 2)
   - Group results by behavioral pattern class

3. **Single CVE analysis** (`/discover-patterns CVE-XXXX-YYYY`):
   - Deep-dive into one CVE
   - Extract the behavioral pattern
   - Assess if it's generalizable

4. **Org-relevant patterns** (`/discover-patterns --org acme-corp`):
   - Read SBOMs to identify their tech stack
   - Find patterns relevant to their languages/frameworks
   - Focus on patterns they might recreate in custom code

### Phase 2: Pattern Extraction Filter (CRITICAL)

For each CVE, apply this filter to determine if a behavioral pattern exists:

#### Step 1: Fetch CVE Details
```bash
curl -s "https://api.osv.dev/v1/vulns/CVE-YYYY-NNNNN"
```

#### Step 2: Locate and Analyze the Fix
Find the fix commit and categorize what changed:

| Fix Type | Pattern Extractable? | Action |
|----------|---------------------|--------|
| Added input validation/sanitization | YES | Extract the dangerous input→sink flow |
| Added allowlist/blocklist | YES | Extract what was being passed unsanitized |
| Restricted user-controllable options | YES | Extract the options injection pattern |
| Rewrote internal parsing logic | NO | Skip - library-internal bug |
| Fixed memory handling | NO | Skip - not pattern-matchable |
| Changed internal state machine | NO | Skip - requires runtime analysis |
| Version-specific behavior change | NO | Skip - SCA territory |

#### Step 3: Abstract the Pattern

If extractable, answer these questions:

1. **What is the SOURCE?** (Where does attacker input enter?)
   - Request parameters, body, headers
   - File contents, environment variables
   - Database values, external API responses

2. **What is the SINK?** (Where does it become dangerous?)
   - Template rendering, code evaluation
   - Shell execution, SQL queries
   - File operations, HTTP requests

3. **What is the BEHAVIOR?** (Library-independent description)
   - "User-controlled objects passed to function options"
   - "Untrusted input concatenated into shell commands"
   - "External URLs passed to HTTP client without validation"

4. **Pattern Class** (Categorization)
   - `injection/template-options`
   - `injection/command`
   - `ssrf/user-controlled-url`
   - `traversal/path-concatenation`

### Phase 3: Score Pattern Candidates

| Factor | Points | Criteria |
|--------|--------|----------|
| Clear source→sink flow | +3 | Taint-trackable data flow |
| Fix is validation/sanitization | +3 | Behavioral fix |
| Developers would recreate this | +3 | Custom code would have same bug |
| Pattern-matchable CWE | +2 | See `resources/cwe-suitability.md` |
| Supported language | +1 | Python, Java, JS/TS, Go, PHP, Ruby |
| Fix is internal restructure | -3 | Library-internal bug |
| Requires version check | -3 | SCA territory |
| Complex state/timing | -3 | Not statically detectable |

**Pattern candidate threshold:** Score >= 6

### Phase 4: Present Results

Group by behavioral pattern class, not by CVE:

```
=== Pattern Discovery Results ===
Query: CWE-94 (Code Injection), last 30 days
Analyzed: 23 CVEs
Extractable patterns: 5

PATTERN: Template Options Injection
  Class: injection/template-options
  Behavior: User-controlled objects passed to template engine options,
            allowing code injection via special object keys
  Languages: JavaScript, Python, PHP
  Source CVEs: CVE-2022-29078 (EJS), CVE-2023-XXXXX (Pug)
  Detection approach: Taint from req.body/query → render() options param
  Score: 9/10

PATTERN: Dynamic Property Assignment to Sensitive Objects
  Class: injection/prototype-pollution-sink
  Behavior: User-controlled keys used to set properties on objects
            that are later used in security-sensitive operations
  Languages: JavaScript
  Source CVEs: CVE-2022-XXXXX (lodash.merge)
  Detection approach: Track polluted objects to dangerous sinks
  Score: 8/10

SKIPPED (Library-Internal Bugs):
  - CVE-2024-XXXXX: Internal parser rewrite (not pattern-matchable)
  - CVE-2024-YYYYY: Memory handling fix (C-level, use CodeQL)
  - CVE-2024-ZZZZZ: State machine bug (requires runtime analysis)

Next steps:
  /pattern-to-rule CVE-2022-29078   # Create rule from pattern source
```

### Phase 5: Drill Down (if requested)

For single CVE analysis, show full pattern extraction:

```
=== Pattern Analysis: CVE-2022-29078 ===

CVE Details:
  Package: ejs (npm)
  CVSS: 9.8 (CRITICAL)
  CWE: CWE-94 - Code Injection

Fix Analysis:
  Commit: https://github.com/mde/ejs/commit/15ee698...
  Fix type: Added validation of options object keys

Pattern Extraction:
  SOURCE: User-controlled object (req.query, req.body with nested keys)
  SINK: Template engine render() with options parameter
  BEHAVIOR: Objects with attacker-controlled keys passed to functions
            that interpret those keys as configuration/code

Abstracted Pattern:
  Name: Template Options Injection
  Class: injection/template-options

  This is NOT about EJS specifically. The pattern is:
  "Any template engine (or configurable function) that accepts an options
   object where the KEYS can influence code execution"

  Applies to:
  - EJS, Pug, Handlebars, Nunjucks (template engines)
  - Express res.render() with any template engine
  - Custom template wrappers
  - Any function using options objects with special key handling

Recreatable in custom code? YES
  - Developers write custom template helpers
  - Developers pass user objects to library functions
  - Spread operators on user input: {...req.query}

Score: 9/10 - Excellent pattern candidate

Ready to create rule: /pattern-to-rule CVE-2022-29078
```

## CVEs to SKIP (Not Pattern-Extractable)

### Library-Internal Logic Bugs
```
CVE-XXXX-YYYY: "Buffer overflow in libxml2 parser"
- Fix: Rewrote internal parsing loop
- No external pattern: User code looks identical before/after
- Detection requires: Knowing library version (SCA)
→ SKIP
```

### Complex State/Timing Bugs
```
CVE-XXXX-ZZZZ: "Race condition in connection pooling"
- Fix: Added mutex locks
- No static pattern: Requires runtime analysis
- Detection requires: Concurrency analysis tools
→ SKIP
```

### Version-Specific Behavior
```
CVE-XXXX-AAAA: "Incorrect default in v2.3.0-2.3.5"
- Fix: Changed default configuration value
- No code pattern: Same user code, different behavior by version
- Detection requires: Version check (SCA)
→ SKIP
```

### Red Flags (Likely Unsuitable)
- Fix only changes internal/private functions
- Description mentions "internal", "parser internals", "state machine"
- Vulnerability requires specific byte sequences or timing
- Fix is a one-line version bump or config change
- No clear user-code→dangerous-sink flow

## Resource Files

| File | Purpose |
|------|---------|
| `resources/osv-api-reference.md` | OSV.dev API endpoints |
| `resources/cwe-suitability.md` | Which CWEs yield patterns |
| `resources/ecosystem-mapping.md` | PURL ecosystem mappings |
| `resources/pattern-classes.md` | Pattern classification taxonomy |

## Integration with Other Skills

After discovering a pattern:

1. **Create rule**: `/pattern-to-rule CVE-XXXX-YYYY` (uses CVE as pattern source)
2. **Test rule**: `/test-semgrep-rule custom-rules/patterns/<class>/<name>.yaml`
3. **Hunt variants**: `semgrep --config custom-rules/patterns/ repos/<org>/`

## Example Session

```
User: /discover-patterns CWE-94

Claude: [Queries OSV.dev for recent CWE-94 CVEs]
        [Analyzes each CVE's fix to extract behavioral pattern]
        [Filters out library-internal bugs]
        [Groups by pattern class]
        [Presents extractable patterns with scores]

User: /discover-patterns CVE-2022-29078

Claude: [Fetches CVE details]
        [Analyzes fix commit]
        [Extracts: "user-controlled objects → template options"]
        [Abstracts to pattern class: injection/template-options]
        [Lists where this pattern would appear in custom code]
        [Confirms: developers would recreate this]
        [Suggests: /pattern-to-rule CVE-2022-29078]
```

## Notes

- CVEs are RESEARCH INPUT, not output identity
- Rules should be named by pattern, not CVE
- Multiple CVEs often map to the same underlying pattern
- A good pattern applies to custom code, not just the vulnerable library
- OSV.dev has no rate limits but respect SLOs (add small delays between requests)
