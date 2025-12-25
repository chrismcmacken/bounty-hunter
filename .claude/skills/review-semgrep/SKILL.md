---
name: review-semgrep
description: Review and triage semgrep security scan results to identify true positive vulnerabilities. Use when analyzing semgrep output, triaging security findings, reviewing static analysis results, or when the user has semgrep-results directories to review. Performs deep code analysis to distinguish real vulnerabilities from false positives with high confidence.
---

# Review Semgrep Security Findings

Expert security analysis workflow for triaging semgrep scan results and identifying true positive vulnerabilities.

## Project Structure

All paths are relative to the project root (working directory):

```
threat_hunting/                    # Project root (working directory)
├── <org-name>/                    # Cloned repositories (e.g., jitsi/, tronprotocol/)
│   └── <repo-name>/               # Individual repository source code
├── findings/<org-name>/           # All scan results for an organization
│   ├── semgrep-results/           # Semgrep JSON output files
│   │   └── <repo-name>.json
│   ├── trufflehog-results/
│   ├── artifact-results/
│   ├── kics-results/
│   └── reports/                   # Final consolidated reports
└── scripts/                       # ALL extraction and scanning scripts
```

**Repository source code location**: `<org-name>/<repo-name>/` (e.g., `jitsi/jicofo/src/main/java/...`)
**Scan results location**: `findings/<org-name>/semgrep-results/<repo-name>.json`

## CRITICAL: Do NOT Write Custom Scripts

**All extraction scripts already exist in `./scripts/`**. Never write custom jq, Python, or shell scripts to parse findings. The existing scripts handle:
- Complex JSON/NDJSON parsing
- Large file handling
- Edge cases and error handling
- Consistent output formatting

Available extraction scripts:
- `./scripts/extract-semgrep-findings.sh` - Parse semgrep results
- `./scripts/extract-trufflehog-findings.sh` - Parse trufflehog results
- `./scripts/extract-artifact-findings.sh` - Parse artifact results
- `./scripts/extract-kics-findings.sh` - Parse KICS results

If you need functionality not provided by existing scripts, ask the user to update the scripts rather than writing one-off solutions.

## CRITICAL: Always Use the Extraction Script First

**MANDATORY**: Before doing ANY manual analysis, you MUST run the extraction script to get a summary of findings:

```bash
./scripts/extract-semgrep-findings.sh <org-name>
```

This script:
- Parses all JSON result files efficiently
- Extracts only the findings (not metadata bloat)
- Formats output in a readable, actionable format
- Shows severity, rule ID, file location, and description

**DO NOT** attempt to read JSON files directly or use Grep to parse them. The extraction script handles the complex JSON structure and large file sizes automatically.

## Quick Reference

```bash
# Extract from findings/ directory (per-repo files)
./scripts/extract-semgrep-findings.sh <org-name>                  # All repos, summary
./scripts/extract-semgrep-findings.sh <org-name> summary <repo>   # Specific repo
./scripts/extract-semgrep-findings.sh <org-name> count            # Counts only

# Extract from catalog scans (merged gzipped files)
./scripts/extract-semgrep-findings.sh <org-name> --catalog         # Latest scan
./scripts/extract-semgrep-findings.sh <org-name> --scan 2025-12-24 # Specific scan

# Scan repositories (if not already done)
./scripts/scan-semgrep.sh <org-name>
```

**Data Sources:**
- `findings/<org>/semgrep-results/*.json` - Per-repo results (uncompressed)
- `catalog/tracked/<org>/scans/<timestamp>/semgrep.json.gz` - Merged scan (gzipped)

## Workflow

### Step 1: Run the Extraction Script

**ALWAYS START HERE** - Run the extraction script (as described above):

```bash
./scripts/extract-semgrep-findings.sh <org-name>
```

Review the script output to understand:
- Total number of findings across all repos
- Which repos have the most findings
- Types of issues detected (by rule ID)
- Severity distribution (ERROR vs WARNING)

### Step 2: Triage Findings

For each finding, quickly assess whether it warrants deep analysis:

**Likely FALSE POSITIVE - Skip these:**
- Test files (`*_test.go`, `*.spec.ts`, `__tests__/`)
- Example/demo code (`examples/`, `demo/`, `sample`)
- Vendor/third-party code (`vendor/`, `node_modules/`)
- Documentation files showing code samples
- Intentional patterns with explanatory comments

**Likely TRUE POSITIVE - Analyze these:**
- Production code paths
- Code handling user input
- Authentication/authorization logic
- Cryptographic operations
- Database queries
- File system operations

**Prioritize by severity:**
1. ERROR findings in production code
2. WARNING findings in security-sensitive areas
3. Everything else

### Step 3: Deep Analysis

For each finding that passed triage, verify exploitability:

#### Read the Source Code
- Read the file at the reported location
- Examine 50+ lines of surrounding context
- Check for mitigating controls nearby

#### Verify Exploitability (CRITICAL)

Semgrep flags **patterns**, not proven vulnerabilities. Check:

**Input Analysis:**
- Is the input user-controlled or hardcoded?
- Constrained inputs (enums, dropdowns) → NOT exploitable
- Freeform inputs (text fields, URLs) → Potentially exploitable

**Character Restrictions:**
- Can dangerous characters reach the sink?
- GitHub usernames: `[a-z0-9-]` only → Cannot inject shell metacharacters
- UUIDs: `[a-f0-9-]` only → Cannot inject code

**Sanitization:**
- Is input validated before the dangerous function?
- Does the framework auto-escape (parameterized queries, template escaping)?

**Access Control:**
- Who can trigger this code path?
- Admin-only → Lower risk than public endpoints

#### Exploitability Verdict

For each finding, determine:
```
EXPLOITABLE - User input reaches dangerous sink without sanitization
NOT EXPLOITABLE - Input constrained, sanitized, or not user-controlled
NEEDS INVESTIGATION - Unclear data flow, requires more context
```

### Step 4: Report Findings

Only report findings with **90%+ confidence** they are true positives.

**For each confirmed finding:**

```
## [Severity] Rule Name

**Repository**: repo-name
**File:Line**: path/to/file.py:123
**Confidence**: 95%

**Summary**: One-line description of the vulnerability

**Analysis**: Why this is a true positive - explain the vulnerable data flow

**Exploitability**: EXPLOITABLE
**Attack Path**: Concrete steps an attacker would take

**Evidence**:
[relevant code snippet]

**Remediation**: Specific fix recommendation
```

**Final Summary:**
- Total findings reviewed
- True positives identified (with count by severity)
- Most critical issues requiring immediate attention
- Patterns observed across repositories

## Output Formats

**Extraction script formats:**
- `summary` (default) - Readable finding details
- `count` - Counts per repository
- `full` - Raw JSON for detailed analysis

## Reference

### JSON Structure (For Understanding Output)

Each finding in the extraction script output contains:
- `check_id`: Semgrep rule that triggered
- `path`: File path where finding was detected
- `start.line` / `end.line`: Line numbers
- `extra.message`: Vulnerability description
- `extra.severity`: ERROR, WARNING, INFO
- `extra.metadata`: CWE, OWASP references, confidence

**Note**: Do NOT manually parse JSON files - always use the extraction script.

## Language-Specific Knowledge

When reviewing code in these languages, consult the detailed guides:

- **PHP**: See [php-vulnerabilities.md](php-vulnerabilities.md) for parser differentials (`parse_url` bypass), type juggling, `strcmp` bypass, and deserialization
- **Python**: See [python-vulnerabilities.md](python-vulnerabilities.md) for path traversal (`os.path.join`/`pathlib` bypass), pickle/ML deserialization RCE, YAML deserialization, class pollution (prototype pollution equivalent), dynamic import LFI (`importlib.import_module()`), SSTI, eval/exec injection, command injection, SSRF, and SQL injection
- **NoSQL/MongoDB**: See [nosql-injection.md](nosql-injection.md) for operator injection (`$ne`, `$gt`, `$regex`), `$where` JavaScript injection, and auth bypass patterns across Python, Node.js, Java, Go, and Ruby
- **XPath Injection**: See [xpath-injection.md](xpath-injection.md) for XPath injection patterns in Python (lxml), Java (javax.xml.xpath), PHP (SimpleXML/DOMXPath), C# (System.Xml.XPath), and Ruby (Nokogiri/REXML) - authentication bypass, data extraction, parameterized query remediation

## Guidelines

- Be skeptical - false positives waste developer time
- Consider full context, not just the flagged line
- Pattern match ≠ vulnerability; verify exploitability
- Prioritize by real-world risk, not just severity labels
- Document your reasoning for each verdict
