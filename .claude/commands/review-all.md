# Review All Findings

Comprehensive security review for organization: **$ARGUMENTS**

## Objective

Triage all scan findings to identify **high-confidence, reportable vulnerabilities** for bug bounty submission. Focus on findings with verified exploitability and clear security impact.

## Project Structure

All paths are relative to the project root (working directory):

```
threat_hunting/                    # Project root (working directory)
├── <org-name>/                    # Standard: Cloned repos (e.g., jitsi/)
├── repos/<org-name>/              # Catalog: Cloned repos (e.g., repos/wise/)
│   └── <repo-name>/               # Individual repository source code
├── findings/<org-name>/           # All scan results for an organization
│   ├── semgrep-results/           # Semgrep JSON output files
│   ├── trufflehog-results/        # Trufflehog NDJSON output files
│   ├── artifact-results/          # Artifact scan JSON output
│   ├── kics-results/              # KICS JSON output files
│   └── reports/                   # Final consolidated reports
├── catalog/tracked/<org>/         # Catalog metadata and historical scans
└── scripts/                       # ALL extraction and scanning scripts
```

**Repository source code locations** (check in order):
1. `repos/<github_org>/` - Catalog mode with different GitHub org (e.g., wise program → repos/transferwise/)
2. `repos/<org-name>/` - Catalog mode (e.g., repos/acme-corp/)
3. `<org-name>/` - Standard mode (e.g., acme-corp/)

**Scan results**: `findings/<org-name>/<scanner>-results/<repo-name>.json`

## Execution Method

### Step 1: Check What Findings Exist

First, check which scan results are available:

```bash
ls -la findings/$ARGUMENTS/
```

Also check catalog metadata if tracked:
```bash
if [[ -f catalog/tracked/$ARGUMENTS/meta.json ]]; then
    cat catalog/tracked/$ARGUMENTS/meta.json
fi
```

### Step 2: Launch Parallel Review Agents

**CRITICAL**: Use the Task tool to launch 4 review agents IN PARALLEL (in a single message with multiple tool calls). Each agent runs its corresponding review skill autonomously.

Launch these 4 Task agents simultaneously:

```
Task 1 - Trufflehog (Secrets):
  subagent_type: "general-purpose"
  prompt: "Run /review-trufflehog $ARGUMENTS - Triage all secret findings. Return a structured report with: (1) VERIFIED secrets requiring immediate action, (2) Unverified secrets needing investigation, (3) False positives filtered out with reasons. Focus on high-confidence findings only."

Task 2 - Semgrep (Code):
  subagent_type: "general-purpose"
  prompt: "Run /review-semgrep $ARGUMENTS - Triage all code vulnerability findings. Return a structured report with: (1) Confirmed exploitable vulnerabilities with evidence, (2) Findings needing further investigation, (3) False positives filtered out with reasons. Skip test files, examples, and vendored code."

Task 3 - Artifacts:
  subagent_type: "general-purpose"
  prompt: "Run /review-artifacts $ARGUMENTS - Triage all artifact findings (archives, SQL dumps, databases, source backups). Return a structured report with: (1) Confirmed sensitive data exposure, (2) Archives that need extraction and scanning, (3) False positives filtered out with reasons."

Task 4 - KICS (IaC):
  subagent_type: "general-purpose"
  prompt: "Run /review-kics $ARGUMENTS - Triage all IaC findings for reconnaissance value. Return a structured report with: (1) Verified exposed resources (with curl/dig evidence), (2) Resource identifiers extracted for manual verification, (3) Findings not verifiable or false positives."
```

### Step 3: Consolidate Results

After all 4 agents complete, consolidate their findings into a single report.

## Output: Final Report

Produce a consolidated report with:

### Reportable Findings (High Confidence)

For each finding worth reporting:
- **Type**: (Secret/Code Vuln/Exposed Resource)
- **Severity**: Critical/High/Medium
- **Location**: repo/file:line
- **Description**: What the vulnerability is
- **Impact**: What an attacker could do
- **Evidence**: Proof it's exploitable (not theoretical)
- **Reproduction Steps**: How to verify

### Findings Requiring Further Investigation

List any findings that need more analysis but show promise.

### Summary Statistics

- Total findings reviewed per scanner
- Findings dismissed as false positives (with reasons)
- High-confidence findings identified

## Reporting Criteria Reminder

Only include findings that are:
- **Verified exploitable** - Not theoretical
- **Clear security impact** - Data exposure, unauthorized access, code execution
- **In production code** - Not tests, examples, or vendored dependencies
- **In scope** - Per program policy (check HackerOne, Bugcrowd, YesWeHack, or Intigriti)

Check platform from catalog metadata:
```bash
jq -r '.platform' catalog/tracked/$ARGUMENTS/meta.json
```
