---
name: review-trufflehog
description: Review and triage Trufflehog secret detection scan results to identify real credential exposures. Use when analyzing trufflehog output, triaging secret findings, reviewing credential leaks, or when the user has trufflehog results to review. Can also run scans for an organization. Filters out test/demo secrets and prioritizes verified findings with source code context analysis.
---

# Review Trufflehog Secret Findings

Expert security analysis workflow for triaging Trufflehog secret detection results, distinguishing real credential exposures from test/demo data.

## Project Structure

All paths are relative to the project root (working directory):

```
threat_hunting/                    # Project root (working directory)
├── <org-name>/                    # Cloned repositories (e.g., jitsi/, tronprotocol/)
│   └── <repo-name>/               # Individual repository source code
├── findings/<org-name>/           # All scan results for an organization
│   ├── semgrep-results/
│   ├── trufflehog-results/        # Trufflehog NDJSON output files
│   │   └── <repo-name>.json
│   ├── artifact-results/
│   ├── kics-results/
│   └── reports/                   # Final consolidated reports
└── scripts/                       # ALL extraction and scanning scripts
```

**Repository source code location**: `<org-name>/<repo-name>/` (e.g., `jitsi/jicofo/src/main/java/...`)
**Scan results location**: `findings/<org-name>/trufflehog-results/<repo-name>.json`

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
./scripts/extract-trufflehog-findings.sh <org-name>
```

This script:
- Parses all NDJSON result files efficiently
- Shows verification status, secret type, file location
- Provides total counts and summary statistics
- Handles empty files and edge cases automatically

**DO NOT** attempt to read NDJSON files directly or use Grep to parse them. The extraction script handles the format automatically.

## Quick Reference

```bash
# Extract from findings/ directory (per-repo NDJSON files)
./scripts/extract-trufflehog-findings.sh <org-name>                  # All repos, summary
./scripts/extract-trufflehog-findings.sh <org-name> verified         # Only verified secrets
./scripts/extract-trufflehog-findings.sh <org-name> summary <repo>   # Specific repo
./scripts/extract-trufflehog-findings.sh <org-name> count            # Counts only

# Extract from catalog scans (merged gzipped NDJSON)
./scripts/extract-trufflehog-findings.sh <org-name> --catalog         # Latest scan
./scripts/extract-trufflehog-findings.sh <org-name> --scan 2025-12-24 # Specific scan

# Scan repositories (if not already done)
./scripts/scan-secrets.sh <org-name>
```

**Data Sources:**
- `findings/<org>/trufflehog-results/*.json` - Per-repo NDJSON (uncompressed)
- `catalog/tracked/<org>/scans/<timestamp>/trufflehog.json.gz` - Merged scan (gzipped NDJSON)

## Workflow

### Step 1: Run the Extraction Script

**ALWAYS START HERE** - Run the extraction script (as described above):

```bash
./scripts/extract-trufflehog-findings.sh <org-name>
```

Review the script output to understand:
- Total number of findings and verified secrets
- Which repos have the most exposures
- Types of secrets detected (AWS, GitHub, PrivateKey, etc.)

**For verified secrets** (confirmed active - highest priority):
```bash
./scripts/extract-trufflehog-findings.sh <org-name> verified
```

### Step 2: Triage Findings

#### Priority by Secret Type

1. **CRITICAL** - Rotate immediately:
   - Cloud provider keys (AWS, GCP, Azure)
   - Database credentials
   - Private keys (SSH, TLS, signing)
   - Payment system keys (Stripe, etc.)

2. **HIGH** - Rotate soon:
   - Auth tokens (JWT, OAuth)
   - Service account credentials
   - API keys for sensitive services

3. **MEDIUM** - Investigate:
   - Third-party SaaS API keys
   - Webhook secrets

4. **LOW** - Verify context:
   - Free-tier service keys
   - Read-only tokens

#### Filter Test/Demo Secrets

**Likely TEST DATA - Lower priority:**

Filename indicators:
- `test`, `spec`, `mock`, `fake`, `dummy`, `example`, `sample`
- `fixture`, `stub`, `demo`, `.test.`, `.spec.`
- `__tests__`, `__mocks__`, `testdata`, `fixtures`
- `.env.example`, `.env.sample`, `.env.template`

Content indicators:
- Placeholder patterns: `xxx`, `000`, `test`, `demo`, `changeme`
- Known dummy values: `sk_test_`, `pk_test_`, `AKIAIOSFODNN7EXAMPLE`
- Documentation/README files with example code

**Likely REAL - Prioritize:**
- Production config files
- Non-template environment files
- Application source code
- CI/CD configuration
- Verified status = true

### Step 3: Deep Analysis

For each non-test finding, examine the source code:

#### Read Context
- Read the source file at the reported location
- Examine 30+ lines of surrounding context
- Check the commit history

#### Determine Real-World Risk

**Is this secret actually used?**
- Hardcoded and used directly → HIGH RISK
- Loaded from env var with hardcoded fallback → Check if fallback is real
- In gitignored file that was committed → Still exposed in history

**What's the blast radius?**
- What systems/data can this credential access?
- Is it scoped (read-only, limited permissions)?
- Organizational vs. personal credential?

**Exposure timeline:**
- How long has it been in version control?
- Is the repository public or private?
- Has the secret been rotated since exposure?

### Step 4: Report Findings

**For VERIFIED secrets (immediate action):**

```
## VERIFIED SECRET - [Secret Type]

**Repository**: repo-name
**File:Line**: path/to/file.py:123
**Commit**: abc123def (date)
**Partial Secret**: AKIA...

**Risk Level**: CRITICAL
**Blast Radius**: [What this credential can access]

**Analysis**: Why this requires immediate action

**Recommendation**:
1. Rotate credential immediately
2. Audit access logs for unauthorized use
3. Remove from repository history if public
```

**For UNVERIFIED secrets (likely real):**

```
## UNVERIFIED - LIKELY REAL - [Secret Type]

**Repository**: repo-name
**File:Line**: path/to/file.py:123
**Confidence**: 85%

**Analysis**: Why this appears to be a real credential

**Recommendation**: Verify and rotate if confirmed
```

**For filtered test/demo secrets:**

```
## FILTERED - TEST/DEMO

**File**: path/to/test_config.py
**Reason**: Test file with placeholder value `sk_test_...`
```

**Final Summary:**
- Total findings reviewed
- Verified secrets requiring immediate rotation
- Unverified secrets requiring investigation
- Filtered test/demo secrets
- Repositories with most exposures
- Patterns observed (e.g., "AWS keys in config files")

## Output Formats

**Extraction script formats:**
- `summary` (default) - Readable finding details
- `verified` - Only confirmed active secrets
- `count` - Counts per repository
- `full` - Raw JSON for detailed analysis

## Reference

### NDJSON Format (For Understanding Output)

Trufflehog outputs newline-delimited JSON (one finding per line). Key fields in the extraction script output:

- `DetectorName`: Type of secret (AWS, GitHub, PrivateKey, etc.)
- `Verified`: Boolean - true means confirmed active
- `Raw`: The actual secret value (partially masked)
- `SourceMetadata.Data.Git.file`: File path
- `SourceMetadata.Data.Git.commit`: Commit hash
- `SourceMetadata.Data.Git.line`: Line number

**Note**: Do NOT manually parse NDJSON files - always use the extraction script.

## Guidelines

- **Verified secrets are confirmed real** - prioritize for immediate rotation
- Be aggressive about filtering test data, but document what was filtered
- When uncertain, err on the side of reporting (false positive > missed real secret)
- Check git history - "removed" secrets are still exposed in history
- Document your reasoning for each verdict
