# Bug Bounty Threat Hunting

## Mission
Hunt for high-confidence vulnerabilities in bug bounty program repositories using automated scanning (semgrep, trufflehog, KICS, artifact detection) combined with manual analysis to find issues others miss.

Supported platforms: HackerOne, Bugcrowd, YesWeHack, Intigriti.

## Workflow

### Quick Start (Recommended)
```bash
./scripts/hunt.sh <org-name> <platform>              # Track, clone, and scan in one command
./scripts/hunt.sh acme-corp hackerone                # Example
./scripts/hunt.sh wise bugcrowd --github-org transferwise  # Different GitHub org
./scripts/hunt.sh acme-corp hackerone --repos "api,sdk,web"  # Clone only in-scope repos
./scripts/hunt.sh acme-corp hackerone --skip-kics    # Skip specific scanners
./scripts/hunt.sh acme-corp hackerone --skip-inventory  # Skip language/dependency inventory
```
The `hunt.sh` command combines tracking, cloning, and scanning into a single automated workflow.

### Manual Workflow (Step by Step)

#### 1. Clone Target Organization
```bash
./scripts/clone-org-repos.sh <org-name>              # Clone to repos/<org>/ (default)
./scripts/clone-org-repos.sh <org-name> --standalone # Clone to ./<org>/ instead
./scripts/clone-org-repos.sh <org-name> --include-archived  # Include archived repos
```
Clones all public, non-fork repositories for analysis.

**Archived Repos**: Use `--include-archived` to also clone archived repositories. Archived repos are only scanned for secrets (trufflehog) - not code vulnerabilities, artifacts, or IaC.

#### 2. Scan for Vulnerabilities
```bash
./scripts/catalog-scan.sh <org-name>                 # Full scan (tracked org)
./scripts/catalog-scan.sh <org-name> --skip-kics     # Skip specific scanners
./scripts/catalog-scan.sh <org-name> --semgrep --secrets  # Run specific scanners only
./scripts/catalog-scan.sh <org-name> --no-catalog --repos-dir ./my-org  # One-off scan
```
Individual scanners (called by catalog-scan.sh):
```bash
./scripts/scan-semgrep.sh <org-name>     # Code vulnerabilities
./scripts/scan-secrets.sh <org-name>     # Exposed secrets
./scripts/scan-artifacts.sh <org-name>   # Backup files & sensitive artifacts
./scripts/scan-kics.sh <org-name>        # IaC misconfigurations (reconnaissance)
./scripts/scan-inventory.sh <org-name>   # Language stats (scc) + dependencies (syft)
```
Results saved to `findings/<org>/` (semgrep-results, trufflehog-results, artifact-results, kics-results, inventory).

### 3. Review All Findings (Recommended)
```bash
/review-all <org-name>
```
Comprehensive review using all skills in priority order (secrets → code → artifacts → IaC).
Produces a consolidated report of high-confidence, reportable findings.

### 4. Extract & Review Individual Scanners
```bash
./scripts/extract-semgrep-findings.sh <org> [format] [repo]
./scripts/extract-trufflehog-findings.sh <org> [format] [repo]
./scripts/extract-artifact-findings.sh <org> [format] [repo]
./scripts/extract-kics-findings.sh <org> [format] [repo]
```
Use the `review-semgrep`, `review-trufflehog`, `review-artifacts`, and `review-kics` skills to triage findings.

### 5. Inventory Scanning (Languages & Dependencies)
```bash
./scripts/scan-inventory.sh <org>               # Run inventory only
./scripts/extract-inventory.sh <org> languages  # Language breakdown by LOC
./scripts/extract-inventory.sh <org> packages   # All dependencies
./scripts/extract-inventory.sh <org> cve-ready  # Package list for CVE lookup
./scripts/extract-inventory.sh --all languages  # Cross-org language stats
```
Inventory data is stored in:
- `catalog/languages.json` - Global language stats for all orgs
- `findings/<org>/inventory/<repo>-sbom.json` - Per-repo SBOM files

Use inventory to prioritize custom Semgrep rule development by language.
See `docs/inventory-scanning.md` for detailed documentation.

### 6. Scan Archives for Secrets (Optional)
```bash
./scripts/extract-and-scan-archives.sh <org> [repo]
```
Extracts archives to temp directory, scans with Trufflehog, and cleans up.

### 7. Advanced Scripts

Dynamic testing, cloud verification, and recon scripts are in `scripts/advanced/`:
```bash
./scripts/advanced/extract-cloud-resources.sh <org>   # Extract cloud resources from IaC
./scripts/advanced/verify-cloud-exposure.sh <org>     # Test public accessibility
./scripts/advanced/generate-targeted-tests.sh <org>   # Generate nuclei templates
./scripts/advanced/recon-subdomains.sh <org>          # Subdomain enumeration
./scripts/advanced/scan-dynamic.sh <org>              # Dynamic web scanning
```
See `docs/static-dynamic-bridge.md` for detailed documentation on static-to-dynamic validation.

## Catalog System

The catalog system provides structured tracking of bug bounty targets with platform integration, historical scan data, and scope queries.

### Structure
```
catalog/
├── index.json           # Master index of tracked orgs
├── platforms/           # Platform scope data (HackerOne, Bugcrowd, etc.)
│   ├── hackerone.json
│   └── bugcrowd.json
└── tracked/             # Per-org tracking data
    └── <org>/
        ├── meta.json    # Org metadata and notes
        └── scans/       # Historical scan results
            └── YYYY-MM-DD-HHMM/
                ├── commits.json     # Repo SHAs at scan time
                ├── semgrep.json
                ├── trufflehog.json
                ├── artifacts.json
                └── kics.json
```

### Platform Authentication
Configure platform tokens in `.env` (copy from `.env.example`):

```bash
# HackerOne - API token from https://hackerone.com/settings/api_token/edit
HACKERONE_TOKEN=your_token
HACKERONE_USERNAME=your_username

# Bugcrowd - Session token (recommended) or email/password
# Session token: Extract _crowdcontrol_session_key cookie from browser
BUGCROWD_TOKEN=your_session_token
# Or use email/password with 2FA:
BUGCROWD_USER=email@example.com
BUGCROWD_PASSWORD=your_password
# Requires: go install rsc.io/2fa@latest && 2fa -add bugcrowd

# YesWeHack - API token from https://yeswehack.com/user/api
YESWEHACK_TOKEN=your_token

# Intigriti - API token from https://app.intigriti.com/researcher/settings/api
INTIGRITI_TOKEN=your_token
```

### Platform Data Refresh
Fetch current scope data from bug bounty platforms:
```bash
./scripts/catalog-refresh.sh              # Refresh all configured platforms
./scripts/catalog-refresh.sh hackerone    # Refresh specific platform
./scripts/catalog-refresh.sh --list       # Show configured platforms
```
Requires platform auth tokens in `.env` (see Platform Authentication above).

### Query Platform Scopes
Search across all platform scope data:
```bash
# Search by keyword
./scripts/catalog-query.sh stripe                      # Find "stripe" in any scope
./scripts/catalog-query.sh --platform h1 aws           # Search HackerOne only

# Find GitHub repos in scope
./scripts/catalog-query.sh --type github --format programs   # Programs with GitHub scope
./scripts/catalog-query.sh --type github --format orgs       # GitHub org names for cloning

# Other filters
./scripts/catalog-query.sh --type wildcard             # Wildcard domains (*.example.com)
./scripts/catalog-query.sh --type domain               # Specific domains
./scripts/catalog-query.sh --format json               # JSON output
```

### Track a Target
```bash
# Add org to catalog
./scripts/catalog-track.sh <org-name> <platform>
./scripts/catalog-track.sh acme-corp hackerone

# List tracked targets
./scripts/catalog-status.sh

# Remove from tracking
./scripts/catalog-untrack.sh <org-name>
./scripts/catalog-untrack.sh <org-name> --delete-all  # Also delete data
```

### Catalog Workflow
```bash
# Recommended: Single command workflow
./scripts/hunt.sh acme-corp hackerone       # Track + clone + scan

# Or step by step:
./scripts/catalog-track.sh acme-corp hackerone  # 1. Track
./scripts/clone-org-repos.sh acme-corp          # 2. Clone (repos/<org>/ by default)
./scripts/catalog-scan.sh acme-corp             # 3. Scan

# Check status and diffs
./scripts/catalog-status.sh                     # Overview
./scripts/catalog-diff.sh acme-corp             # Changes since last scan
```

### Status and Diffs
```bash
# Overview of all tracked orgs
./scripts/catalog-status.sh
./scripts/catalog-status.sh --stale-days 14  # Custom stale threshold

# Detailed status for one org
./scripts/catalog-status.sh <org-name>

# Compare latest scan vs previous
./scripts/catalog-diff.sh <org-name>
./scripts/catalog-diff.sh <org-name> --summary  # Counts only
./scripts/catalog-diff.sh <org-name> --code     # Include git commit history

# Compare specific scans
./scripts/catalog-diff.sh <org-name> <old-timestamp> <new-timestamp>
```

### DuckDB Extraction
All extraction scripts use DuckDB for fast JSON processing:
```bash
./scripts/extract-semgrep-findings.sh <org> [format] [repo]
# Formats: summary, full, count, jsonl, rules

./scripts/extract-trufflehog-findings.sh <org> [format] [repo]
# Formats: summary, full, count, verified, detectors

./scripts/extract-artifact-findings.sh <org> [format] [repo]
# Formats: summary, full, count, archives, databases, sql, sources

./scripts/extract-kics-findings.sh <org> [format] [repo]
# Formats: summary, full, count, resources, queries

./scripts/extract-inventory.sh <org> [format]
# Formats: summary, languages, packages, cve-ready, types, count
```

### Testing
Run the test suite after making changes:
```bash
./scripts/test-catalog.sh           # Run all tests (47 tests)
./scripts/test-catalog.sh --quick   # Quick smoke tests
./scripts/test-catalog.sh --phase 2 # Test specific phase
```
See `docs/catalog-tests.md` for test documentation and known issues.

## High Confidence Standards

### What Makes a Finding Reportable
- **Verified exploitability** - Not theoretical, actually works
- **Clear security impact** - Data exposure, unauthorized access, code execution
- **In production code** - Not tests, examples, or vendored dependencies
- **In scope** - Check program policy before reporting

### Common False Positives to Skip
- Secrets in test fixtures or example code
- Hardcoded values that are public/non-sensitive (API endpoints, public keys)
- Vulnerabilities in vendored/third-party code (report upstream instead)
- "Informational" findings without exploitable impact
- Deprecated code paths that aren't reachable

## Novel Attack Vectors

When reviewing findings, look for patterns others miss:

### Beyond Standard Detections
- **Chained vulnerabilities** - Low-severity findings that combine into critical impact
- **Context-dependent bugs** - Safe in isolation, dangerous in this specific codebase
- **Custom rule opportunities** - Patterns specific to this org's code style
- **Historical commits** - Secrets rotated but still valid, or rollback-exploitable bugs
- **CVE variant analysis** - Write Semgrep rules from CVE patches to find 0-days (see `docs/cve-rule-workflow.md`)

## Pattern Research Workflow

Discover dangerous **behavioral patterns** from CVE patches, then create Semgrep rules to find these patterns in bug bounty targets. The goal is detecting dangerous coding practices that developers recreate - NOT detecting specific vulnerable library versions (that's SCA).

### Core Principle
CVEs are **research input** to discover patterns, not the output identity. A good pattern rule detects the dangerous behavior in ANY codebase, not just usage of one specific library.

### Discover Patterns
```bash
# By CWE (recommended - most pattern-focused)
/discover-patterns CWE-94              # Code injection patterns
/discover-patterns CWE-78              # Command injection patterns

# From ecosystem CVEs (filters to extractable patterns)
/discover-patterns pypi                # Extract patterns from Python CVEs
/discover-patterns npm                 # Extract patterns from Node.js CVEs

# Analyze specific CVE for pattern extraction
/discover-patterns CVE-2022-29078      # Extract behavioral pattern

# Patterns relevant to a target's tech stack
/discover-patterns --org acme-corp     # Based on their languages
```
The skill queries OSV.dev, analyzes fix commits, filters to behavioral patterns (not library-internal bugs), and groups by pattern class.

### Create Rule from Pattern
```bash
/pattern-to-rule CVE-2024-XXXXX
```
Analyzes the CVE, passes the **Pattern Abstraction Gate**, extracts the behavioral pattern, and generates a generalized Semgrep rule that detects the pattern in any codebase.

Rules are organized by pattern, not CVE:
```
custom-rules/patterns/
  injection/
    template-options-injection.yaml    # NOT CVE-2022-29078.yaml
    command-injection-subprocess.yaml
  ssrf/
    user-controlled-url.yaml
```

### Test the Rule
```bash
/test-semgrep-rule custom-rules/patterns/injection/template-options-injection.yaml
```
Evaluates the rule against test cases and real codebases.

### Hunt for Patterns
```bash
semgrep --config custom-rules/patterns/ repos/<org>/
```
Scan bug bounty targets for dangerous behavioral patterns.

### What Makes a Good Pattern (vs Skip)

**Good patterns (create rules):**
- User input → SQL query concatenation
- User objects → template engine options
- User URLs → HTTP client requests
- User paths → file operations

**Skip (use SCA instead):**
- Library-internal parser bugs
- Memory corruption in C extensions
- Version-specific default changes
- Bugs where user code looks identical before/after fix

See skill documentation for detailed pattern extraction workflow.

### High-Value Semgrep Findings
Prioritize these rule categories:
- Injection (SQL, command, template)
- Deserialization flaws
- Authentication/authorization bypasses
- Cryptographic weaknesses (weak algorithms, hardcoded keys)
- Path traversal

### High-Value Trufflehog Findings
Prioritize in this order:
1. **Verified secrets** - Confirmed active, immediate rotation needed
2. **High-entropy API keys** - AWS, GCP, Stripe, etc.
3. **Private keys** - SSH, TLS certificates
4. **Database credentials** - Connection strings with passwords
5. **Unverified but suspicious** - Requires manual validation

### High-Value Artifact Findings
Artifacts Trufflehog cannot scan directly - require manual triage:
1. **Archives** - `.zip`, `.tar.gz` must be extracted first (use `extract-and-scan-archives.sh`)
2. **Binary databases** - `.sqlite`, `.db` need manual SQLite inspection
3. **SQL dumps with data** - Files marked `[CONTAINS DATA]` may have PII
4. **Source backups** - `.php.bak`, `.py.old` may reveal old vulnerabilities
5. **Environment backups** - `.env.bak`, `.env.production.old`

Use the `review-artifacts` skill to triage these findings.

### High-Value KICS Findings (Reconnaissance)
IaC findings are **reconnaissance**, not direct vulnerabilities. Extract resource identifiers, then verify actual infrastructure:

1. **Public Storage** - S3/GCS/Azure bucket names → Test with `aws s3 ls --no-sign-request`
2. **Open Security Groups** - 0.0.0.0/0 on sensitive ports → Port scan actual IPs
3. **Privileged Containers** - K8s/Docker privilege escalation → Test if deployed
4. **IAM Over-Permission** - Wildcard policies → Test privilege escalation
5. **Hardcoded Resources** - Actual bucket/DB names in Terraform → Verify exposure

**Key insight**: Code saying `acl = "public-read"` is not a finding. A bucket you can actually list is.

Use the `review-kics` skill with `resources` format to extract identifiers for verification.

## Reporting Guidelines

When a high-confidence finding is confirmed:
1. Document exact reproduction steps
2. Assess real-world impact (what can an attacker actually do?)
3. Check program policy for scope and duplicate status
4. Draft report with clear PoC and impact statement

### Platform-Specific Notes
- **HackerOne**: Check program policy page, use markdown formatting
- **Bugcrowd**: Check VRT for severity guidance, note P1-P5 classification
- **YesWeHack**: Review program scope carefully, CVSS scoring used
- **Intigriti**: Check program rules, triage team reviews first
